//! PROFINET cyclic IO controller (RT_CLASS_1), ported from
//! `profinet-py/profinet/cyclic.py` (macos-support branch, which includes the
//! 802.1Q VLAN-tag skip in the RX path): CyclicController, CyclicState,
//! CyclicStats.
//!
//! The controller keeps the AR alive by exchanging cyclic RT frames over raw
//! L2 (EtherType 0x8892): a TX thread sends the output frame every cycle
//! period (send_clock_factor * reduction_ratio * 31.25us), an RX thread
//! receives and validates input frames, and a watchdog escalates to FAULT
//! after consecutive timeouts (recovering to RUNNING on frame receipt).
//!
//! Threading model: the reference uses Python threads + locks; here the
//! shared state lives in an `Arc` of an internal struct with `Mutex`es per
//! concern (state, stats, output builder, input data, callbacks) and an
//! `AtomicBool` run flag. The TX thread owns the TX [`RawSocket`] and returns
//! it through its `JoinHandle` so `stop()` can send the STOP frames on the
//! then-uncontended socket (the reference's BUG-1 ordering); the RX thread
//! owns the RX socket and polls with a 1 ms timeout so it exits on the run
//! flag without needing the socket closed from outside.
//!
//! The frame-level logic ([`CyclicController::process_input_frame`],
//! [`CyclicController::track_cycle_counter`],
//! [`CyclicController::handle_watchdog_timeout`],
//! [`CyclicController::next_output_frame`]) is exposed as socket-free methods
//! and unit-tested; the live TX/RX loops and `start()`/`stop()` are
//! bench-validated only.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::pcap::RawSocket;
use crate::rt::{
    build_ethernet_frame, parse_ethernet_frame, CyclicDataBuilder, IocrConfig, RtFrame,
    DATA_STATUS_PROVIDER_RUN, DATA_STATUS_STATE, DATA_STATUS_STATION_OK, DATA_STATUS_VALID,
    ETHERTYPE_PROFINET, IOXS_BAD, IOXS_DATA_STATE_GOOD, IOXS_GOOD,
};

/// Default number of consecutive watchdog timeouts before FAULT.
pub const DEFAULT_MAX_CONSECUTIVE_TIMEOUTS: u32 = 3;

/// Lock a mutex, recovering from poisoning instead of panicking. On the
/// safety-critical output/stop path a panicked TX/RX thread must never
/// prevent the safe output value from being commanded; the
/// guarded data is plain buffers/counters that stay structurally valid
/// through an unwind. Identical to `.lock().unwrap()` when unpoisoned.
fn plock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Number of STOP frames to send during graceful shutdown.
pub const STOP_FRAME_COUNT: usize = 3;

/// State machine for the cyclic controller.
///
/// State transitions:
///
/// ```text
/// IDLE -> STARTING -> RUNNING -> STOPPING -> STOPPED
///                        |                      ^
///                        +-> FAULT -------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CyclicState {
    /// Initial state, not yet started.
    Idle,
    /// Sockets created, threads launching.
    Starting,
    /// Active cyclic data exchange.
    Running,
    /// Graceful shutdown in progress (sending STOP frames).
    Stopping,
    /// Fully stopped, threads joined.
    Stopped,
    /// Communication failure (e.g., consecutive watchdog timeouts).
    Fault,
}

/// States in which the output image must not be written any more.
///
/// `Stopping` is included so the STOP image is **immutable** once a shutdown
/// has begun: [`CyclicController::stop`] applies the registered safe output
/// and only then sends the STOP frames, so a late or
/// racing write must not be able to put a command byte back into the image
/// those frames carry. `Fault`/`Stopped` mean there is no live channel at all.
fn output_writes_locked(state: CyclicState) -> bool {
    matches!(
        state,
        CyclicState::Stopping | CyclicState::Fault | CyclicState::Stopped
    )
}

impl CyclicState {
    /// The reference enum's string value ("idle", "running", ...).
    pub fn as_str(self) -> &'static str {
        match self {
            CyclicState::Idle => "idle",
            CyclicState::Starting => "starting",
            CyclicState::Running => "running",
            CyclicState::Stopping => "stopping",
            CyclicState::Stopped => "stopped",
            CyclicState::Fault => "fault",
        }
    }
}

impl fmt::Display for CyclicState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Statistics for cyclic communication (CyclicStats): frame counts, timing
/// and errors. In the reference the counters are GIL-protected; here the
/// whole struct sits behind one `Mutex` in the controller and snapshots are
/// returned by [`CyclicController::stats`].
#[derive(Debug, Clone)]
pub struct CyclicStats {
    /// Total output frames transmitted.
    pub frames_sent: u64,
    /// Total input frames received.
    pub frames_received: u64,
    /// Number of watchdog timeouts (missed frames).
    pub frames_missed: u64,
    /// Number of received frames with invalid status.
    pub frames_invalid: u64,
    /// Number of duplicate frames (same cycle counter received twice).
    pub frames_duplicate: u64,
    /// Number of frames received out of expected sequence.
    pub frames_out_of_order: u64,
    /// Actual send interval of the last transmission (microseconds).
    pub last_cycle_time_us: u64,
    /// Maximum observed SEND jitter: deviation of the TX send interval from the
    /// target cycle. Measured in the TX loop.
    pub max_jitter_us: u64,
    /// Minimum observed send interval (microseconds).
    pub min_cycle_time_us: u64,
    /// Maximum observed send interval (microseconds).
    pub max_cycle_time_us: u64,
    /// Actual arrival interval of the last received frame (microseconds).
    pub last_rx_interval_us: u64,
    /// Maximum observed RECEIVE jitter: deviation of the inter-arrival interval
    /// of received frames from the target cycle. Measured on the RX path.
    pub max_rx_jitter_us: u64,
    /// Minimum observed receive inter-arrival interval (microseconds).
    pub min_rx_interval_us: u64,
    /// Maximum observed receive inter-arrival interval (microseconds).
    pub max_rx_interval_us: u64,
    /// Sum of receive intervals, for [`CyclicStats::avg_rx_interval_us`].
    pub rx_interval_sum_us: u64,
    /// Number of measured receive intervals.
    pub rx_interval_count: u64,
    /// Timestamp of last received frame. Initialized to now to avoid a
    /// spurious watchdog timeout on the first check (the reference's BUG-7).
    pub last_receive_time: Instant,
    /// Current streak of consecutive watchdog timeouts.
    pub consecutive_timeouts: u32,
    /// Sum of observed cycle times, for [`CyclicStats::avg_cycle_time_us`].
    pub cycle_time_sum_us: u64,
    /// Number of observed cycles, for [`CyclicStats::avg_cycle_time_us`].
    pub cycle_count: u64,
}

impl CyclicStats {
    /// Fresh statistics with the reference defaults (min_cycle_time_us
    /// starts at 2^31, last_receive_time at now).
    pub fn new() -> CyclicStats {
        CyclicStats {
            frames_sent: 0,
            frames_received: 0,
            frames_missed: 0,
            frames_invalid: 0,
            frames_duplicate: 0,
            frames_out_of_order: 0,
            last_cycle_time_us: 0,
            max_jitter_us: 0,
            min_cycle_time_us: 1 << 31,
            max_cycle_time_us: 0,
            last_rx_interval_us: 0,
            max_rx_jitter_us: 0,
            min_rx_interval_us: 1 << 31,
            max_rx_interval_us: 0,
            rx_interval_sum_us: 0,
            rx_interval_count: 0,
            last_receive_time: Instant::now(),
            consecutive_timeouts: 0,
            cycle_time_sum_us: 0,
            cycle_count: 0,
        }
    }

    /// Average send interval (microseconds).
    pub fn avg_cycle_time_us(&self) -> u64 {
        self.cycle_time_sum_us
            .checked_div(self.cycle_count)
            .unwrap_or(0)
    }

    /// Average receive inter-arrival interval (microseconds).
    pub fn avg_rx_interval_us(&self) -> u64 {
        self.rx_interval_sum_us
            .checked_div(self.rx_interval_count)
            .unwrap_or(0)
    }

    /// Reset all statistics; last_receive_time is set to now to avoid a
    /// spurious watchdog timeout on restart.
    pub fn reset(&mut self) {
        *self = CyclicStats::new();
    }
}

impl Default for CyclicStats {
    fn default() -> CyclicStats {
        CyclicStats::new()
    }
}

type InputCallback = Box<dyn Fn(u16, u16, &[u8]) + Send>;
type TimeoutCallback = Box<dyn Fn() + Send>;
type ErrorCallback = Box<dyn Fn(&str) + Send>;
type StateChangeCallback = Box<dyn Fn(CyclicState, CyclicState) + Send>;
type InputStatusCallback = Box<dyn Fn(u16, u16, u8) + Send>;

/// Latest input payload for a submodule together with the provider status
/// (IOPS) the device sent alongside it. Both live under one lock: the payload
/// only means anything while its own IOPS reports GOOD, so they must never be
/// read from different moments in time.
struct InputEntry {
    data: Vec<u8>,
    iops: u8,
}

impl InputEntry {
    fn is_good(&self) -> bool {
        self.iops & IOXS_DATA_STATE_GOOD != 0
    }
}

#[derive(Default)]
struct Callbacks {
    on_input_data: Option<InputCallback>,
    on_input_status: Option<InputStatusCallback>,
    on_timeout: Option<TimeoutCallback>,
    on_error: Option<ErrorCallback>,
    on_state_change: Option<StateChangeCallback>,
}

/// State shared between the controller handle and the TX/RX threads.
struct Shared {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    input_iocr: IocrConfig,
    output_iocr: IocrConfig,
    max_consecutive_timeouts: u32,
    state: Mutex<CyclicState>,
    running: AtomicBool,
    cycle_counter: Mutex<u16>,
    output_builder: Mutex<CyclicDataBuilder>,
    input_data: Mutex<HashMap<(u16, u16), InputEntry>>,
    last_rx_cycle_counter: Mutex<Option<u16>>,
    /// RX cycle-counter step: per IEC 61158-6-10 the counter increments by
    /// send_clock_factor * reduction_ratio per frame.
    rx_counter_step: u32,
    /// TX cycle-counter step (the reference's PROTO-1: SCF * RR, not +1).
    tx_counter_step: u32,
    callbacks: Mutex<Callbacks>,
    stats: Mutex<CyclicStats>,
    /// Safe output image (slot, subslot, data) applied by every stop path
    /// before the STOP frames are built; see
    /// [`CyclicController::set_safe_output`].
    safe_output: Mutex<Option<(u16, u16, Vec<u8>)>>,
}

impl Shared {
    /// Transition to a new state (no-op if unchanged) and fire the
    /// state-change callback outside the state lock, as `_transition`.
    fn transition(&self, new_state: CyclicState) {
        let old = {
            let mut state = plock(&self.state);
            let old = *state;
            if old == new_state {
                return;
            }
            *state = new_state;
            old
        };
        let callbacks = plock(&self.callbacks);
        if let Some(cb) = &callbacks.on_state_change {
            cb(old, new_state);
        }
    }

    fn emit_error(&self, message: &str) {
        let callbacks = plock(&self.callbacks);
        if let Some(cb) = &callbacks.on_error {
            cb(message);
        }
    }

    /// Advance the TX cycle counter by its step and build the next complete
    /// output Ethernet frame from the send buffer, the frame-building half
    /// of `_send_output_frame` (the TX loop / stop path does the send).
    fn next_output_frame(&self, data_status: Option<u8>) -> Vec<u8> {
        let cycle_counter = {
            let mut counter = plock(&self.cycle_counter);
            *counter = ((*counter as u32 + self.tx_counter_step) & 0xFFFF) as u16;
            *counter
        };
        let payload = plock(&self.output_builder).build();
        let data_status = data_status.unwrap_or(
            DATA_STATUS_VALID
                | DATA_STATUS_PROVIDER_RUN
                | DATA_STATUS_STATION_OK
                | DATA_STATUS_STATE,
        );
        let frame = RtFrame {
            frame_id: self.output_iocr.frame_id,
            cycle_counter,
            data_status,
            transfer_status: 0x00,
            payload,
        };
        build_ethernet_frame(&self.dst_mac, &self.src_mac, &frame)
    }

    /// Parse and process a received raw Ethernet frame, as
    /// `_process_input_frame`: VLAN-tag skip, src-MAC and frame-id filter,
    /// stats/watchdog bookkeeping, FAULT recovery, cycle-counter tracking,
    /// IOCS acknowledgment and input-data extraction.
    fn process_input_frame(&self, data: &[u8]) {
        if data.len() < 18 {
            return;
        }

        // Filter by device MAC, then let the RT layer own the header: tagged
        // and untagged frames both arrive (Linux AF_PACKET usually strips the
        // 802.1Q tag, libpcap/BPF delivers it in-band, and a frame may carry
        // more than one), which parse_ethernet_frame already handles.
        if data[6..12] != self.dst_mac {
            return;
        }
        let Some(frame) = parse_ethernet_frame(data) else {
            return;
        };

        // Check frame ID matches our input IOCR
        if frame.frame_id != self.input_iocr.frame_id {
            return;
        }

        // Update receive time / counters and measure the receive jitter.
        // Validity decides whether this frame may feed the liveness signals.
        // A device that keeps sending frames marked INVALID (provider stopped,
        // data BAD/substitute) must NOT keep the watchdog satisfied or pull the
        // state back to Running: otherwise "link degraded to all-invalid" is
        // indistinguishable from healthy, FAULT never escalates, and the
        // control loop's abort-on-FAULT never fires. Diagnostic counters still
        // record the frame as received.
        let valid = frame.is_valid();

        {
            let now = Instant::now();
            let target_us = self.input_iocr.cycle_time_us();
            let mut stats = plock(&self.stats);
            // Measure the arrival interval only between consecutive received
            // frames: skip the first frame and any interval spanning a
            // watchdog timeout (consecutive_timeouts > 0), which would be an
            // outlier rather than steady-state RX jitter.
            if stats.frames_received > 0 && stats.consecutive_timeouts == 0 {
                let interval_us = (now - stats.last_receive_time).as_micros() as u64;
                stats.last_rx_interval_us = interval_us;
                stats.max_rx_jitter_us =
                    stats.max_rx_jitter_us.max(interval_us.abs_diff(target_us));
                stats.min_rx_interval_us = stats.min_rx_interval_us.min(interval_us);
                stats.max_rx_interval_us = stats.max_rx_interval_us.max(interval_us);
                stats.rx_interval_sum_us += interval_us;
                stats.rx_interval_count += 1;
            }
            stats.last_receive_time = now;
            stats.frames_received += 1;
            if valid {
                stats.consecutive_timeouts = 0;
            }
        }

        // If in FAULT and we got a VALID frame, recover to RUNNING. Invalid
        // frames must not mask a dead link.
        if valid && *plock(&self.state) == CyclicState::Fault {
            self.transition(CyclicState::Running);
        }

        // Cycle counter tracking
        self.track_cycle_counter(frame.cycle_counter);

        if !valid {
            plock(&self.stats).frames_invalid += 1;
            return;
        }

        // Set IOCS to GOOD - we received valid input data
        plock(&self.output_builder).set_all_iocs(IOXS_GOOD);

        // Extract data per IO object. Each submodule's payload is followed by
        // its IOPS byte; the device sets it BAD to disown data it is still
        // sending, so the payload is only usable while IOPS reports GOOD.
        //
        // Callbacks fire after the input lock is released (the reference calls
        // them under the lock, which the GIL makes safe; here that would
        // deadlock a callback reading input).
        let mut updates = Vec::new();
        let mut status_changes = Vec::new();
        {
            let mut input_data = plock(&self.input_data);
            for obj in &self.input_iocr.objects {
                if obj.iops_offset >= frame.payload.len()
                    || obj.frame_offset + obj.data_length > frame.payload.len()
                {
                    continue;
                }
                let iops = frame.payload[obj.iops_offset];
                let key = (obj.slot, obj.subslot);
                let was_good = input_data.get(&key).is_some_and(InputEntry::is_good);
                let is_good = iops & IOXS_DATA_STATE_GOOD != 0;
                let obj_data =
                    frame.payload[obj.frame_offset..obj.frame_offset + obj.data_length].to_vec();
                input_data.insert(
                    key,
                    InputEntry {
                        data: obj_data.clone(),
                        iops,
                    },
                );
                if is_good != was_good {
                    status_changes.push((obj.slot, obj.subslot, iops));
                }
                if is_good {
                    updates.push((obj.slot, obj.subslot, obj_data));
                }
            }
        }
        let callbacks = plock(&self.callbacks);
        if let Some(cb) = &callbacks.on_input_status {
            for (slot, subslot, iops) in &status_changes {
                cb(*slot, *subslot, *iops);
            }
        }
        if let Some(cb) = &callbacks.on_input_data {
            for (slot, subslot, obj_data) in &updates {
                cb(*slot, *subslot, obj_data);
            }
        }
    }

    /// Track a received cycle counter for gap/duplicate/out-of-order
    /// detection, as `_track_cycle_counter` (16-bit wrap-aware, step =
    /// send_clock_factor * reduction_ratio).
    fn track_cycle_counter(&self, rx_counter: u16) {
        let mut last = plock(&self.last_rx_cycle_counter);
        let Some(prev) = *last else {
            // First frame - just record
            *last = Some(rx_counter);
            return;
        };

        let step = self.rx_counter_step;
        let expected = ((prev as u32 + step) & 0xFFFF) as u16;
        let mut stats = plock(&self.stats);

        if rx_counter == prev {
            // Duplicate
            stats.frames_duplicate += 1;
        } else if rx_counter != expected {
            // Gap or out-of-order: forward distance handles 16-bit wrap
            let forward = rx_counter.wrapping_sub(prev) as u32;
            if forward > 0x8000 {
                // Counter went backwards = out of order
                stats.frames_out_of_order += 1;
            } else {
                // Gap: count how many frames were skipped
                let gap = forward
                    .checked_div(step)
                    .map_or(0, |frames| frames.saturating_sub(1));
                stats.frames_missed += gap as u64;
            }
            *last = Some(rx_counter);
        } else {
            // Normal sequential
            *last = Some(rx_counter);
        }
    }

    /// Handle a watchdog timeout event, as `_handle_watchdog_timeout`:
    /// bump counters, set IOCS to BAD, fire the timeout callback, and
    /// transition RUNNING -> FAULT after max_consecutive_timeouts (0 = never).
    fn handle_watchdog_timeout(&self) {
        let consecutive = {
            let mut stats = plock(&self.stats);
            stats.frames_missed += 1;
            stats.consecutive_timeouts += 1;
            stats.consecutive_timeouts
        };

        // Set IOCS to BAD - we haven't received valid input
        plock(&self.output_builder).set_all_iocs(IOXS_BAD);

        {
            let callbacks = plock(&self.callbacks);
            if let Some(cb) = &callbacks.on_timeout {
                cb();
            }
        }

        // Check for FAULT transition
        if self.max_consecutive_timeouts > 0
            && consecutive >= self.max_consecutive_timeouts
            && *plock(&self.state) == CyclicState::Running
        {
            self.transition(CyclicState::Fault);
            self.emit_error(&format!(
                "Communication lost: {consecutive} consecutive watchdog timeouts"
            ));
        }
    }

    /// Force the registered safe output image (if any) into the output
    /// builder's write AND send buffers, so the very next frame built —
    /// STOP frames included — carries it instead of whatever unsafe byte
    /// was last buffered.
    fn apply_safe_output(&self) {
        if let Some((slot, subslot, data)) = plock(&self.safe_output).clone() {
            let mut builder = plock(&self.output_builder);
            if let Err(e) = builder.set_data(slot, subslot, &data) {
                drop(builder);
                self.emit_error(&format!("safe output not applied: {e}"));
                return;
            }
            builder.set_iops(slot, subslot, IOXS_GOOD);
            builder.swap();
        }
    }

    /// Send frames with ProviderRun=STOP before shutting down, as
    /// `_send_stop_frames`. Runs on the caller's thread after the TX thread
    /// has exited and handed its socket back.
    fn send_stop_frames(&self, sock: &mut RawSocket) {
        // DATA_STATUS_PROVIDER_RUN is NOT set = STOP
        let stop_status = DATA_STATUS_VALID | DATA_STATUS_STATION_OK | DATA_STATUS_STATE;
        let cycle_time = Duration::from_micros(self.output_iocr.cycle_time_us());

        for i in 0..STOP_FRAME_COUNT {
            plock(&self.output_builder).swap();
            let frame = self.next_output_frame(Some(stop_status));
            if sock.send(&frame).is_err() {
                break;
            }
            plock(&self.stats).frames_sent += 1;
            if i < STOP_FRAME_COUNT - 1 {
                thread::sleep(cycle_time);
            }
        }
    }
}

/// Transmit loop - sends output frames at cycle rate, as `_tx_loop`. Owns
/// the TX socket and returns it on exit so `stop()` can send STOP frames.
fn tx_loop(shared: Arc<Shared>, mut sock: RawSocket) -> RawSocket {
    let cycle_time_us = shared.output_iocr.cycle_time_us();
    let cycle_time = Duration::from_micros(cycle_time_us);
    let mut next_send = Instant::now();
    let mut last_send = next_send;
    let mut first_frame = true;

    while shared.running.load(Ordering::SeqCst) {
        let now = Instant::now();

        if now >= next_send {
            // In FAULT state, don't send output frames
            if *plock(&shared.state) != CyclicState::Fault {
                // Swap double buffer and send
                plock(&shared.output_builder).swap();
                let frame = shared.next_output_frame(None);
                if let Err(e) = sock.send(&frame) {
                    shared.emit_error(&format!("TX error: {e}"));
                }
                plock(&shared.stats).frames_sent += 1;
            }

            if first_frame {
                first_frame = false;
            } else {
                // Calculate actual cycle time and jitter (skip first frame)
                let actual_us = (now - last_send).as_micros() as u64;
                let mut stats = plock(&shared.stats);
                stats.last_cycle_time_us = actual_us;
                let jitter = actual_us.abs_diff(cycle_time_us);
                if jitter > stats.max_jitter_us {
                    stats.max_jitter_us = jitter;
                }
                stats.min_cycle_time_us = stats.min_cycle_time_us.min(actual_us);
                stats.max_cycle_time_us = stats.max_cycle_time_us.max(actual_us);
                stats.cycle_time_sum_us += actual_us;
                stats.cycle_count += 1;
            }

            last_send = now;

            // Calculate next send time; if we're behind, catch up (the
            // reference additionally logs the number of missed cycles here).
            next_send += cycle_time;
            if next_send < now {
                next_send = now + cycle_time;
            }
        }

        // Sleep until just before the next cycle (100us spin margin, as the
        // reference's `next_send - perf_counter() - 0.0001`).
        let remaining = next_send.saturating_duration_since(Instant::now());
        let sleep_time = remaining.saturating_sub(Duration::from_micros(100));
        if sleep_time > Duration::ZERO {
            thread::sleep(sleep_time);
        }
    }

    sock
}

/// Receive loop - processes input frames from the device, as `_rx_loop`.
/// Uses the 1 ms recv timeout (the reference's rx socket timeout) to check
/// the watchdog and the run flag between frames.
fn rx_loop(shared: Arc<Shared>, mut sock: RawSocket) {
    let watchdog = Duration::from_micros(shared.input_iocr.watchdog_time_us());
    plock(&shared.stats).last_receive_time = Instant::now();

    while shared.running.load(Ordering::SeqCst) {
        match sock.recv(Duration::from_millis(1)) {
            Ok(Some(data)) => shared.process_input_frame(&data),
            Ok(None) => {
                // Check watchdog
                let elapsed = plock(&shared.stats).last_receive_time.elapsed();
                if elapsed > watchdog {
                    shared.handle_watchdog_timeout();
                    // Reset timer
                    plock(&shared.stats).last_receive_time = Instant::now();
                }
            }
            Err(e) => {
                if shared.running.load(Ordering::SeqCst) {
                    shared.emit_error(&format!("RX error: {e}"));
                }
                break;
            }
        }
    }
}

/// RT_CLASS_1 cyclic data exchange controller (CyclicController): TX thread
/// sends output data at the configured rate, RX thread receives and
/// validates input data, a watchdog escalates to FAULT after consecutive
/// timeouts, and IOCS bytes acknowledge received input.
pub struct CyclicController {
    /// Network interface name (e.g., "en7").
    pub interface: String,
    shared: Arc<Shared>,
    tx_thread: Option<JoinHandle<RawSocket>>,
    rx_thread: Option<JoinHandle<()>>,
}

impl CyclicController {
    /// New controller in IDLE state. Errors if the output cycle time is
    /// below 1 ms (the `std::thread::sleep` pacing of the TX loop cannot
    /// reliably do sub-millisecond cycles, matching the reference's guard).
    /// `max_consecutive_timeouts` of 0 means never enter FAULT.
    pub fn new(
        interface: &str,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        input_iocr: IocrConfig,
        output_iocr: IocrConfig,
        max_consecutive_timeouts: u32,
    ) -> Result<CyclicController, String> {
        if output_iocr.cycle_time_ms() < 1.0 {
            return Err(format!(
                "Cycle time {:.2}ms is below 1ms — not reliably achievable \
                 with thread-sleep pacing",
                output_iocr.cycle_time_ms()
            ));
        }

        let rx_counter_step =
            input_iocr.send_clock_factor as u32 * input_iocr.reduction_ratio as u32;
        let tx_counter_step =
            output_iocr.send_clock_factor as u32 * output_iocr.reduction_ratio as u32;

        // Initialize all IOPS to good
        let mut output_builder = CyclicDataBuilder::new(output_iocr.clone());
        output_builder.set_all_iops(IOXS_GOOD);

        Ok(CyclicController {
            interface: interface.to_string(),
            shared: Arc::new(Shared {
                src_mac,
                dst_mac,
                input_iocr,
                output_iocr,
                max_consecutive_timeouts,
                state: Mutex::new(CyclicState::Idle),
                running: AtomicBool::new(false),
                cycle_counter: Mutex::new(0),
                output_builder: Mutex::new(output_builder),
                input_data: Mutex::new(HashMap::new()),
                last_rx_cycle_counter: Mutex::new(None),
                rx_counter_step,
                tx_counter_step,
                callbacks: Mutex::new(Callbacks::default()),
                stats: Mutex::new(CyclicStats::new()),
                safe_output: Mutex::new(None),
            }),
            tx_thread: None,
            rx_thread: None,
        })
    }

    /// Controller MAC address.
    pub fn src_mac(&self) -> [u8; 6] {
        self.shared.src_mac
    }

    /// Device MAC address.
    pub fn dst_mac(&self) -> [u8; 6] {
        self.shared.dst_mac
    }

    /// IOCR config for input data (device -> controller).
    pub fn input_iocr(&self) -> &IocrConfig {
        &self.shared.input_iocr
    }

    /// IOCR config for output data (controller -> device).
    pub fn output_iocr(&self) -> &IocrConfig {
        &self.shared.output_iocr
    }

    /// Current controller state.
    pub fn state(&self) -> CyclicState {
        *plock(&self.shared.state)
    }

    /// True if the controller is currently running.
    pub fn is_running(&self) -> bool {
        self.state() == CyclicState::Running
    }

    /// Snapshot of the current statistics.
    pub fn stats(&self) -> CyclicStats {
        plock(&self.shared.stats).clone()
    }

    /// Current TX cycle counter value.
    pub fn cycle_counter(&self) -> u16 {
        *plock(&self.shared.cycle_counter)
    }

    /// Last received cycle counter, if any frame has been tracked yet.
    pub fn last_rx_cycle_counter(&self) -> Option<u16> {
        *plock(&self.shared.last_rx_cycle_counter)
    }

    /// Transition to a new state (no-op if unchanged), firing the
    /// state-change callback. Public port of `_transition`, also the hook
    /// tests use to drive the state machine without sockets.
    pub fn transition(&self, new_state: CyclicState) {
        self.shared.transition(new_state)
    }

    /// Set output data for the next cycle (any thread; double-buffered).
    /// Errors if the controller is in FAULT or STOPPED state.
    pub fn set_output_data(&self, slot: u16, subslot: u16, data: &[u8]) -> Result<(), String> {
        let state = self.state();
        if output_writes_locked(state) {
            return Err(format!("Cannot set output data in {state} state"));
        }
        let mut builder = plock(&self.shared.output_builder);
        builder.set_data(slot, subslot, data)?;
        builder.set_iops(slot, subslot, IOXS_GOOD);
        Ok(())
    }

    /// Latest input data from the device for a slot/subslot, or None if
    /// nothing was received yet or the device marked the payload BAD.
    ///
    /// Data whose IOPS is BAD must not be used: the device is saying the
    /// payload is not valid (module pulled, sensor faulted) while still
    /// sending the stale bytes. Use [`Self::get_input_data_allow_bad`] to see
    /// them anyway, or [`Self::get_input_status`] for the raw IOPS.
    pub fn get_input_data(&self, slot: u16, subslot: u16) -> Option<Vec<u8>> {
        plock(&self.shared.input_data)
            .get(&(slot, subslot))
            .filter(|entry| entry.is_good())
            .map(|entry| entry.data.clone())
    }

    /// Latest input data regardless of the provider status.
    pub fn get_input_data_allow_bad(&self, slot: u16, subslot: u16) -> Option<Vec<u8>> {
        plock(&self.shared.input_data)
            .get(&(slot, subslot))
            .map(|entry| entry.data.clone())
    }

    /// Raw provider status (IOPS) the device sent for a submodule (0x80 =
    /// GOOD), or None if nothing was received yet.
    pub fn get_input_status(&self, slot: u16, subslot: u16) -> Option<u8> {
        plock(&self.shared.input_data)
            .get(&(slot, subslot))
            .map(|entry| entry.iops)
    }

    /// Whether the device currently reports GOOD provider status.
    pub fn is_input_good(&self, slot: u16, subslot: u16) -> bool {
        plock(&self.shared.input_data)
            .get(&(slot, subslot))
            .is_some_and(InputEntry::is_good)
    }

    /// Register the callback for input data updates, invoked from the RX
    /// thread as `callback(slot, subslot, data)` per received data object.
    pub fn on_input<F: Fn(u16, u16, &[u8]) + Send + 'static>(&self, callback: F) {
        plock(&self.shared.callbacks).on_input_data = Some(Box::new(callback));
    }

    /// Register the callback for provider-status (IOPS) transitions, invoked
    /// from the RX thread as `callback(slot, subslot, iops)` whenever a
    /// submodule flips between GOOD and BAD. That is how a device disowns its
    /// input data without dropping the AR — the frames keep arriving with
    /// stale payload — so this is the only notification there is.
    pub fn on_input_status<F: Fn(u16, u16, u8) + Send + 'static>(&self, callback: F) {
        plock(&self.shared.callbacks).on_input_status = Some(Box::new(callback));
    }

    /// Register the callback for watchdog timeouts.
    pub fn on_timeout<F: Fn() + Send + 'static>(&self, callback: F) {
        plock(&self.shared.callbacks).on_timeout = Some(Box::new(callback));
    }

    /// Register the callback for communication errors.
    pub fn on_error<F: Fn(&str) + Send + 'static>(&self, callback: F) {
        plock(&self.shared.callbacks).on_error = Some(Box::new(callback));
    }

    /// Register the callback for state transitions.
    pub fn on_state_change<F: Fn(CyclicState, CyclicState) + Send + 'static>(&self, callback: F) {
        plock(&self.shared.callbacks).on_state_change = Some(Box::new(callback));
    }

    /// Parse and process a received raw Ethernet frame. Socket-free port of
    /// `_process_input_frame`, called by the RX loop and unit tests.
    pub fn process_input_frame(&self, data: &[u8]) {
        self.shared.process_input_frame(data)
    }

    /// Track a received cycle counter for gap/duplicate/out-of-order
    /// detection. Socket-free port of `_track_cycle_counter`.
    pub fn track_cycle_counter(&self, rx_counter: u16) {
        self.shared.track_cycle_counter(rx_counter)
    }

    /// Handle a watchdog timeout event. Socket-free port of
    /// `_handle_watchdog_timeout`, called by the RX loop and unit tests.
    pub fn handle_watchdog_timeout(&self) {
        self.shared.handle_watchdog_timeout()
    }

    /// Advance the TX cycle counter and build the next output Ethernet frame
    /// from the send buffer (the frame-building half of
    /// `_send_output_frame`; the TX loop sends what this returns).
    pub fn next_output_frame(&self, data_status: Option<u8>) -> Vec<u8> {
        self.shared.next_output_frame(data_status)
    }

    /// Start cyclic data exchange: create the separate TX/RX sockets
    /// (PROFINET-filtered, like the reference's paired raw sockets) and
    /// spawn the TX/RX threads. Bench-validated (needs a live interface and
    /// capture privileges).
    pub fn start(&mut self) -> Result<(), String> {
        let state = self.state();
        if !matches!(
            state,
            CyclicState::Idle | CyclicState::Stopped | CyclicState::Fault
        ) {
            return Err(format!("Cannot start from {state} state"));
        }

        self.shared.transition(CyclicState::Starting);
        self.shared.running.store(true, Ordering::SeqCst);
        plock(&self.shared.stats).reset();
        *plock(&self.shared.last_rx_cycle_counter) = None;

        // Create separate TX and RX sockets
        let tx_sock = RawSocket::open(&self.interface, Some(ETHERTYPE_PROFINET))?;
        let rx_sock = RawSocket::open(&self.interface, Some(ETHERTYPE_PROFINET))?;

        // Swap initial data into send buffer
        plock(&self.shared.output_builder).swap();

        let shared = Arc::clone(&self.shared);
        self.tx_thread = Some(
            thread::Builder::new()
                .name(format!("CyclicTX-{}", self.interface))
                .spawn(move || tx_loop(shared, tx_sock))
                .map_err(|e| format!("failed to spawn TX thread: {e}"))?,
        );

        let shared = Arc::clone(&self.shared);
        self.rx_thread = Some(
            thread::Builder::new()
                .name(format!("CyclicRX-{}", self.interface))
                .spawn(move || rx_loop(shared, rx_sock))
                .map_err(|e| format!("failed to spawn RX thread: {e}"))?,
        );

        self.shared.transition(CyclicState::Running);
        Ok(())
    }

    /// Register the safe output image (typically an all-zero control
    /// byte). Every stop path — [`CyclicController::stop`],
    /// [`CyclicController::stop_safe`], and the panic-unwind `Drop` — forces
    /// this image into the frame buffer BEFORE the STOP frames go out, so a
    /// stop can never latch a stale unsafe byte on the device (a device holds
    /// the last output state it received).
    pub fn set_safe_output(&self, slot: u16, subslot: u16, data: &[u8]) {
        *plock(&self.shared.safe_output) = Some((slot, subslot, data.to_vec()));
    }

    /// [`CyclicController::stop`], but forcing `data` into `slot`/`subslot`
    /// first: the STOP frames carry the caller-supplied safe bytes, not
    /// whatever was last buffered.
    pub fn stop_safe(&mut self, slot: u16, subslot: u16, data: &[u8]) {
        self.set_safe_output(slot, subslot, data);
        self.stop();
    }

    /// Stop cyclic exchange gracefully, in the reference's BUG-1 order:
    /// signal the threads to exit, join the TX thread and take back its
    /// socket, send the STOP frames (ProviderRun cleared) on it, then join
    /// the RX thread. Bench-validated. Applies the registered safe output
    /// image (see [`CyclicController::set_safe_output`]) before anything
    /// else, even when not running.
    pub fn stop(&mut self) {
        self.shared.apply_safe_output();
        if !self.shared.running.load(Ordering::SeqCst) {
            return;
        }

        self.shared.transition(CyclicState::Stopping);

        // 1. Signal threads to exit BEFORE sending stop frames
        self.shared.running.store(false, Ordering::SeqCst);

        // 2.+3. Wait for the TX thread first — it hands its socket back, so
        // the STOP frames go out with no concurrent socket access or cycle
        // counter mutation.
        if let Some(handle) = self.tx_thread.take() {
            if let Ok(mut sock) = handle.join() {
                self.shared.send_stop_frames(&mut sock);
            }
        }

        // 4. Wait for the RX thread (its 1 ms recv timeout sees the run
        // flag; no socket close needed to unblock it). Sockets drop here.
        if let Some(handle) = self.rx_thread.take() {
            let _ = handle.join();
        }

        self.shared.transition(CyclicState::Stopped);
    }
}

impl fmt::Debug for CyclicController {
    /// The reference's `__repr__`: interface, frame ids, state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CyclicController({}, out_id=0x{:04X}, in_id=0x{:04X}, {})",
            self.interface,
            self.shared.output_iocr.frame_id,
            self.shared.input_iocr.frame_id,
            self.state()
        )
    }
}

impl Drop for CyclicController {
    /// Stop on drop, the reference's context-manager `__exit__`.
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    //! In-crate tests for the safe-stop path: they reach the private
    //! `Shared` buffers to prove what the STOP frames would actually carry,
    //! which the public API deliberately does not expose.

    use super::*;
    use crate::rt::{IoDataObject, IOCR_TYPE_INPUT, IOCR_TYPE_OUTPUT};

    fn iocr(iocr_type: u16, frame_id: u16) -> IocrConfig {
        IocrConfig {
            iocr_type,
            iocr_reference: 1,
            frame_id,
            send_clock_factor: 32,
            reduction_ratio: 32,
            phase: 0,
            watchdog_factor: 3,
            data_length: 40,
            objects: vec![IoDataObject {
                slot: 1,
                subslot: 1,
                frame_offset: 0,
                data_length: 4,
                iops_offset: 4,
                iocs_offset: None,
            }],
        }
    }

    fn controller() -> CyclicController {
        CyclicController::new(
            "eth0",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            iocr(IOCR_TYPE_INPUT, 0xC001),
            iocr(IOCR_TYPE_OUTPUT, 0xC000),
            3,
        )
        .unwrap()
    }

    /// The slot 1/1 data bytes of the SEND buffer — what the next TX or
    /// STOP frame would carry on the wire.
    fn send_bytes(c: &CyclicController) -> Vec<u8> {
        plock(&c.shared.output_builder).build()[0..4].to_vec()
    }

    /// An Ethernet+RT input frame from the device, marked valid or invalid.
    fn device_frame(valid: bool) -> Vec<u8> {
        let rt = RtFrame {
            frame_id: 0xC001,
            cycle_counter: 1,
            data_status: if valid { DATA_STATUS_VALID } else { 0 },
            transfer_status: 0,
            payload: vec![0x80, 0x00, 0x00, 0x00, 0x80],
        };
        let mut f = Vec::new();
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst: us
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // src: device
        f.extend_from_slice(&ETHERTYPE_PROFINET.to_be_bytes());
        f.extend_from_slice(&rt.to_bytes());
        f
    }

    #[test]
    fn invalid_frames_do_not_feed_the_watchdog_or_clear_fault() {
        let c = controller();
        // Pretend the RX watchdog already escalated.
        c.shared.transition(CyclicState::Fault);
        plock(&c.shared.stats).consecutive_timeouts = 3;

        // A device that keeps sending INVALID frames (provider stopped, data
        // BAD/substitute) must not look like a live link: otherwise FAULT
        // never sticks and the control loop's abort-on-FAULT never fires.
        c.process_input_frame(&device_frame(false));
        assert_eq!(
            plock(&c.shared.stats).consecutive_timeouts,
            3,
            "an invalid frame must not reset the watchdog"
        );
        assert_eq!(
            c.state(),
            CyclicState::Fault,
            "an invalid frame must not clear FAULT"
        );
        assert_eq!(plock(&c.shared.stats).frames_invalid, 1);

        // A valid frame is genuine liveness: watchdog reset + recovery.
        c.process_input_frame(&device_frame(true));
        assert_eq!(plock(&c.shared.stats).consecutive_timeouts, 0);
        assert_eq!(c.state(), CyclicState::Running);
    }

    #[test]
    fn stop_image_is_immutable_once_shutdown_started() {
        // Once a shutdown has begun, stop() has already applied the safe
        // output and the STOP frames will carry it. A late
        // write must not be able to put a command byte back into that image,
        // so writes are locked from Stopping onwards — not only once Stopped.
        assert!(
            output_writes_locked(CyclicState::Stopping),
            "the STOP image must be immutable while stopping"
        );
        assert!(output_writes_locked(CyclicState::Fault));
        assert!(output_writes_locked(CyclicState::Stopped));
        // Healthy states still accept commands.
        assert!(!output_writes_locked(CyclicState::Idle));
        assert!(!output_writes_locked(CyclicState::Starting));
        assert!(!output_writes_locked(CyclicState::Running));
    }

    #[test]
    fn stop_safe_forces_safe_bytes_before_stop_frames() {
        let mut c = controller();
        c.set_output_data(1, 1, &[0x01, 0xAA, 0xBB, 0xCC]).unwrap();
        // Promote into the send buffer, as the TX loop would: the unsafe
        // safe byte is now what a plain stop's STOP frames would carry.
        plock(&c.shared.output_builder).swap();
        assert_eq!(send_bytes(&c), [0x01, 0xAA, 0xBB, 0xCC]);
        c.stop_safe(1, 1, &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            send_bytes(&c),
            [0x00; 4],
            "STOP frames must carry the safe image, not the last buffered byte"
        );
    }

    #[test]
    fn drop_path_applies_registered_safe_output() {
        let mut c = controller();
        c.set_output_data(1, 1, &[0x01; 4]).unwrap();
        plock(&c.shared.output_builder).swap();
        c.set_safe_output(1, 1, &[0x00; 4]);
        // stop() is exactly what Drop runs; it must force the registered
        // safe image even on a controller that is not running.
        c.stop();
        assert_eq!(send_bytes(&c), [0x00; 4]);
    }

    #[test]
    fn output_path_survives_poisoned_output_builder() {
        let mut c = controller();
        c.set_output_data(1, 1, &[0x01; 4]).unwrap();
        plock(&c.shared.output_builder).swap();
        // Poison the output-builder mutex the way a panicking peer thread
        // would: unwind while holding the guard.
        let shared = Arc::clone(&c.shared);
        let _ = thread::spawn(move || {
            let _guard = shared.output_builder.lock().unwrap();
            panic!("poison the output builder");
        })
        .join();
        assert!(c.shared.output_builder.is_poisoned());
        // The safety-critical write path must still command the safe value
        // instead of panicking on the poisoned lock.
        c.set_output_data(1, 1, &[0x00; 4]).unwrap();
        c.stop_safe(1, 1, &[0x00; 4]);
        assert_eq!(send_bytes(&c), [0x00; 4]);
    }
}
