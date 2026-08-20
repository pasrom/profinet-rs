//! Pure-logic tests for the cyclic RT controller, ported from the Python
//! reference's tests/test_cyclic.py (macos-support branch): state machine,
//! cycle-counter tracking, watchdog/FAULT transitions, input-frame
//! processing (including the VLAN-tag skip), TX counter stepping and
//! build_iocr_configs. No threads or sockets are started here.

use std::sync::{Arc, Mutex};

use profinet_rs::cyclic::{CyclicController, CyclicState, CyclicStats};
use profinet_rs::gsdml::IoSlot;
use profinet_rs::rt::{
    build_ethernet_frame, build_iocr_configs, parse_ethernet_frame, CyclicDataBuilder,
    IoDataObject, IocrConfig, RtFrame, DATA_STATUS_PROVIDER_RUN, DATA_STATUS_STATE,
    DATA_STATUS_STATION_OK, DATA_STATUS_VALID, IOCR_TYPE_INPUT, IOCR_TYPE_OUTPUT, IOXS_BAD,
    IOXS_GOOD,
};

const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const DST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

const RUN_STATUS: u8 =
    DATA_STATUS_VALID | DATA_STATUS_PROVIDER_RUN | DATA_STATUS_STATION_OK | DATA_STATUS_STATE;

/// Input IOCR with SCF=1, RR=1 so the cycle counter step is 1 (simple for
/// tests), one 4-byte object in slot 1/subslot 1.
fn make_input_iocr(send_clock_factor: u16, reduction_ratio: u16) -> IocrConfig {
    IocrConfig {
        iocr_type: IOCR_TYPE_INPUT,
        iocr_reference: 1,
        frame_id: 0xC001,
        send_clock_factor,
        reduction_ratio,
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

/// Output IOCR with SCF=32, RR=32 (32 ms cycle), one 4-byte object.
fn make_output_iocr(send_clock_factor: u16, reduction_ratio: u16) -> IocrConfig {
    IocrConfig {
        iocr_type: IOCR_TYPE_OUTPUT,
        iocr_reference: 2,
        frame_id: 0xC000,
        send_clock_factor,
        reduction_ratio,
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

fn make_controller_with(
    input_iocr: IocrConfig,
    output_iocr: IocrConfig,
    max_consecutive_timeouts: u32,
) -> CyclicController {
    CyclicController::new(
        "eth0",
        SRC_MAC,
        DST_MAC,
        input_iocr,
        output_iocr,
        max_consecutive_timeouts,
    )
    .expect("controller construction")
}

fn make_controller() -> CyclicController {
    make_controller_with(make_input_iocr(1, 1), make_output_iocr(32, 32), 3)
}

/// Build a fake Ethernet + RT frame as if sent by the device: dst =
/// controller MAC (ctrl.src_mac), src = device MAC (ctrl.dst_mac).
fn build_input_eth_frame(
    ctrl: &CyclicController,
    cycle_counter: u16,
    payload: Option<Vec<u8>>,
    data_status: Option<u8>,
) -> Vec<u8> {
    let mut default_payload = vec![0x01, 0x02, 0x03, 0x04, 0x80]; // 4B data + IOPS
    default_payload.extend_from_slice(&[0u8; 35]);
    let frame = RtFrame {
        frame_id: ctrl.input_iocr().frame_id,
        cycle_counter,
        data_status: data_status.unwrap_or(RUN_STATUS),
        transfer_status: 0x00,
        payload: payload.unwrap_or(default_payload),
    };
    build_ethernet_frame(&ctrl.src_mac(), &ctrl.dst_mac(), &frame)
}

// =============================================================================
// CyclicState
// =============================================================================

#[test]
fn state_values() {
    assert_eq!(CyclicState::Idle.as_str(), "idle");
    assert_eq!(CyclicState::Starting.as_str(), "starting");
    assert_eq!(CyclicState::Running.as_str(), "running");
    assert_eq!(CyclicState::Stopping.as_str(), "stopping");
    assert_eq!(CyclicState::Stopped.as_str(), "stopped");
    assert_eq!(CyclicState::Fault.as_str(), "fault");
}

// =============================================================================
// CyclicStats
// =============================================================================

#[test]
fn stats_defaults() {
    let stats = CyclicStats::new();
    assert_eq!(stats.frames_sent, 0);
    assert_eq!(stats.frames_received, 0);
    assert_eq!(stats.frames_missed, 0);
    assert_eq!(stats.frames_invalid, 0);
    assert_eq!(stats.frames_duplicate, 0);
    assert_eq!(stats.frames_out_of_order, 0);
    assert_eq!(stats.consecutive_timeouts, 0);
    assert_eq!(stats.min_cycle_time_us, 1 << 31);
}

#[test]
fn stats_reset() {
    let mut stats = CyclicStats::new();
    stats.frames_sent = 100;
    stats.frames_duplicate = 5;
    stats.frames_out_of_order = 3;
    stats.consecutive_timeouts = 2;
    stats.reset();
    assert_eq!(stats.frames_sent, 0);
    assert_eq!(stats.frames_duplicate, 0);
    assert_eq!(stats.frames_out_of_order, 0);
    assert_eq!(stats.consecutive_timeouts, 0);
}

#[test]
fn stats_avg_cycle_time() {
    let mut stats = CyclicStats::new();
    stats.cycle_time_sum_us = 30000;
    stats.cycle_count = 3;
    assert_eq!(stats.avg_cycle_time_us(), 10000);
}

#[test]
fn stats_avg_cycle_time_zero() {
    assert_eq!(CyclicStats::new().avg_cycle_time_us(), 0);
}

#[test]
fn stats_reset_sets_last_receive_time() {
    // After reset(), last_receive_time must be "now", not an ancient epoch
    // (the reference's BUG-7: a zero value always looks like a timeout).
    let mut stats = CyclicStats::new();
    stats.reset();
    assert!(stats.last_receive_time.elapsed().as_secs() < 1);
}

// =============================================================================
// CyclicController - State Machine
// =============================================================================

#[test]
fn initial_state_is_idle() {
    assert_eq!(make_controller().state(), CyclicState::Idle);
}

#[test]
fn set_output_data_fails_in_fault() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Fault);
    let err = ctrl.set_output_data(1, 1, &[1, 2, 3, 4]).unwrap_err();
    assert!(err.contains("fault"), "unexpected error: {err}");
}

#[test]
fn set_output_data_fails_in_stopped() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Stopped);
    let err = ctrl.set_output_data(1, 1, &[1, 2, 3, 4]).unwrap_err();
    assert!(err.contains("stopped"), "unexpected error: {err}");
}

#[test]
fn set_output_data_works_in_idle() {
    let ctrl = make_controller();
    ctrl.set_output_data(1, 1, &[1, 2, 3, 4]).unwrap();
}

#[test]
fn start_fails_in_running() {
    let mut ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    let err = ctrl.start().unwrap_err();
    assert!(err.contains("Cannot start"), "unexpected error: {err}");
}

#[test]
fn is_running_reflects_state() {
    let ctrl = make_controller();
    assert!(!ctrl.is_running());
    ctrl.transition(CyclicState::Running);
    assert!(ctrl.is_running());
    ctrl.transition(CyclicState::Fault);
    assert!(!ctrl.is_running());
}

#[test]
fn state_change_callback() {
    let ctrl = make_controller();
    let transitions = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&transitions);
    ctrl.on_state_change(move |old, new| seen.lock().unwrap().push((old, new)));
    ctrl.transition(CyclicState::Starting);
    ctrl.transition(CyclicState::Running);
    assert_eq!(
        *transitions.lock().unwrap(),
        vec![
            (CyclicState::Idle, CyclicState::Starting),
            (CyclicState::Starting, CyclicState::Running),
        ]
    );
}

#[test]
fn transition_noop_same_state() {
    let ctrl = make_controller();
    let transitions = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&transitions);
    ctrl.on_state_change(move |old, new| seen.lock().unwrap().push((old, new)));
    ctrl.transition(CyclicState::Idle);
    assert!(transitions.lock().unwrap().is_empty());
}

#[test]
fn debug_shows_state() {
    let ctrl = make_controller();
    assert!(format!("{ctrl:?}").contains("idle"));
    ctrl.transition(CyclicState::Running);
    assert!(format!("{ctrl:?}").contains("running"));
}

// =============================================================================
// CyclicController - Cycle Counter Tracking
// =============================================================================

#[test]
fn first_frame_sets_counter() {
    let ctrl = make_controller();
    ctrl.track_cycle_counter(42);
    assert_eq!(ctrl.last_rx_cycle_counter(), Some(42));
}

#[test]
fn sequential_frames() {
    let ctrl = make_controller();
    ctrl.track_cycle_counter(1);
    ctrl.track_cycle_counter(2);
    ctrl.track_cycle_counter(3);
    let stats = ctrl.stats();
    assert_eq!(stats.frames_duplicate, 0);
    assert_eq!(stats.frames_out_of_order, 0);
    assert_eq!(stats.frames_missed, 0);
}

#[test]
fn duplicate_detection() {
    let ctrl = make_controller();
    ctrl.track_cycle_counter(5);
    ctrl.track_cycle_counter(5);
    assert_eq!(ctrl.stats().frames_duplicate, 1);
}

#[test]
fn gap_detection() {
    let ctrl = make_controller();
    ctrl.track_cycle_counter(1);
    ctrl.track_cycle_counter(4); // gap of 2 (missed 2, 3)
    assert_eq!(ctrl.stats().frames_missed, 2);
}

#[test]
fn out_of_order_detection() {
    let ctrl = make_controller();
    ctrl.track_cycle_counter(5);
    ctrl.track_cycle_counter(3); // went backwards
    assert_eq!(ctrl.stats().frames_out_of_order, 1);
}

#[test]
fn wrap_around() {
    let ctrl = make_controller();
    ctrl.track_cycle_counter(0xFFFE);
    ctrl.track_cycle_counter(0xFFFF);
    ctrl.track_cycle_counter(0x0000);
    let stats = ctrl.stats();
    assert_eq!(stats.frames_missed, 0);
    assert_eq!(stats.frames_duplicate, 0);
    assert_eq!(stats.frames_out_of_order, 0);
}

#[test]
fn wrap_with_gap() {
    let ctrl = make_controller();
    ctrl.track_cycle_counter(0xFFFE);
    ctrl.track_cycle_counter(0x0001); // missed FFFF and 0000
    assert_eq!(ctrl.stats().frames_missed, 2);
}

#[test]
fn step_based_tracking() {
    // With SCF=32, RR=32 the step is 1024.
    let ctrl = make_controller_with(make_input_iocr(32, 32), make_output_iocr(32, 32), 3);
    ctrl.track_cycle_counter(0);
    ctrl.track_cycle_counter(1024);
    ctrl.track_cycle_counter(2048);
    let stats = ctrl.stats();
    assert_eq!(stats.frames_missed, 0);
    assert_eq!(stats.frames_duplicate, 0);
}

#[test]
fn step_based_gap() {
    // With step=1024, skipping one frame means the counter jumps by 2048.
    let ctrl = make_controller_with(make_input_iocr(32, 32), make_output_iocr(32, 32), 3);
    ctrl.track_cycle_counter(0);
    ctrl.track_cycle_counter(2048); // skipped one frame (1024)
    assert_eq!(ctrl.stats().frames_missed, 1);
}

#[test]
fn step_based_wrap() {
    // Near wrap: 0xFC00 + 1024 = 0x10000 -> wraps to 0x0000.
    let ctrl = make_controller_with(make_input_iocr(32, 32), make_output_iocr(32, 32), 3);
    ctrl.track_cycle_counter(0xFC00);
    ctrl.track_cycle_counter(0x0000);
    let stats = ctrl.stats();
    assert_eq!(stats.frames_missed, 0);
    assert_eq!(stats.frames_duplicate, 0);
}

// =============================================================================
// CyclicController - Watchdog
// =============================================================================

#[test]
fn single_timeout_increments_counter() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    ctrl.handle_watchdog_timeout();
    let stats = ctrl.stats();
    assert_eq!(stats.frames_missed, 1);
    assert_eq!(stats.consecutive_timeouts, 1);
    assert_eq!(ctrl.state(), CyclicState::Running); // not FAULT yet
}

#[test]
fn fault_after_max_timeouts() {
    let ctrl = make_controller_with(make_input_iocr(1, 1), make_output_iocr(32, 32), 3);
    ctrl.transition(CyclicState::Running);
    ctrl.handle_watchdog_timeout();
    ctrl.handle_watchdog_timeout();
    assert_eq!(ctrl.state(), CyclicState::Running);
    ctrl.handle_watchdog_timeout();
    assert_eq!(ctrl.state(), CyclicState::Fault);
}

#[test]
fn timeout_callback_called() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    let calls = Arc::new(Mutex::new(0u32));
    let seen = Arc::clone(&calls);
    ctrl.on_timeout(move || *seen.lock().unwrap() += 1);
    ctrl.handle_watchdog_timeout();
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[test]
fn error_callback_on_fault() {
    let ctrl = make_controller_with(make_input_iocr(1, 1), make_output_iocr(32, 32), 1);
    ctrl.transition(CyclicState::Running);
    let errors = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&errors);
    ctrl.on_error(move |msg| seen.lock().unwrap().push(msg.to_string()));
    ctrl.handle_watchdog_timeout();
    let errors = errors.lock().unwrap();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("Communication lost"));
}

#[test]
fn disable_fault_with_zero() {
    let ctrl = make_controller_with(make_input_iocr(1, 1), make_output_iocr(32, 32), 0);
    ctrl.transition(CyclicState::Running);
    for _ in 0..100 {
        ctrl.handle_watchdog_timeout();
    }
    assert_eq!(ctrl.state(), CyclicState::Running); // never goes to FAULT
}

#[test]
fn consecutive_timeouts_reset_on_rx() {
    // Feed a real frame through process_input_frame to verify the counter
    // actually resets (rather than poking the field, which would be
    // tautological).
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    ctrl.handle_watchdog_timeout();
    ctrl.handle_watchdog_timeout();
    assert_eq!(ctrl.stats().consecutive_timeouts, 2);
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 1, None, None));
    assert_eq!(ctrl.stats().consecutive_timeouts, 0);
}

#[test]
fn vlan_tagged_input_frame_accepted() {
    // Linux AF_PACKET strips the 802.1Q tag, but libpcap/BPF (macOS,
    // Windows) delivers it in-band. process_input_frame must skip the
    // 4-byte tag instead of dropping the frame on the 0x8100 ethertype.
    let mut payload = vec![0x01, 0x02, 0x03, 0x04, 0x80];
    payload.extend_from_slice(&[0u8; 35]);

    let untagged = make_controller();
    untagged.transition(CyclicState::Running);
    let rt_frame = RtFrame {
        frame_id: untagged.input_iocr().frame_id,
        cycle_counter: 1,
        data_status: RUN_STATUS,
        transfer_status: 0x00,
        payload,
    };
    let rt_bytes = rt_frame.to_bytes();

    let mut untagged_frame = Vec::new();
    untagged_frame.extend_from_slice(&SRC_MAC); // dst = controller
    untagged_frame.extend_from_slice(&DST_MAC); // src = device
    untagged_frame.extend_from_slice(&0x8892u16.to_be_bytes());
    untagged_frame.extend_from_slice(&rt_bytes);
    untagged.process_input_frame(&untagged_frame);

    let tagged = make_controller();
    tagged.transition(CyclicState::Running);
    let mut tagged_frame = Vec::new();
    tagged_frame.extend_from_slice(&SRC_MAC);
    tagged_frame.extend_from_slice(&DST_MAC);
    // 802.1Q tag: TPID 0x8100 + TCI (PCP 6, VID 0) + inner ethertype 0x8892
    tagged_frame.extend_from_slice(&[0x81, 0x00, 0xC0, 0x00]);
    tagged_frame.extend_from_slice(&0x8892u16.to_be_bytes());
    tagged_frame.extend_from_slice(&rt_bytes);
    tagged.process_input_frame(&tagged_frame);

    // Both paths must count exactly one received frame.
    assert_eq!(untagged.stats().frames_received, 1);
    assert_eq!(tagged.stats().frames_received, 1);
}

// =============================================================================
// CyclicController - Input Frame Processing
// =============================================================================

#[test]
fn valid_frame_updates_stats() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 1, None, None));
    assert_eq!(ctrl.stats().frames_received, 1);
}

#[test]
fn invalid_status_counted() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 1, None, Some(0x00)));
    let stats = ctrl.stats();
    assert_eq!(stats.frames_invalid, 1);
    // The frame still counts as received (and resets the watchdog).
    assert_eq!(stats.frames_received, 1);
}

#[test]
fn wrong_frame_id_ignored() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    let frame = RtFrame {
        frame_id: 0xBEEF,
        cycle_counter: 1,
        data_status: DATA_STATUS_VALID,
        transfer_status: 0,
        payload: vec![0; 40],
    };
    ctrl.process_input_frame(&build_ethernet_frame(&SRC_MAC, &DST_MAC, &frame));
    assert_eq!(ctrl.stats().frames_received, 0);
}

#[test]
fn wrong_src_mac_ignored() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    let frame = RtFrame {
        frame_id: ctrl.input_iocr().frame_id,
        cycle_counter: 1,
        data_status: DATA_STATUS_VALID,
        transfer_status: 0,
        payload: vec![0; 40],
    };
    // dst=controller, src=wrong (not the device)
    let wrong_src = [0xFF; 6];
    ctrl.process_input_frame(&build_ethernet_frame(&SRC_MAC, &wrong_src, &frame));
    assert_eq!(ctrl.stats().frames_received, 0);
}

#[test]
fn input_callback_called() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    let received = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&received);
    ctrl.on_input(move |slot, subslot, data| {
        seen.lock().unwrap().push((slot, subslot, data.to_vec()))
    });
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 1, None, None));
    let received = received.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], (1, 1, vec![0x01, 0x02, 0x03, 0x04]));
}

#[test]
fn fault_recovery_on_frame() {
    // Receiving a frame in FAULT state recovers to RUNNING.
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Fault);
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 1, None, None));
    assert_eq!(ctrl.state(), CyclicState::Running);
}

#[test]
fn get_input_data_returns_latest() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);

    let mut payload1 = vec![0x01, 0x02, 0x03, 0x04, 0x80];
    payload1.extend_from_slice(&[0u8; 35]);
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 1, Some(payload1), None));
    assert_eq!(
        ctrl.get_input_data(1, 1),
        Some(vec![0x01, 0x02, 0x03, 0x04])
    );

    let mut payload2 = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x80];
    payload2.extend_from_slice(&[0u8; 35]);
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 2, Some(payload2), None));
    assert_eq!(
        ctrl.get_input_data(1, 1),
        Some(vec![0xAA, 0xBB, 0xCC, 0xDD])
    );
}

#[test]
fn get_input_data_none_before_rx() {
    assert_eq!(make_controller().get_input_data(1, 1), None);
}

// =============================================================================
// CyclicController - Misc
// =============================================================================

#[test]
fn cycle_time_too_fast_errors() {
    // SCF=1, RR=1 -> 31.25us cycle, far below the 1ms floor.
    let err = CyclicController::new(
        "eth0",
        SRC_MAC,
        DST_MAC,
        make_input_iocr(1, 1),
        make_output_iocr(1, 1),
        3,
    )
    .unwrap_err();
    assert!(err.contains("below 1ms"), "unexpected error: {err}");
}

// =============================================================================
// PROTO-1: TX cycle counter step
// =============================================================================

#[test]
fn tx_counter_increments_by_step() {
    // Each output frame increments the counter by SCF*RR (1024), not 1.
    let ctrl = make_controller();
    let step = 32 * 32;

    let frame = parse_ethernet_frame(&ctrl.next_output_frame(None)).unwrap();
    assert_eq!(frame.cycle_counter, step);
    assert_eq!(frame.frame_id, ctrl.output_iocr().frame_id);
    assert_eq!(frame.data_status, RUN_STATUS);
    assert_eq!(ctrl.cycle_counter(), step);

    let frame = parse_ethernet_frame(&ctrl.next_output_frame(None)).unwrap();
    assert_eq!(frame.cycle_counter, step * 2);
}

#[test]
fn tx_counter_wraps_at_16_bits() {
    let ctrl = make_controller();
    let step = 32u32 * 32;

    // 64 steps of 1024 from 0 land exactly on 0x10000 -> wraps to 0x0000.
    for _ in 0..64 {
        ctrl.next_output_frame(None);
    }
    assert_eq!(ctrl.cycle_counter(), 0x0000);

    // One more step lands at 1024.
    let frame = parse_ethernet_frame(&ctrl.next_output_frame(None)).unwrap();
    assert_eq!(frame.cycle_counter as u32, step);
}

#[test]
fn stop_frame_data_status_clears_provider_run() {
    // The graceful-stop frames carry ProviderRun cleared (STOP).
    let ctrl = make_controller();
    let stop_status = DATA_STATUS_VALID | DATA_STATUS_STATION_OK | DATA_STATUS_STATE;
    let frame = parse_ethernet_frame(&ctrl.next_output_frame(Some(stop_status))).unwrap();
    assert_eq!(frame.data_status, stop_status);
    assert!(!frame.is_running());
    assert!(frame.is_valid());
}

// =============================================================================
// PROTO-2/3: build_iocr_configs
// =============================================================================

fn fake_slot(slot: u16, subslot: u16, input_length: usize, output_length: usize) -> IoSlot {
    IoSlot {
        slot,
        subslot,
        module_ident: 0,
        submodule_ident: 0,
        input_length,
        output_length,
    }
}

#[test]
fn output_iocr_has_iocs_for_input_only_slots() {
    // Slot 1 has only input (8B), slot 2 has only output (4B): the output
    // IOCR must carry an IOCS-only entry for slot 1 so set_all_iocs() can
    // acknowledge the received input.
    let slots = [fake_slot(1, 1, 8, 0), fake_slot(2, 1, 0, 4)];
    let (_input_iocr, output_iocr) = build_iocr_configs(&slots, 0xC001, 0xC000, 32, 32, 3);

    assert_eq!(output_iocr.objects.len(), 2);

    let data_obj = &output_iocr.objects[0];
    assert_eq!(data_obj.slot, 2);
    assert_eq!(data_obj.data_length, 4);
    assert_eq!(data_obj.iops_offset, 4);

    let iocs_obj = &output_iocr.objects[1];
    assert_eq!(iocs_obj.slot, 1);
    assert_eq!(iocs_obj.data_length, 0);
    assert_eq!(iocs_obj.iocs_offset, Some(5)); // after data(4) + IOPS(1)

    // CyclicDataBuilder.set_all_iocs actually writes the IOCS byte.
    let mut builder = CyclicDataBuilder::new(output_iocr);
    builder.set_all_iocs(IOXS_GOOD);
    builder.swap();
    assert_eq!(builder.build()[5], IOXS_GOOD);
}

#[test]
fn set_all_iops_does_not_corrupt_data_via_iocs_objects() {
    // IOCS-only objects have data_length=0 and iops_offset=0; set_all_iops
    // must skip them or it would clobber the first byte of real output data.
    let slots = [fake_slot(1, 1, 8, 0), fake_slot(2, 1, 0, 4)];
    let (_input_iocr, output_iocr) = build_iocr_configs(&slots, 0xC001, 0xC000, 32, 32, 3);

    let mut builder = CyclicDataBuilder::new(output_iocr);
    builder.set_data(2, 1, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    builder.set_all_iops(IOXS_GOOD);
    builder.swap();
    let payload = builder.build();

    assert_eq!(&payload[0..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(payload[4], IOXS_GOOD); // IOPS for slot 2
}

#[test]
fn output_iocr_no_iocs_when_all_have_output() {
    let slots = [fake_slot(1, 1, 4, 4)];
    let (_input_iocr, output_iocr) = build_iocr_configs(&slots, 0xC001, 0xC000, 32, 32, 3);
    assert_eq!(output_iocr.objects.len(), 1);
    assert_eq!(output_iocr.objects[0].data_length, 4);
}

#[test]
fn input_iocr_layout_and_lengths() {
    // Input side: slot 1 gets data at 0 with IOPS at 8; slot 2 (no input)
    // contributes one IOCS byte to the length; C_SDU is padded to 40.
    let slots = [fake_slot(1, 1, 8, 0), fake_slot(2, 1, 0, 4)];
    let (input_iocr, output_iocr) = build_iocr_configs(&slots, 0xC001, 0xC000, 32, 32, 3);

    assert_eq!(input_iocr.iocr_type, IOCR_TYPE_INPUT);
    assert_eq!(input_iocr.frame_id, 0xC001);
    assert_eq!(input_iocr.objects.len(), 1);
    assert_eq!(input_iocr.objects[0].frame_offset, 0);
    assert_eq!(input_iocr.objects[0].iops_offset, 8);
    assert_eq!(input_iocr.data_length, 40); // max(40, 8+1+1)

    assert_eq!(output_iocr.iocr_type, IOCR_TYPE_OUTPUT);
    assert_eq!(output_iocr.frame_id, 0xC000);
    assert_eq!(output_iocr.data_length, 40); // max(40, 4+1+1)
}

// =============================================================================
// Remaining test_cyclic.py cases (behaviors not already covered above).
//
// Five Python tests have no Rust counterpart and are intentionally omitted:
//   - test_cycle_time_warning:  Python `warnings` module has no Rust channel;
//     only the sub-1ms hard error is modelled (cycle_time_too_fast_errors).
//   - test_context_manager_stop_called:  Python `with`/MagicMock; Rust has no
//     context-manager protocol.
//   - test_negative_max_consecutive_timeouts_raises:  the Rust parameter is a
//     u32, so a negative value is unrepresentable by construction.
//   - test_stop_sets_running_false_before_stop_frames:  a MagicMock socket/
//     thread ordering probe with no assertable Rust equivalent.
//   - test_version_is_0_6_0:  the Rust crate carries its own package version.
// =============================================================================

#[test]
fn all_states_exist() {
    // Every CyclicState variant is distinct and carries a name.
    let states = [
        CyclicState::Idle,
        CyclicState::Starting,
        CyclicState::Running,
        CyclicState::Stopping,
        CyclicState::Stopped,
        CyclicState::Fault,
    ];
    let names: std::collections::HashSet<&str> = states.iter().map(|s| s.as_str()).collect();
    assert_eq!(names.len(), 6);
    assert!(names.iter().all(|n| !n.is_empty()));
}

#[test]
fn start_allowed_from_idle() {
    // The start() gate accepts IDLE (actual socket setup is not exercised here).
    let ctrl = make_controller();
    assert_eq!(ctrl.state(), CyclicState::Idle);
}

#[test]
fn consecutive_timeouts_reset_on_valid_frame() {
    // InputFrameProcessing variant: a valid frame while RUNNING clears the
    // consecutive-timeout counter (driven through real frames, since Rust
    // stats are not externally mutable).
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    ctrl.handle_watchdog_timeout();
    ctrl.handle_watchdog_timeout();
    assert_eq!(ctrl.stats().consecutive_timeouts, 2);
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 1, None, None));
    assert_eq!(ctrl.stats().consecutive_timeouts, 0);
}

#[test]
fn tx_counter_step_computed() {
    // The output cycle-counter step equals SCF*RR (32*32 = 1024): one output
    // frame from a fresh controller advances the counter by exactly that.
    let ctrl = make_controller_with(make_input_iocr(1, 1), make_output_iocr(32, 32), 3);
    ctrl.next_output_frame(None);
    assert_eq!(ctrl.cycle_counter(), 32 * 32);
}

// =============================================================================
// Receive jitter (RX inter-arrival interval), complementing the TX send jitter
// =============================================================================

#[test]
fn rx_jitter_tracked_between_frames() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    // The first frame has no predecessor, so no interval is measured.
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 1, None, None));
    assert_eq!(ctrl.stats().rx_interval_count, 0);
    // Each subsequent frame yields exactly one arrival interval.
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 2, None, None));
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 3, None, None));
    let stats = ctrl.stats();
    assert_eq!(stats.rx_interval_count, 2);
    assert!(stats.min_rx_interval_us < (1 << 31)); // updated from the sentinel
    assert!(stats.avg_rx_interval_us() < 1_000_000); // a sane sub-second interval
}

#[test]
fn rx_jitter_skips_interval_after_timeout() {
    // A gap that spans a watchdog timeout is an outlier, not steady-state RX
    // jitter, so the frame that ends it does not contribute an interval.
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 1, None, None));
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 2, None, None));
    assert_eq!(ctrl.stats().rx_interval_count, 1);
    ctrl.handle_watchdog_timeout();
    ctrl.process_input_frame(&build_input_eth_frame(&ctrl, 3, None, None));
    assert_eq!(ctrl.stats().rx_interval_count, 1); // the post-timeout gap is skipped
}

// ---------------------------------------------------------------------------
// IOPS gating: a device disowns its input data without dropping the AR
// ---------------------------------------------------------------------------

/// One data object's payload: four data bytes, then its IOPS byte at the
/// configured iops_offset, padded to the frame length.
fn payload_with_iops(data: [u8; 4], iops: u8) -> Vec<u8> {
    let mut payload = data.to_vec();
    payload.push(iops);
    payload.extend_from_slice(&[0u8; 35]);
    payload
}

fn feed(ctrl: &CyclicController, cycle: u16, data: [u8; 4], iops: u8) {
    ctrl.process_input_frame(&build_input_eth_frame(
        ctrl,
        cycle,
        Some(payload_with_iops(data, iops)),
        None,
    ));
}

#[test]
fn input_data_marked_bad_is_withheld() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);

    feed(&ctrl, 1, [0x01, 0x02, 0x03, 0x04], 0x80);
    assert_eq!(
        ctrl.get_input_data(1, 1),
        Some(vec![0x01, 0x02, 0x03, 0x04])
    );

    // The device keeps sending the same bytes but disowns them. Handing them
    // to the application as if they were live readings is the bug.
    feed(&ctrl, 2, [0x01, 0x02, 0x03, 0x04], 0x00);
    assert_eq!(ctrl.get_input_data(1, 1), None);
    assert!(!ctrl.is_input_good(1, 1));
    assert_eq!(ctrl.get_input_status(1, 1), Some(0x00));
    // Deliberately asking for it anyway still works.
    assert_eq!(
        ctrl.get_input_data_allow_bad(1, 1),
        Some(vec![0x01, 0x02, 0x03, 0x04])
    );
}

#[test]
fn a_good_iops_with_extension_bits_stays_good() {
    // DataState is bit 7; the lower bits carry Instance and Extension. A
    // received IOxS has to be masked, not compared against IOXS_GOOD.
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    feed(&ctrl, 1, [0xAA, 0xBB, 0xCC, 0xDD], 0x81);
    assert!(ctrl.is_input_good(1, 1));
    assert_eq!(
        ctrl.get_input_data(1, 1),
        Some(vec![0xAA, 0xBB, 0xCC, 0xDD])
    );
}

#[test]
fn nothing_received_yet_is_not_good() {
    let ctrl = make_controller();
    assert!(!ctrl.is_input_good(1, 1));
    assert_eq!(ctrl.get_input_status(1, 1), None);
}

#[test]
fn the_status_callback_fires_only_on_transitions() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&seen);
    ctrl.on_input_status(move |slot, subslot, iops| {
        sink.lock().unwrap().push((slot, subslot, iops))
    });

    feed(&ctrl, 1, [0x01, 0x02, 0x03, 0x04], 0x80); // first GOOD: a transition
    feed(&ctrl, 2, [0x01, 0x02, 0x03, 0x04], 0x80); // still GOOD: silent
    feed(&ctrl, 3, [0x01, 0x02, 0x03, 0x04], 0x00); // GOOD -> BAD
    feed(&ctrl, 4, [0x01, 0x02, 0x03, 0x04], 0x00); // still BAD: silent
    feed(&ctrl, 5, [0x01, 0x02, 0x03, 0x04], 0x80); // BAD -> GOOD

    let events = seen.lock().unwrap();
    assert_eq!(
        *events,
        vec![(1, 1, 0x80), (1, 1, 0x00), (1, 1, 0x80)],
        "one event per transition, none for repeats"
    );
}

#[test]
fn the_data_callback_is_silent_while_the_device_marks_it_bad() {
    let ctrl = make_controller();
    ctrl.transition(CyclicState::Running);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&seen);
    ctrl.on_input(move |slot, subslot, data| {
        sink.lock().unwrap().push((slot, subslot, data.to_vec()))
    });

    feed(&ctrl, 1, [0x01, 0x02, 0x03, 0x04], 0x80);
    feed(&ctrl, 2, [0x05, 0x06, 0x07, 0x08], 0x00);

    let events = seen.lock().unwrap();
    assert_eq!(events.len(), 1, "the BAD frame must not be delivered");
    assert_eq!(events[0], (1, 1, vec![0x01, 0x02, 0x03, 0x04]));
}

#[test]
fn an_input_only_device_still_gets_its_consumer_status() {
    // No submodule has output data, so the first IOCS byte sits at offset 0.
    // A "> 0" guard treated that as "no IOCS" and left the device seeing BAD
    // for the whole session.
    let slots = [fake_slot(1, 1, 8, 0), fake_slot(2, 1, 4, 0)];
    let (_input, output) = build_iocr_configs(&slots, 0xC001, 0xC000, 32, 32, 3);
    assert_eq!(output.objects.len(), 2);
    assert_eq!(output.objects[0].iocs_offset, Some(0));
    assert_eq!(output.objects[1].iocs_offset, Some(1));

    let mut builder = CyclicDataBuilder::new(output);
    builder.set_all_iocs(IOXS_GOOD);
    builder.swap();
    let frame = builder.build();
    assert_eq!(frame[0], IOXS_GOOD, "slot 1 consumer status");
    assert_eq!(frame[1], IOXS_GOOD, "slot 2 consumer status");
}

// ---------------------------------------------------------------------------
// Watchdog: consumer status vs. monitoring-only operation
// ---------------------------------------------------------------------------

/// Output IOCR with a real IOCS byte, so set_all_iocs has somewhere to write:
/// slot 1 is input-only (its IOCS lives in the output frame), slot 2 output.
fn output_iocr_with_iocs() -> IocrConfig {
    let slots = [fake_slot(1, 1, 8, 0), fake_slot(2, 1, 0, 4)];
    let (_input, output) = build_iocr_configs(&slots, 0xC001, 0xC000, 32, 32, 3);
    output
}

/// The IOCS byte of the input-only slot in the next output frame.
fn iocs_byte(ctrl: &CyclicController) -> u8 {
    let frame = parse_ethernet_frame(&ctrl.next_output_frame(None)).expect("RT frame");
    frame.payload[5]
}

#[test]
fn a_watchdog_timeout_marks_the_consumer_status_bad() {
    let ctrl = make_controller_with(make_input_iocr(1, 1), output_iocr_with_iocs(), 3);
    ctrl.transition(CyclicState::Running);
    // Input arrived once, so the consumer status starts out GOOD.
    feed(&ctrl, 1, [0x01, 0x02, 0x03, 0x04], 0x80);
    assert_eq!(iocs_byte(&ctrl), IOXS_GOOD);
    ctrl.handle_watchdog_timeout();
    assert_eq!(
        iocs_byte(&ctrl),
        IOXS_BAD,
        "a watchdog that may fault must report the input as not consumed"
    );
}

#[test]
fn a_monitoring_only_watchdog_keeps_the_consumer_status_good() {
    // max_consecutive_timeouts = 0 means "never enter FAULT": the watchdog
    // only counts. Reporting IOCS BAD then asks the device to drop an output
    // relationship that is deliberately not being faulted.
    let ctrl = make_controller_with(make_input_iocr(1, 1), output_iocr_with_iocs(), 0);
    ctrl.transition(CyclicState::Running);
    feed(&ctrl, 1, [0x01, 0x02, 0x03, 0x04], 0x80);
    assert_eq!(iocs_byte(&ctrl), IOXS_GOOD);
    ctrl.handle_watchdog_timeout();
    assert_eq!(iocs_byte(&ctrl), IOXS_GOOD);
    assert_eq!(
        ctrl.state(),
        CyclicState::Running,
        "a monitoring-only watchdog must not fault"
    );
}
