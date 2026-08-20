//! PROFINET alarm listener, ported from `alarm_listener.py` (+ the
//! PNRTAHeader / PNAlarmAckPDU packet layouts from `protocol.py`): background
//! reception of alarm notifications for an established AlarmCR, with
//! acknowledgment. Per IEC 61158-6-10, alarms arrive as RTA-PDUs over raw
//! Layer 2 (EtherType 0x8892, frame IDs 0xFC01 high / 0xFE01 low) or as UDP
//! datagrams on port 34964.
//!
//! The frame parsing/building is pure and unit-tested against golden bytes;
//! the live receive loop (over [`crate::pcap::RawSocket`], consistent with
//! dcp/cyclic) is bench-only.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::alarms::{parse_alarm_notification, AlarmNotification};
use crate::pcap::RawSocket;
use crate::util::skip_vlan_tags;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Frame ID for high-priority RT alarms (Layer 2).
pub const FRAME_ID_ALARM_HIGH: u16 = 0xFC01;
/// Frame ID for low-priority RT alarms (Layer 2).
pub const FRAME_ID_ALARM_LOW: u16 = 0xFE01;
/// EtherType for PROFINET.
pub const ETHERTYPE_PROFINET: u16 = 0x8892;
/// UDP port for alarm reception (transport 1).
pub const ALARM_UDP_PORT: u16 = 34964;

/// RTA AddFlags: window size in bits 0-3.
pub const ADD_FLAGS_WINDOW_1: u8 = 0x01;
/// RTA AddFlags: TACK, "transport-acknowledge this PDU", bit 4.
pub const ADD_FLAGS_TACK: u8 = 0x10;

/// RTA sequence numbers start at 0xFFFF and wrap modulo 0x8000 once
/// acknowledged, so the counters are masked rather than allowed to roll over a
/// full u16.
pub const SEQ_NUM_INIT: u16 = 0xFFFF;
/// Initial value of the "previous" counters (`SEQ_NUM_INIT - 1`).
pub const SEQ_NUM_INIT_O: u16 = 0xFFFE;
/// Mask applied after every increment.
pub const SEQ_NUM_MASK: u16 = 0x7FFF;

/// 802.1Q priority tag for high-priority alarm frames: PCP 6, VID 0.
pub const VLAN_TAG_ALARM_HIGH: [u8; 4] = [0x81, 0x00, 0xC0, 0x00];
/// 802.1Q priority tag for low-priority alarm frames: PCP 5, VID 0.
pub const VLAN_TAG_ALARM_LOW: [u8; 4] = [0x81, 0x00, 0xA0, 0x00];

// ---------------------------------------------------------------------------
// RTA-PDU header (PNRTAHeader from protocol.py)
// ---------------------------------------------------------------------------

/// RTA-PDU header: Real-Time Acyclic PDU for Layer-2 alarm transport
/// (`PNRTAHeader`, 12 bytes, big-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtaHeader {
    pub alarm_dst_endpoint: u16,
    pub alarm_src_endpoint: u16,
    /// Bits: type(4) + version(4).
    pub pdu_type: u8,
    pub add_flags: u8,
    pub send_seq_num: u16,
    pub ack_seq_num: u16,
    pub var_part_len: u16,
}

impl RtaHeader {
    pub const SIZE: usize = 12;

    pub const RTA_TYPE_DATA: u8 = 0x01;
    pub const RTA_TYPE_NACK: u8 = 0x02;
    pub const RTA_TYPE_ACK: u8 = 0x03;
    pub const RTA_TYPE_ERR: u8 = 0x04;
    pub const VERSION_1: u8 = 0x01;
    pub const VERSION_2: u8 = 0x02;

    /// PDU type: the **low** nibble of `pdu_type`.
    pub fn kind(&self) -> u8 {
        self.pdu_type & 0x0F
    }

    /// Protocol version: the **high** nibble of `pdu_type`.
    pub fn version(&self) -> u8 {
        (self.pdu_type >> 4) & 0x0F
    }

    /// Encode the `pdu_type` byte: version in the high nibble, type in the
    /// low one.
    pub fn encode_pdu_type(version: u8, kind: u8) -> u8 {
        ((version & 0x0F) << 4) | (kind & 0x0F)
    }

    /// Parse an RTA-PDU header from the first 12 bytes of `data`.
    pub fn from_bytes(data: &[u8]) -> Result<RtaHeader, String> {
        if data.len() < Self::SIZE {
            return Err("RTA header too short".to_string());
        }
        Ok(RtaHeader {
            alarm_dst_endpoint: u16::from_be_bytes([data[0], data[1]]),
            alarm_src_endpoint: u16::from_be_bytes([data[2], data[3]]),
            pdu_type: data[4],
            add_flags: data[5],
            send_seq_num: u16::from_be_bytes([data[6], data[7]]),
            ack_seq_num: u16::from_be_bytes([data[8], data[9]]),
            var_part_len: u16::from_be_bytes([data[10], data[11]]),
        })
    }

    /// Serialize to the 12-byte wire layout.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..2].copy_from_slice(&self.alarm_dst_endpoint.to_be_bytes());
        out[2..4].copy_from_slice(&self.alarm_src_endpoint.to_be_bytes());
        out[4] = self.pdu_type;
        out[5] = self.add_flags;
        out[6..8].copy_from_slice(&self.send_seq_num.to_be_bytes());
        out[8..10].copy_from_slice(&self.ack_seq_num.to_be_bytes());
        out[10..12].copy_from_slice(&self.var_part_len.to_be_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// Alarm endpoint
// ---------------------------------------------------------------------------

/// Alarm endpoint configuration (`AlarmEndpoint`): everything needed to set
/// up alarm reception for an established AR with AlarmCR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmEndpoint {
    /// Network interface name (e.g. "en0").
    pub interface: String,
    /// Controller's local alarm reference (from AlarmCRBlockReq).
    pub controller_ref: u16,
    /// Device's local alarm reference (from AlarmCRBlockRes).
    pub device_ref: u16,
    /// Device MAC address.
    pub device_mac: [u8; 6],
    /// Transport type: 0 = Layer 2 (RTA), 1 = UDP.
    pub transport: u16,
    /// Retransmit interval as factor x 100 ms. The spec negotiates this in the
    /// AlarmCRBlockRes, which this crate does not parse yet, so it is local
    /// policy for now.
    pub rta_timeout_factor: u16,
    /// Retransmissions before giving up; local policy, see above.
    pub rta_retries: u16,
}

impl Default for AlarmEndpoint {
    fn default() -> Self {
        AlarmEndpoint {
            interface: String::new(),
            controller_ref: 0,
            device_ref: 0,
            device_mac: [0; 6],
            transport: 0,
            rta_timeout_factor: 1,
            rta_retries: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Pure frame filtering / parsing / building
// ---------------------------------------------------------------------------

/// Filter a raw Layer-2 frame as `_handle_layer2_frame`: require the
/// PROFINET EtherType, the expected device source MAC and an alarm frame ID.
/// Returns the priority (`true` = high) and the RTA payload after the frame
/// ID, or `None` for frames to ignore.
///
/// An optional 802.1Q VLAN tag between the source MAC and the EtherType is
/// tolerated (PROFINET RT is commonly priority-tagged), mirroring the
/// VLAN-aware DCP/BPF paths; without this a tagged alarm would be dropped.
pub fn check_layer2_frame<'a>(data: &'a [u8], device_mac: &[u8; 6]) -> Option<(bool, &'a [u8])> {
    if data.len() < 14 || data[6..12] != device_mac[..] {
        return None;
    }
    // Skip any VLAN tags so the EtherType and frame ID are read at the right
    // offset.
    let tag = skip_vlan_tags(data) - 12;
    if data.len() < 16 + tag {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12 + tag], data[13 + tag]]);
    if ethertype != ETHERTYPE_PROFINET {
        return None;
    }
    let frame_id = u16::from_be_bytes([data[14 + tag], data[15 + tag]]);
    match frame_id {
        FRAME_ID_ALARM_HIGH => Some((true, &data[16 + tag..])),
        FRAME_ID_ALARM_LOW => Some((false, &data[16 + tag..])),
        _ => None,
    }
}

/// Parse a Layer-2 alarm payload as `_process_alarm` (transport 0): strip
/// and validate the RTA header when present, then parse the notification.
/// Returns `Ok(None)` when the alarm is addressed to a different controller
/// reference (silently ignored, like the reference).
pub fn process_layer2_alarm(
    payload: &[u8],
    controller_ref: u16,
) -> Result<Option<(Option<RtaHeader>, AlarmNotification)>, String> {
    let (rta_header, alarm_data) = if payload.len() >= RtaHeader::SIZE {
        let rta = RtaHeader::from_bytes(payload)?;
        if rta.alarm_dst_endpoint != controller_ref {
            return Ok(None);
        }
        if rta.version() != RtaHeader::VERSION_1 {
            return Ok(None);
        }
        // Only an RTA DATA PDU carries an alarm notification. ACK/NACK/ERR
        // PDUs have no notification body, so skip them instead of misparsing
        // their content as an alarm.
        if rta.kind() != RtaHeader::RTA_TYPE_DATA {
            return Ok(None);
        }
        (Some(rta), &payload[RtaHeader::SIZE..])
    } else {
        (None, payload)
    };
    let alarm = parse_alarm_notification(alarm_data)?;
    Ok(Some((rta_header, alarm)))
}

/// Build the AlarmAck-PDU as `_send_ack` (`PNAlarmAckPDU`, 22 bytes):
/// BlockHeader(6) + AlarmType(2) + API(4) + Slot(2) + Subslot(2) +
/// AlarmSpecifier(2) + PNIOStatus(4).
pub fn build_alarm_ack(alarm: &AlarmNotification) -> Vec<u8> {
    let block_type: u16 = if alarm.is_high_priority() {
        0x8001 // AlarmAckHigh
    } else {
        0x8002 // AlarmAckLow
    };
    // PNAlarmAckPDU.fmt_size - 4 (exclude type + length).
    let block_length: u16 = 18;

    // Reconstruct the alarm specifier from the decoded bits.
    let alarm_specifier: u16 = (alarm.alarm_sequence_number & 0x07FF)
        | if alarm.channel_diagnosis { 0x0800 } else { 0 }
        | if alarm.manufacturer_specific {
            0x1000
        } else {
            0
        }
        | if alarm.submodule_diagnosis_state {
            0x2000
        } else {
            0
        }
        | if alarm.ar_diagnosis_state { 0x8000 } else { 0 };

    let mut out = Vec::with_capacity(22);
    out.extend_from_slice(&block_type.to_be_bytes());
    out.extend_from_slice(&block_length.to_be_bytes());
    out.push(0x01); // Version high.
    out.push(0x00); // Version low.
    out.extend_from_slice(&alarm.alarm_type.to_be_bytes());
    out.extend_from_slice(&alarm.api.to_be_bytes());
    out.extend_from_slice(&alarm.slot_number.to_be_bytes());
    out.extend_from_slice(&alarm.subslot_number.to_be_bytes());
    out.extend_from_slice(&alarm_specifier.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // PNIOStatus: OK.
    out
}

/// An outgoing RTA PDU: everything about it that is not fixed by the endpoint.
struct RtaPdu<'a> {
    kind: u8,
    add_flags: u8,
    send_seq_num: u16,
    ack_seq_num: u16,
    var_part: &'a [u8],
    high_priority: bool,
}

/// Build a complete Ethernet frame carrying an RTA PDU, as `_build_rta_frame`:
/// Ethernet header (to the endpoint's device MAC) + alarm-priority VLAN tag +
/// EtherType + alarm frame ID + RTA header + variable part.
fn build_rta_frame(endpoint: &AlarmEndpoint, controller_mac: &[u8; 6], pdu: RtaPdu<'_>) -> Vec<u8> {
    let RtaPdu {
        kind,
        add_flags,
        send_seq_num,
        ack_seq_num,
        var_part,
        high_priority,
    } = pdu;
    let rta = RtaHeader {
        alarm_dst_endpoint: endpoint.device_ref,
        alarm_src_endpoint: endpoint.controller_ref,
        pdu_type: RtaHeader::encode_pdu_type(RtaHeader::VERSION_1, kind),
        add_flags,
        send_seq_num,
        ack_seq_num,
        var_part_len: var_part.len() as u16,
    };
    let (frame_id, vlan_tag) = if high_priority {
        (FRAME_ID_ALARM_HIGH, VLAN_TAG_ALARM_HIGH)
    } else {
        (FRAME_ID_ALARM_LOW, VLAN_TAG_ALARM_LOW)
    };

    let mut frame = Vec::with_capacity(18 + 2 + RtaHeader::SIZE + var_part.len());
    frame.extend_from_slice(&endpoint.device_mac);
    frame.extend_from_slice(controller_mac);
    frame.extend_from_slice(&vlan_tag);
    frame.extend_from_slice(&ETHERTYPE_PROFINET.to_be_bytes());
    frame.extend_from_slice(&frame_id.to_be_bytes());
    frame.extend_from_slice(&rta.to_bytes());
    frame.extend_from_slice(var_part);
    frame
}

/// Build the complete Layer-2 AlarmAck frame as `_send_ack`: a DATA PDU with
/// the TACK flag set, so the device transport-acknowledges it in turn.
pub fn build_layer2_ack_frame(
    endpoint: &AlarmEndpoint,
    controller_mac: &[u8; 6],
    send_seq_num: u16,
    ack_seq_num: u16,
    ack_data: &[u8],
    high_priority: bool,
) -> Vec<u8> {
    build_rta_frame(
        endpoint,
        controller_mac,
        RtaPdu {
            kind: RtaHeader::RTA_TYPE_DATA,
            add_flags: ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
            send_seq_num,
            ack_seq_num,
            var_part: ack_data,
            high_priority,
        },
    )
}

/// Build an RTA PDU that carries no variable part: a transport ACK or a NACK.
/// The `kind` decides which; everything else about the two is identical.
fn build_rta_control_frame(
    endpoint: &AlarmEndpoint,
    controller_mac: &[u8; 6],
    kind: u8,
    send_seq_num: u16,
    ack_seq_num: u16,
    high_priority: bool,
) -> Vec<u8> {
    build_rta_frame(
        endpoint,
        controller_mac,
        RtaPdu {
            kind,
            add_flags: ADD_FLAGS_WINDOW_1,
            send_seq_num,
            ack_seq_num,
            var_part: &[],
            high_priority,
        },
    )
}

/// Build a pure RTA transport ACK (`_send_transport_ack`). Devices retransmit
/// the alarm and then abort the AR when the DATA PDU carrying it is never
/// transport-acknowledged.
pub fn build_transport_ack_frame(
    endpoint: &AlarmEndpoint,
    controller_mac: &[u8; 6],
    send_seq_num: u16,
    ack_seq_num: u16,
    high_priority: bool,
) -> Vec<u8> {
    build_rta_control_frame(
        endpoint,
        controller_mac,
        RtaHeader::RTA_TYPE_ACK,
        send_seq_num,
        ack_seq_num,
        high_priority,
    )
}

/// Build an RTA NACK for an out-of-sequence DATA PDU (`_send_nack`).
pub fn build_nack_frame(
    endpoint: &AlarmEndpoint,
    controller_mac: &[u8; 6],
    send_seq_num: u16,
    ack_seq_num: u16,
    high_priority: bool,
) -> Vec<u8> {
    build_rta_control_frame(
        endpoint,
        controller_mac,
        RtaHeader::RTA_TYPE_NACK,
        send_seq_num,
        ack_seq_num,
        high_priority,
    )
}

// ---------------------------------------------------------------------------
// RTA transport state machine (pure)
// ---------------------------------------------------------------------------

/// What the receiver must do with an incoming RTA PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtaAction {
    /// Nothing to do: wrong version, a type without transport meaning, a DATA
    /// PDU that asks for no acknowledgment, or a stale ACK.
    Ignore,
    /// The device acknowledged our last DATA PDU; any pending retransmission
    /// can be dropped.
    OurDataAcked,
    /// The device reports a sequence error on our side.
    DeviceNack,
    /// The device sent an ERR PDU; its variable part carries a PNIOStatus.
    DeviceError,
    /// Retransmission of a PDU already accepted: acknowledge it again, but do
    /// not process the notification a second time.
    ReAck,
    /// Out of sequence: answer with a NACK and do not process it.
    SendNack,
    /// In sequence: process the notification, then transport-acknowledge it.
    Accept,
}

/// RTA sequence bookkeeping (the APMS/APMR counters of `AlarmListener`).
///
/// Pure and independent of any socket so the transport rules can be tested
/// without a device: the live loop only turns the returned [`RtaAction`] into
/// frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtaSequencer {
    send_seq_num: u16,
    send_seq_num_o: u16,
    exp_seq_num: u16,
    exp_seq_num_o: u16,
}

impl Default for RtaSequencer {
    fn default() -> Self {
        RtaSequencer {
            send_seq_num: SEQ_NUM_INIT,
            send_seq_num_o: SEQ_NUM_INIT_O,
            exp_seq_num: SEQ_NUM_INIT,
            exp_seq_num_o: SEQ_NUM_INIT_O,
        }
    }
}

impl RtaSequencer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sequence number to put in the next PDU we send.
    pub fn send_seq_num(&self) -> u16 {
        self.send_seq_num
    }

    /// Sequence numbers for a transport ACK or NACK: the previous send counter
    /// and the last accepted receive counter, as the reference sends them.
    pub fn ack_seq_pair(&self) -> (u16, u16) {
        (self.send_seq_num_o, self.exp_seq_num_o)
    }

    /// Sequence numbers for a DATA PDU we originate (the AlarmAck): the
    /// current send counter, acknowledging the last PDU we accepted. Naming
    /// both pairings here keeps a caller from combining the wrong two.
    pub fn data_seq_pair(&self) -> (u16, u16) {
        (self.send_seq_num, self.exp_seq_num_o)
    }

    fn advance_send(&mut self) {
        self.send_seq_num_o = self.send_seq_num;
        // Wrapping: the counters start at 0xFFFF, so the very first increment
        // overflows a u16 before the mask brings it back into range.
        self.send_seq_num = self.send_seq_num.wrapping_add(1) & SEQ_NUM_MASK;
    }

    /// Classify an incoming PDU and advance the counters accordingly.
    pub fn on_pdu(&mut self, header: &RtaHeader) -> RtaAction {
        if header.version() != RtaHeader::VERSION_1 {
            return RtaAction::Ignore;
        }
        match header.kind() {
            RtaHeader::RTA_TYPE_ACK => {
                if header.ack_seq_num == self.send_seq_num {
                    self.advance_send();
                    RtaAction::OurDataAcked
                } else {
                    RtaAction::Ignore
                }
            }
            RtaHeader::RTA_TYPE_NACK => RtaAction::DeviceNack,
            RtaHeader::RTA_TYPE_ERR => RtaAction::DeviceError,
            RtaHeader::RTA_TYPE_DATA => {
                if header.add_flags & ADD_FLAGS_TACK == 0 {
                    return RtaAction::Ignore;
                }
                if header.send_seq_num == self.exp_seq_num_o {
                    return RtaAction::ReAck;
                }
                if header.send_seq_num != self.exp_seq_num {
                    return RtaAction::SendNack;
                }
                self.exp_seq_num_o = self.exp_seq_num;
                self.exp_seq_num = self.exp_seq_num.wrapping_add(1) & SEQ_NUM_MASK;
                // A DATA PDU may piggyback the ack for our last DATA.
                if header.ack_seq_num == self.send_seq_num {
                    self.advance_send();
                }
                RtaAction::Accept
            }
            _ => RtaAction::Ignore,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-priority channel state
// ---------------------------------------------------------------------------

/// RTA state for one alarm priority. High and low priority are independent
/// APMS/APMR instances in IEC 61158-6-10: each keeps its own sequence
/// counters, so sharing one set makes a high-priority alarm look like a
/// retransmission of a low-priority one that happened to use the same number.
struct AlarmChannel {
    seq: RtaSequencer,
    /// AlarmAck awaiting its transport ACK: frame, when to retransmit,
    /// retransmissions left.
    pending: Option<(Vec<u8>, Instant, u16)>,
    /// AlarmAck payloads waiting for the window to free. The APMS send window
    /// is one PDU: a second AlarmAck sent before the first is acknowledged
    /// would carry the same sequence number and be discarded as a duplicate.
    queued: std::collections::VecDeque<Vec<u8>>,
    high_priority: bool,
}

impl AlarmChannel {
    fn new(high_priority: bool) -> Self {
        AlarmChannel {
            seq: RtaSequencer::new(),
            pending: None,
            queued: std::collections::VecDeque::new(),
            high_priority,
        }
    }

    /// Retransmit an unacknowledged AlarmAck when its deadline passes, or send
    /// the next queued one once the window is free. Giving up after the
    /// configured retries is silent; the device may then abort the AR.
    fn service(
        &mut self,
        sock: &mut RawSocket,
        endpoint: &AlarmEndpoint,
        controller_mac: &[u8; 6],
        retransmit_after: Duration,
        now: Instant,
    ) {
        if let Some((frame, due, retries_left)) = self.pending.as_mut() {
            if now >= *due {
                if *retries_left > 0 {
                    let _ = sock.send(frame);
                    *due = now + retransmit_after;
                    *retries_left -= 1;
                } else {
                    self.pending = None;
                }
            }
        }
        if self.pending.is_some() {
            return;
        }
        let Some(ack_data) = self.queued.pop_front() else {
            return;
        };
        let (send_seq, ack_seq) = self.seq.data_seq_pair();
        let frame = build_layer2_ack_frame(
            endpoint,
            controller_mac,
            send_seq,
            ack_seq,
            &ack_data,
            self.high_priority,
        );
        let _ = sock.send(&frame);
        self.pending = Some((frame, now + retransmit_after, endpoint.rta_retries));
    }

    /// When the next deadline falls due, so the receive timeout can be capped
    /// short enough to honour it.
    fn next_due(&self) -> Option<Instant> {
        self.pending.as_ref().map(|(_, due, _)| *due)
    }
}

// ---------------------------------------------------------------------------
// Background listener (bench-only live path)
// ---------------------------------------------------------------------------

type AlarmCallback = Box<dyn Fn(&AlarmNotification) + Send + 'static>;

/// Background listener for PROFINET alarm notifications (`AlarmListener`):
/// a thread receives alarm frames from the device, parses them, invokes the
/// registered callbacks and sends acknowledgments. Requires capture
/// privileges for the raw Layer-2 transport (bench-only, like dcp/cyclic).
pub struct AlarmListener {
    pub endpoint: AlarmEndpoint,
    pub controller_mac: [u8; 6],
    running: Arc<AtomicBool>,
    callbacks: Arc<Mutex<Vec<(usize, AlarmCallback)>>>,
    next_callback_id: usize,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for AlarmListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlarmListener")
            .field("endpoint", &self.endpoint)
            .field("controller_mac", &self.controller_mac)
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl AlarmListener {
    /// Create a listener for `endpoint`; `controller_mac` is used as the
    /// source MAC of Layer-2 acknowledgments (the reference defaults it to
    /// all-zero when not given).
    pub fn new(endpoint: AlarmEndpoint, controller_mac: Option<[u8; 6]>) -> AlarmListener {
        AlarmListener {
            endpoint,
            controller_mac: controller_mac.unwrap_or([0u8; 6]),
            running: Arc::new(AtomicBool::new(false)),
            callbacks: Arc::new(Mutex::new(Vec::new())),
            next_callback_id: 0,
            thread: None,
        }
    }

    /// Register a callback invoked from the listener thread for each parsed
    /// alarm (`add_callback`). Returns an id for [`Self::remove_callback`]
    /// (the reference removes by function identity, which boxed closures
    /// don't support).
    pub fn add_callback<F>(&mut self, callback: F) -> usize
    where
        F: Fn(&AlarmNotification) + Send + 'static,
    {
        let id = self.next_callback_id;
        self.next_callback_id += 1;
        self.callbacks
            .lock()
            .expect("callbacks lock poisoned")
            .push((id, Box::new(callback)));
        id
    }

    /// Remove a previously registered callback by id (`remove_callback`).
    pub fn remove_callback(&mut self, id: usize) {
        self.callbacks
            .lock()
            .expect("callbacks lock poisoned")
            .retain(|(cb_id, _)| *cb_id != id);
    }

    /// Number of registered callbacks (mirrors the reference's tested
    /// `_callbacks` length; read-only).
    pub fn callback_count(&self) -> usize {
        self.callbacks
            .lock()
            .expect("callbacks lock poisoned")
            .len()
    }

    /// True if the listener is currently running (`is_running`).
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Start the background listener (`start`): opens the socket and spawns
    /// the listener thread. No-op if already running. Only the Layer-2
    /// transport (0) is supported; the reference's UDP branch is not ported
    /// because the raw-L2 path is the bench-proven one.
    pub fn start(&mut self) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        if self.endpoint.transport != 0 {
            return Err("only Layer-2 (transport 0) alarm reception is supported".to_string());
        }

        let mut sock = RawSocket::open(&self.endpoint.interface, Some(ETHERTYPE_PROFINET))?;
        self.running.store(true, Ordering::SeqCst);

        let running = Arc::clone(&self.running);
        let callbacks = Arc::clone(&self.callbacks);
        let endpoint = self.endpoint.clone();
        let controller_mac = self.controller_mac;

        self.thread = Some(std::thread::spawn(move || {
            // One channel per priority: their counters are independent.
            let mut low = AlarmChannel::new(false);
            let mut high_ch = AlarmChannel::new(true);
            let retransmit_after =
                Duration::from_millis(100 * u64::from(endpoint.rta_timeout_factor.max(1)));

            while running.load(Ordering::SeqCst) {
                let now = Instant::now();
                low.service(&mut sock, &endpoint, &controller_mac, retransmit_after, now);
                high_ch.service(&mut sock, &endpoint, &controller_mac, retransmit_after, now);

                // A second at most, for a clean shutdown, but never past a
                // retransmission deadline: with the default timeout factor the
                // interval is 100 ms, and a fixed 1 s wait would miss every
                // one of them until the device gave up on us.
                let mut wait = Duration::from_secs(1);
                for due in [low.next_due(), high_ch.next_due()].into_iter().flatten() {
                    wait = wait.min(due.saturating_duration_since(now));
                }
                let frame = match sock.recv(wait.max(Duration::from_millis(1))) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => continue,
                    Err(_) => break,
                };

                let Some((is_high, payload)) = check_layer2_frame(&frame, &endpoint.device_mac)
                else {
                    continue;
                };
                let Ok(rta) = RtaHeader::from_bytes(payload) else {
                    continue;
                };
                if rta.alarm_dst_endpoint != endpoint.controller_ref {
                    continue;
                }
                let channel = if is_high { &mut high_ch } else { &mut low };

                let action = channel.seq.on_pdu(&rta);
                if action == RtaAction::OurDataAcked {
                    channel.pending = None;
                    continue;
                }
                if action == RtaAction::SendNack {
                    let (send_seq, ack_seq) = channel.seq.ack_seq_pair();
                    let _ = sock.send(&build_nack_frame(
                        &endpoint,
                        &controller_mac,
                        send_seq,
                        ack_seq,
                        is_high,
                    ));
                    continue;
                }
                // Ignore, DeviceNack and DeviceError carry no notification.
                if action != RtaAction::ReAck && action != RtaAction::Accept {
                    continue;
                }

                // Transport-acknowledge before anything else, a retransmission
                // included: the device retransmits and then aborts the AR
                // without this.
                let (send_seq, ack_seq) = channel.seq.ack_seq_pair();
                let _ = sock.send(&build_transport_ack_frame(
                    &endpoint,
                    &controller_mac,
                    send_seq,
                    ack_seq,
                    is_high,
                ));
                if action == RtaAction::ReAck {
                    // Already delivered once; acking again is the whole job.
                    continue;
                }

                let Ok(Some((_, alarm))) = process_layer2_alarm(payload, endpoint.controller_ref)
                else {
                    continue;
                };

                // The application-level AlarmAck is a DATA PDU of ours, so it
                // queues behind any unacknowledged one on this channel. The
                // reference picks its frame ID from the alarm's block type
                // rather than the received frame ID.
                let ack_channel = if alarm.is_high_priority() {
                    &mut high_ch
                } else {
                    &mut low
                };
                ack_channel.queued.push_back(build_alarm_ack(&alarm));
                ack_channel.service(
                    &mut sock,
                    &endpoint,
                    &controller_mac,
                    retransmit_after,
                    Instant::now(),
                );

                for (_, callback) in callbacks.lock().expect("callbacks lock poisoned").iter() {
                    callback(&alarm);
                }
            }
        }));
        Ok(())
    }

    /// Stop the listener (`stop`): signals the thread and joins it (the
    /// receive timeout bounds the shutdown latency).
    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for AlarmListener {
    fn drop(&mut self) {
        self.stop();
    }
}
