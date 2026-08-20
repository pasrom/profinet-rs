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
use std::time::Duration;

use crate::alarms::{parse_alarm_notification, AlarmNotification};
use crate::dcp::VLAN_ETHERTYPE;
use crate::pcap::RawSocket;

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
    // Skip a VLAN tag so the EtherType and frame ID are read at the right offset.
    let tag = if u16::from_be_bytes([data[12], data[13]]) == VLAN_ETHERTYPE {
        4
    } else {
        0
    };
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
        // Only an RTA DATA PDU carries an alarm notification. ACK/NACK/ERR PDUs
        // (the type is the high nibble of pdu_type) have no notification body,
        // so skip them instead of misparsing their content as an alarm.
        if rta.pdu_type >> 4 != RtaHeader::RTA_TYPE_DATA {
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

/// Build the complete Layer-2 acknowledgment frame as `_send_layer2_ack`:
/// Ethernet header (to the endpoint's device MAC) + alarm frame ID (matching
/// the alarm's priority) + RTA header (DATA, version 1) + AlarmAck PDU.
pub fn build_layer2_ack_frame(
    endpoint: &AlarmEndpoint,
    controller_mac: &[u8; 6],
    send_seq_num: u16,
    ack_seq_num: u16,
    ack_data: &[u8],
    high_priority: bool,
) -> Vec<u8> {
    let rta = RtaHeader {
        alarm_dst_endpoint: endpoint.device_ref,
        alarm_src_endpoint: endpoint.controller_ref,
        pdu_type: (RtaHeader::RTA_TYPE_DATA << 4) | RtaHeader::VERSION_1,
        add_flags: 0,
        send_seq_num,
        ack_seq_num,
        var_part_len: ack_data.len() as u16,
    };
    let frame_id = if high_priority {
        FRAME_ID_ALARM_HIGH
    } else {
        FRAME_ID_ALARM_LOW
    };

    let mut frame = Vec::with_capacity(14 + 2 + RtaHeader::SIZE + ack_data.len());
    frame.extend_from_slice(&endpoint.device_mac);
    frame.extend_from_slice(controller_mac);
    frame.extend_from_slice(&ETHERTYPE_PROFINET.to_be_bytes());
    frame.extend_from_slice(&frame_id.to_be_bytes());
    frame.extend_from_slice(&rta.to_bytes());
    frame.extend_from_slice(ack_data);
    frame
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
            // RTA sequence tracking.
            let mut send_seq_num: u16 = 0;
            let mut recv_seq_num: u16 = 0;

            while running.load(Ordering::SeqCst) {
                // 1 s receive timeout for a clean shutdown, as the reference.
                let frame = match sock.recv(Duration::from_secs(1)) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => continue,
                    Err(_) => break,
                };

                let Some((_high, payload)) = check_layer2_frame(&frame, &endpoint.device_mac)
                else {
                    continue;
                };
                let Ok(Some((rta, alarm))) = process_layer2_alarm(payload, endpoint.controller_ref)
                else {
                    continue;
                };
                if let Some(rta) = rta {
                    recv_seq_num = rta.send_seq_num;
                }

                // Acknowledge, then invoke callbacks (send errors are logged
                // and ignored by the reference; here they are just ignored).
                send_seq_num = send_seq_num.wrapping_add(1);
                let ack_frame = build_layer2_ack_frame(
                    &endpoint,
                    &controller_mac,
                    send_seq_num,
                    recv_seq_num,
                    &build_alarm_ack(&alarm),
                    // The reference picks the ack frame ID from the alarm's
                    // block type, not the received frame ID.
                    alarm.is_high_priority(),
                );
                let _ = sock.send(&ack_frame);

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
