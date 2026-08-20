//! Ports of profinet-py tests/test_review_fixes.py (regression tests for the
//! code-review fixes H-1..M-10) against the Rust port.
//!
//! Five Python tests are mock-/introspection-driven with no pure Rust
//! equivalent and are omitted:
//!   - test_check_timeout_uses_monotonic:  patches RPCCon's socket and
//!     connect() with MagicMock to probe the reconnect clock; RpcConn's
//!     timeout path is not constructible without a live raw-L2 socket.
//!   - test_session_key_not_hardcoded / test_session_key_is_nonzero:  build
//!     RPCCon instances (mocked socket) to sample the randomized session key;
//!     the Rust equivalent has no pure key generator surfaced for testing.
//!   - test_uuids_regenerated_on_reconnect:  MagicMocks _send_receive to force
//!     a reconnect and inspect ar/activity UUIDs; regeneration happens inside
//!     connect() over a live socket.
//!   - test_read_response_accepts_expected_xid_param:  a Python signature
//!     introspection check; in Rust an expected-xid argument is enforced at
//!     compile time, not discoverable at runtime.

use profinet_rs::alarm_listener::{
    build_layer2_ack_frame, AlarmEndpoint, RtaHeader, ADD_FLAGS_TACK, ADD_FLAGS_WINDOW_1,
    FRAME_ID_ALARM_HIGH, FRAME_ID_ALARM_LOW, VLAN_TAG_ALARM_HIGH, VLAN_TAG_ALARM_LOW,
};
use profinet_rs::dcp::{DCP_HELLO_MULTICAST_MAC, DCP_MULTICAST_MAC};
use profinet_rs::transport::parse_rpc_header;
use profinet_rs::util::skip_vlan_tags;

// =============================================================================
// H-1: DREP-aware RPC response parsing
// =============================================================================

/// Build a minimal 80-byte DCE/RPC response header (+ zero body), matching the
/// Python test's `_build_rpc_response`. `drep_byte` 0x10 selects little-endian
/// for the multi-byte fields.
fn build_rpc_response(drep_byte: u8, operation: u16, body_len: u16) -> Vec<u8> {
    let le = drep_byte & 0x10 != 0;
    let w16 = |v: u16| -> [u8; 2] {
        if le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    };
    let w32 = |v: u32| -> [u8; 4] {
        if le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    };

    let mut d = Vec::new();
    // Single-byte header fields (endian-independent).
    d.extend_from_slice(&[0x04, 0x02, 0x00, 0x00]); // version, RESPONSE, flags1/2
    d.extend_from_slice(&[drep_byte, 0x00, 0x00]); // drep
    d.push(0x00); // serial_high
    d.extend_from_slice(&[0u8; 16]); // object_uuid
    d.extend_from_slice(&[0u8; 16]); // interface_uuid
    d.extend_from_slice(&[0u8; 16]); // activity_uuid
                                     // Multi-byte fields in DREP byte order.
    d.extend_from_slice(&w32(0)); // server_boot_time
    d.extend_from_slice(&w32(1)); // interface_version
    d.extend_from_slice(&w32(42)); // sequence_number
    d.extend_from_slice(&w16(operation)); // operation_number
    d.extend_from_slice(&w16(0xFFFF)); // interface_hint
    d.extend_from_slice(&w16(0xFFFF)); // activity_hint
    d.extend_from_slice(&w16(body_len)); // length_of_body
    d.extend_from_slice(&w16(0)); // fragment_number
    d.push(0); // auth_protocol
    d.push(0); // serial_low
    d.extend(std::iter::repeat_n(0u8, body_len as usize)); // payload
    d
}

#[test]
fn parse_rpc_header_big_endian() {
    let data = build_rpc_response(0x00, 0x02, 20);
    let result = parse_rpc_header(&data).expect("parse");
    assert!(!result.is_little_endian);
    assert_eq!(result.operation_number, 0x02);
    assert_eq!(result.length_of_body, 20);
    assert_eq!(result.sequence_number, 42);
}

#[test]
fn parse_rpc_header_little_endian() {
    let data = build_rpc_response(0x10, 0x02, 20);
    let result = parse_rpc_header(&data).expect("parse");
    assert!(result.is_little_endian);
    assert_eq!(result.operation_number, 0x02);
    assert_eq!(result.length_of_body, 20);
    assert_eq!(result.sequence_number, 42);
}

#[test]
fn big_endian_vs_little_endian_differ_without_drep() {
    // A big-endian parser misreads a LE operation=0x02 field as 0x0200.
    let data = build_rpc_response(0x10, 0x02, 20);
    let wrong_op = u16::from_be_bytes([data[68], data[69]]);
    let correct_op = u16::from_le_bytes([data[68], data[69]]);
    assert_eq!(correct_op, 0x02);
    assert_eq!(wrong_op, 0x0200);
}

#[test]
fn parse_rpc_header_too_short() {
    assert!(parse_rpc_header(&[0u8; 10]).is_none());
    assert!(parse_rpc_header(&[]).is_none());
}

// =============================================================================
// H-3: DCP Hello multicast address
// =============================================================================

#[test]
fn hello_multicast_constant_defined() {
    assert_eq!(
        DCP_HELLO_MULTICAST_MAC,
        [0x01, 0x0E, 0xCF, 0x00, 0x00, 0x01]
    );
}

#[test]
fn identify_multicast_unchanged() {
    assert_eq!(DCP_MULTICAST_MAC, [0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00]);
}

#[test]
fn hello_and_identify_differ() {
    assert_ne!(DCP_HELLO_MULTICAST_MAC, DCP_MULTICAST_MAC);
}

// =============================================================================
// H-4 / M-9: AlarmAck RTA PDU type and priority-matched frame ID
// =============================================================================

fn ack_endpoint() -> AlarmEndpoint {
    AlarmEndpoint {
        interface: "lo".to_string(),
        controller_ref: 1,
        device_ref: 42,
        device_mac: [0x22; 6],
        transport: 0,
        ..Default::default()
    }
}

/// Offset of the frame ID in an alarm frame: past any VLAN tags and the
/// EtherType. Derived rather than hardcoded, so adding or removing a tag
/// cannot silently point these assertions at the wrong bytes.
fn frame_id_offset(frame: &[u8]) -> usize {
    skip_vlan_tags(frame) + 2
}

#[test]
fn rta_type_data_for_alarm_ack() {
    // The ack goes out as RTA_TYPE_DATA (0x01), not RTA_TYPE_ACK (0x03), with
    // the version in the high nibble of pdu_type and the type in the low one.
    let frame = build_layer2_ack_frame(&ack_endpoint(), &[0x11; 6], 0, 0, &[0u8; 20], false);
    let header = RtaHeader::from_bytes(&frame[frame_id_offset(&frame) + 2..]).unwrap();
    assert_eq!(header.kind(), RtaHeader::RTA_TYPE_DATA);
    assert_eq!(header.version(), RtaHeader::VERSION_1);
    // TACK is what stops the device retransmitting and then aborting the AR.
    assert_eq!(header.add_flags, ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK);
}

#[test]
fn high_priority_alarm_uses_high_frame_id() {
    let frame = build_layer2_ack_frame(&ack_endpoint(), &[0x11; 6], 0, 0, &[0u8; 20], true);
    assert_eq!(&frame[12..16], &VLAN_TAG_ALARM_HIGH);
    let at = frame_id_offset(&frame);
    assert_eq!(
        u16::from_be_bytes([frame[at], frame[at + 1]]),
        FRAME_ID_ALARM_HIGH
    );
}

#[test]
fn low_priority_alarm_uses_low_frame_id() {
    let frame = build_layer2_ack_frame(&ack_endpoint(), &[0x11; 6], 0, 0, &[0u8; 20], false);
    // Alarm-low frames are tagged PCP 5, not PCP 6 like RT and alarm-high.
    assert_eq!(&frame[12..16], &VLAN_TAG_ALARM_LOW);
    let at = frame_id_offset(&frame);
    assert_eq!(
        u16::from_be_bytes([frame[at], frame[at + 1]]),
        FRAME_ID_ALARM_LOW
    );
}
