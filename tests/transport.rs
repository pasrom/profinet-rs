//! Tests for the transport module's response parsers against golden vectors
//! generated from the Python reference (tools/gen_transport_golden.py ->
//! tests/golden/transport.json). The socket round-trip itself is
//! bench-validated against real hardware; these tests cover the DREP-aware
//! parsing, the PNIO error path, the echoed-request-skip loop and the
//! CControl (ApplicationReady) exchange, which are the error-prone parts.

use std::collections::VecDeque;

use profinet_rs::transport::{
    ccontrol_response, next_rpc_response, parse_ccontrol_request, parse_connect_response,
    parse_iod_header, parse_nrd, parse_read_response, parse_rpc_header, parse_rpc_response,
    PACKET_TYPE_RESPONSE,
};

fn golden() -> serde_json::Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/transport.json"
    ))
    .expect("read golden file");
    serde_json::from_str(&raw).expect("parse golden file")
}

fn entry_bytes(entry: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(entry[field].as_str().expect("hex field")).expect("valid hex")
}

#[test]
fn parse_rpc_header_be_and_le_extract_same_fields() {
    let golden = golden();
    let be = parse_rpc_header(&entry_bytes(&golden["read_response_be"], "hex")).unwrap();
    let le = parse_rpc_header(&entry_bytes(&golden["read_response_le"], "hex")).unwrap();

    assert!(!be.is_little_endian);
    assert!(le.is_little_endian);
    assert_eq!(be.drep, [0x00, 0x00, 0x00]);
    assert_eq!(le.drep, [0x10, 0x00, 0x00]);

    for (name, hdr) in [("be", &be), ("le", &le)] {
        assert_eq!(hdr.packet_type, PACKET_TYPE_RESPONSE, "{name}");
        assert_eq!(
            u64::from(hdr.operation_number),
            golden["read_response_be"]["opnum"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            u64::from(hdr.sequence_number),
            golden["read_response_be"]["seq"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(hdr.length_of_body as usize, hdr.payload.len(), "{name}");
        assert_eq!(
            hdr.payload,
            entry_bytes(&golden["read_response_be"], "body"),
            "{name}"
        );
        assert_eq!(hdr.interface_hint, 0xFFFF, "{name}");
        assert_eq!(hdr.interface_version, 1, "{name}");
    }
}

#[test]
fn parse_read_response_extracts_record_payload_from_both_dreps() {
    let golden = golden();
    let expected = entry_bytes(&golden["read_response_be"], "record_payload");
    for name in ["read_response_be", "read_response_le"] {
        let hdr = parse_rpc_header(&entry_bytes(&golden[name], "hex")).unwrap();
        assert_eq!(
            parse_read_response(&hdr.payload, hdr.is_little_endian).unwrap(),
            expected,
            "{name}"
        );
    }
}

#[test]
fn parse_iod_header_fields() {
    let golden = golden();
    let hdr = parse_rpc_header(&entry_bytes(&golden["read_response_be"], "hex")).unwrap();
    let nrd = parse_nrd(&hdr.payload, false).unwrap();
    assert_eq!(nrd.args_status, 0);
    assert_eq!(nrd.args_length as usize, nrd.payload.len());
    let iod = parse_iod_header(&nrd.payload).unwrap();
    assert_eq!(iod.block_type, 0x8009); // IODReadResponseHeader
    assert_eq!(iod.slot, 1);
    assert_eq!(iod.subslot, 1);
    assert_eq!(iod.index, 0xAFF0);
    assert_eq!(iod.length as usize, iod.payload.len());
    assert_eq!(
        iod.ar_uuid,
        *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    );
}

#[test]
fn nonzero_args_status_is_pnio_error_with_code() {
    let golden = golden();
    let entry = &golden["error_response"];
    let hdr = parse_rpc_header(&entry_bytes(entry, "hex")).unwrap();
    let err = parse_read_response(&hdr.payload, hdr.is_little_endian).unwrap_err();
    let code = entry["args_status"].as_u64().unwrap() as u32;
    assert!(
        err.contains(&format!("0x{code:08X}")),
        "error {err:?} should contain PNIO code 0x{code:08X}"
    );
}

#[test]
fn echoed_request_is_skipped_by_receive_loop() {
    let golden = golden();
    let echo = entry_bytes(&golden["echoed_request"], "hex");
    let resp = entry_bytes(&golden["read_response_be"], "hex");

    // The echoed request alone classifies as "skip".
    assert_eq!(parse_rpc_response(&echo).unwrap(), None);

    // The loop consumes the echo, then returns the real response. Request and
    // response of a DCE-RPC pair share activity UUID + sequence number.
    let hdr = parse_rpc_header(&resp).expect("golden response header");
    let mut packets: VecDeque<Vec<u8>> = VecDeque::from([echo, resp]);
    let parsed = next_rpc_response(
        || packets.pop_front().ok_or_else(|| "timeout".to_string()),
        &hdr.activity_uuid,
        hdr.sequence_number,
    )
    .unwrap();
    assert_eq!(parsed.packet_type, PACKET_TYPE_RESPONSE);
    assert!(packets.is_empty(), "both packets consumed");
}

#[test]
fn fault_and_reject_are_errors() {
    let golden = golden();
    let fault = entry_bytes(&golden["fault_response"], "hex");
    let err = parse_rpc_response(&fault).unwrap_err();
    let code = golden["fault_response"]["fault_code"].as_u64().unwrap() as u16;
    assert!(err.contains("fault"), "{err:?}");
    assert!(err.contains(&format!("0x{code:04X}")), "{err:?}");

    let reject = entry_bytes(&golden["reject_response"], "hex");
    assert!(parse_rpc_response(&reject)
        .unwrap_err()
        .contains("rejected"));

    // Too-short packets are errors, not panics.
    assert!(parse_rpc_response(&[0u8; 10]).is_err());
    assert!(parse_rpc_header(&[0u8; 79]).is_none());
}

#[test]
fn connect_response_yields_frame_ids() {
    let golden = golden();
    let entry = &golden["connect_response"];
    let hdr = parse_rpc_header(&entry_bytes(entry, "hex")).unwrap();
    let result = parse_connect_response(&hdr.payload, hdr.is_little_endian).unwrap();
    assert_eq!(
        u64::from(result.input_frame_id),
        entry["input_frame_id"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(result.output_frame_id),
        entry["output_frame_id"].as_u64().unwrap()
    );
    assert!(result.has_cyclic);
}

#[test]
fn connect_response_without_iocr_blocks_has_no_cyclic() {
    // NRD(status 0) wrapping a lone ARBlockRes-sized filler block.
    let mut nrd = Vec::new();
    nrd.extend_from_slice(&0u32.to_be_bytes());
    for _ in 0..4 {
        nrd.extend_from_slice(&8u32.to_be_bytes());
    }
    nrd.extend_from_slice(&[0x81, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00]);
    let result = parse_connect_response(&nrd, false).unwrap();
    assert_eq!(result.input_frame_id, 0);
    assert_eq!(result.output_frame_id, 0);
    assert!(!result.has_cyclic);
}

#[test]
fn ccontrol_request_parses_and_response_matches_reference() {
    let golden = golden();
    for (req_name, resp_name) in [
        ("ccontrol_request_le", "ccontrol_response_le"),
        ("ccontrol_request_be", "ccontrol_response_be"),
    ] {
        let entry = &golden[req_name];
        let hdr = parse_rpc_header(&entry_bytes(entry, "hex")).unwrap();
        let cc = parse_ccontrol_request(&hdr).unwrap();
        assert_eq!(
            u64::from(cc.block_type),
            entry["block_type"].as_u64().unwrap(),
            "{req_name}"
        );
        assert_eq!(
            u64::from(cc.control_command),
            entry["control_command"].as_u64().unwrap(),
            "{req_name}"
        );
        assert_eq!(cc.nrd_body, entry_bytes(entry, "nrd_body"), "{req_name}");

        let resp_entry = &golden[resp_name];
        let mut ar_uuid = [0u8; 16];
        ar_uuid.copy_from_slice(&entry_bytes(resp_entry, "ar_uuid"));
        let session_key = resp_entry["session_key"].as_u64().unwrap() as u16;
        let resp = ccontrol_response(&hdr, &ar_uuid, session_key);
        assert_eq!(
            hex::encode(resp),
            resp_entry["hex"].as_str().unwrap(),
            "{resp_name}"
        );
    }
}

#[test]
fn ccontrol_request_rejects_non_control_packets() {
    let golden = golden();
    // A RESPONSE packet is not a device CControl request.
    let hdr = parse_rpc_header(&entry_bytes(&golden["read_response_be"], "hex")).unwrap();
    assert!(parse_ccontrol_request(&hdr).is_err());
    // An echoed READ request has the wrong opnum.
    let hdr = parse_rpc_header(&entry_bytes(&golden["echoed_request"], "hex")).unwrap();
    assert!(parse_ccontrol_request(&hdr).is_err());
}

// ---------------------------------------------------------------------------
// Ports of profinet-py tests/test_protocol.py (PNRPCHeader, PNNRDData,
// PNIODHeader packet structures) and tests/test_rpc.py (_send_receive
// DREP handling and echo-skip), rebuilt on the same hand-constructed byte
// vectors instead of golden files. The Python mock-socket lifecycle tests
// (RPCCon init/close, CControl socket binding) are not ported: they exercise
// unittest.mock plumbing, while the packet logic is covered here.
// ---------------------------------------------------------------------------

mod py_parity {
    use std::collections::VecDeque;

    use profinet_rs::rpc;
    use profinet_rs::transport::{
        next_rpc_response, parse_iod_header, parse_nrd, parse_rpc_header, IOCR_BLOCK_RES,
        PACKET_TYPE_FAULT, PACKET_TYPE_REQUEST, PACKET_TYPE_RESPONSE,
    };

    /// Build minimal valid PNRPCHeader bytes with big-endian DREP, exactly as
    /// the Python helper `_build_rpc_bytes` packs them.
    fn build_rpc_bytes(packet_type: u8, operation_number: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(80 + payload.len());
        out.push(0x04); // version
        out.push(packet_type);
        out.push(0x00); // flags1
        out.push(0x00); // flags2
        out.extend_from_slice(&[0x00, 0x00, 0x00]); // drep (big-endian)
        out.push(0x00); // serial_high
        out.extend_from_slice(&[0u8; 48]); // object/interface/activity UUIDs
        out.extend_from_slice(&0u32.to_be_bytes()); // server_boot_time
        out.extend_from_slice(&1u32.to_be_bytes()); // interface_version
        out.extend_from_slice(&0u32.to_be_bytes()); // sequence_number
        out.extend_from_slice(&operation_number.to_be_bytes());
        out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // interface_hint
        out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // activity_hint
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes()); // length_of_body
        out.extend_from_slice(&0u16.to_be_bytes()); // fragment_number
        out.push(0x00); // auth_protocol
        out.push(0x00); // serial_low
        out.extend_from_slice(payload);
        out
    }

    /// Build PNRPCHeader bytes with little-endian DREP (0x10), exactly as
    /// the Python helper `_build_rpc_bytes_le` packs them.
    fn build_rpc_bytes_le(packet_type: u8, operation_number: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(80 + payload.len());
        out.push(0x04);
        out.push(packet_type);
        out.push(0x00);
        out.push(0x00);
        out.extend_from_slice(&[0x10, 0x00, 0x00]); // DREP = little-endian
        out.push(0x00);
        out.extend_from_slice(&[0u8; 48]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&operation_number.to_le_bytes());
        out.extend_from_slice(&0xFFFFu16.to_le_bytes());
        out.extend_from_slice(&0xFFFFu16.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.push(0x00);
        out.push(0x00);
        out.extend_from_slice(payload);
        out
    }

    // TestPNRPCHeader::test_constants
    #[test]
    fn rpc_header_constants() {
        assert_eq!(rpc::REQUEST, 0x00);
        assert_eq!(PACKET_TYPE_REQUEST, 0x00);
        assert_eq!(PACKET_TYPE_RESPONSE, 0x02);
        assert_eq!(PACKET_TYPE_FAULT, 0x03);
        assert_eq!(rpc::CONNECT, 0x00);
        assert_eq!(rpc::RELEASE, 0x01);
        assert_eq!(rpc::READ, 0x02);
        assert_eq!(rpc::WRITE, 0x03);
        assert_eq!(rpc::CONTROL, 0x04);
    }

    // TestPNRPCHeader::test_interface_uuids + test_object_uuid_prefix (only
    // the device interface UUID exists as bytes in Rust; the other roles are
    // canonical strings in `epm`, checked in tests/acyclic.rs)
    #[test]
    fn rpc_uuid_constant_sizes() {
        assert_eq!(rpc::IFACE_UUID_DEVICE.len(), 16);
        assert_eq!(rpc::OBJECT_UUID_PREFIX.len(), 10);
    }

    // TestPNRPCHeader::test_parse_rpc_header
    #[test]
    fn parse_minimal_rpc_header() {
        let mut data = vec![0u8; 80];
        data[0] = 0x04; // version
        data[1] = 0x02; // packet_type (RESPONSE)
        data[2] = 0x20; // flags1
        let pkt = parse_rpc_header(&data).unwrap();
        assert_eq!(pkt.version, 0x04);
        assert_eq!(pkt.packet_type, 0x02);
    }

    // TestPNNRDData::test_parse_nrd_data (the serialization roundtrip is not
    // ported: the Rust nrd() builder emits the fixed request-side counts)
    #[test]
    fn parse_nrd_data_fields() {
        let mut data = Vec::new();
        for v in [0u32, 0x100, 0x100, 0, 0x100] {
            data.extend_from_slice(&v.to_be_bytes());
        }
        let pkt = parse_nrd(&data, false).unwrap();
        assert_eq!(pkt.args_status, 0);
        assert_eq!(pkt.args_length, 256);
        assert_eq!(pkt.actual_count, 256);
    }

    // TestPNIODHeader::test_parse_iod_header
    #[test]
    fn parse_iod_header_fields() {
        let mut data = vec![0u8; 64];
        data[0..2].copy_from_slice(&0x0009u16.to_be_bytes());
        data[2..4].copy_from_slice(&60u16.to_be_bytes());
        data[4] = 1;
        data[6..8].copy_from_slice(&1u16.to_be_bytes()); // sequence_number
        data[24..28].copy_from_slice(&0u32.to_be_bytes()); // api
        data[28..30].copy_from_slice(&0u16.to_be_bytes()); // slot
        data[30..32].copy_from_slice(&1u16.to_be_bytes()); // subslot
        data[34..36].copy_from_slice(&0xAFF0u16.to_be_bytes()); // index
        data[36..40].copy_from_slice(&64u32.to_be_bytes()); // length

        let pkt = parse_iod_header(&data).unwrap();
        assert_eq!(pkt.sequence_number, 1);
        assert_eq!(pkt.api, 0);
        assert_eq!(pkt.slot, 0);
        assert_eq!(pkt.subslot, 1);
        assert_eq!(pkt.index, 0xAFF0);
        assert_eq!(pkt.length, 64);
    }

    // TestPNIOCRBlockRes::test_block_type_constant
    #[test]
    fn iocr_block_res_constant() {
        assert_eq!(IOCR_BLOCK_RES, 0x8102);
    }

    // TestSendReceiveLittleEndian::test_little_endian_response_parsed
    #[test]
    fn little_endian_response_parsed() {
        let le_response = build_rpc_bytes_le(PACKET_TYPE_RESPONSE, 0x02, &[0u8; 20]);
        let result = parse_rpc_header(&le_response).unwrap();
        assert!(result.is_little_endian);
        assert_eq!(result.packet_type, PACKET_TYPE_RESPONSE);
        assert_eq!(result.operation_number, 0x02);
        assert_eq!(result.length_of_body, 20);
    }

    // TestSendReceiveLittleEndian::test_little_endian_fields_correctly_swapped
    #[test]
    fn little_endian_fields_correctly_swapped() {
        let le_response = build_rpc_bytes_le(PACKET_TYPE_RESPONSE, 0x03, &[0xAB; 10]);
        let result = parse_rpc_header(&le_response).unwrap();
        assert_eq!(result.operation_number, 0x03);
        assert_eq!(result.length_of_body, 10);
    }

    // TestSendReceiveEchoSkip::test_echo_skip_returns_response
    #[test]
    fn echo_skip_returns_response() {
        let request = build_rpc_bytes(PACKET_TYPE_REQUEST, 0x02, &[]);
        let response = build_rpc_bytes(PACKET_TYPE_RESPONSE, 0x02, &[]);
        let mut packets: VecDeque<Vec<u8>> = VecDeque::from([request, response]);
        let mut recv_count = 0;
        // build_rpc_bytes zeroes the activity UUID and sequence number.
        let result = next_rpc_response(
            || {
                recv_count += 1;
                packets.pop_front().ok_or_else(|| "timeout".to_string())
            },
            &[0u8; 16],
            0,
        )
        .unwrap();
        assert_eq!(result.packet_type, PACKET_TYPE_RESPONSE);
        // recv was called twice (REQUEST skipped, RESPONSE returned).
        assert_eq!(recv_count, 2);
    }

    // TestSendReceiveEchoSkip::test_echo_skip_timeout: only REQUEST packets
    // arrive until the (simulated) deadline errors out of the loop.
    #[test]
    fn echo_skip_times_out_on_endless_requests() {
        let request = build_rpc_bytes(PACKET_TYPE_REQUEST, 0x02, &[]);
        let mut remaining = 3;
        let err = next_rpc_response(
            || {
                if remaining == 0 {
                    return Err("No response from device".to_string());
                }
                remaining -= 1;
                Ok(request.clone())
            },
            &[0u8; 16],
            0,
        )
        .unwrap_err();
        assert!(err.contains("No response"), "{err}");
    }
}

/// A device that answers with the opposite DREP must still yield a usable
/// PNIO status.
///
/// The status check used to parse the NRD as big-endian regardless of what
/// the response said, so on a little-endian responder every status came out
/// byte-reversed: BUSY read as 0x00C280DE instead of 0xDE80C200. Callers
/// compare against the canonical codes, so the BUSY retry and the
/// wrong-length/bad-index classification silently never matched. Found on a
/// real device, which answers little-endian.
#[test]
fn pnio_status_survives_an_opposite_drep_response() {
    // Minimal little-endian NRD carrying the BUSY status.
    const BUSY: u32 = 0xDE80_C200;
    let mut nrd_le = Vec::new();
    nrd_le.extend_from_slice(&BUSY.to_le_bytes()); // args_status
    nrd_le.extend_from_slice(&[0u8; 16]); // length, max, offset, actual
    let err = parse_read_response(&nrd_le, true).unwrap_err();
    assert!(
        err.contains(&format!("0x{BUSY:08X}")),
        "little-endian response must report the canonical code, got {err}"
    );

    // The same status from a big-endian responder reads identically.
    let mut nrd_be = Vec::new();
    nrd_be.extend_from_slice(&BUSY.to_be_bytes());
    nrd_be.extend_from_slice(&[0u8; 16]);
    let err_be = parse_read_response(&nrd_be, false).unwrap_err();
    assert!(err_be.contains(&format!("0x{BUSY:08X}")), "got {err_be}");
}
