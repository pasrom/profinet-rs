//! Golden byte-fidelity tests for the DCE/RPC framing module, asserting
//! byte-for-byte equality against vectors generated from the Python
//! reference (tools/gen_golden.py -> tests/golden/foundation.json).

use profinet_rs::blocks::iod_read_request;
use profinet_rs::rpc::{
    nrd, object_uuid, read_record_implicit_request, read_record_request, rpc_request,
    write_record_request, IFACE_UUID_DEVICE, IMPLICIT_READ, READ,
};
use profinet_rs::transport::parse_rpc_header;

fn golden() -> serde_json::Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/foundation.json"
    ))
    .expect("read golden file");
    serde_json::from_str(&raw).expect("parse golden file")
}

fn golden_hex(name: &str) -> String {
    golden()[name]["hex"]
        .as_str()
        .unwrap_or_else(|| panic!("golden entry {name} missing hex"))
        .to_string()
}

fn ar_uuid() -> [u8; 16] {
    let mut ar = [0u8; 16];
    for (i, b) in ar.iter_mut().enumerate() {
        *b = i as u8;
    }
    ar
}

fn activity_uuid() -> [u8; 16] {
    let mut act = [0u8; 16];
    for (i, b) in act.iter_mut().enumerate() {
        *b = 16 + i as u8;
    }
    act
}

fn obj_uuid() -> [u8; 16] {
    object_uuid(0x00, 0x07, 0x0a, 0xbc)
}

#[test]
fn golden_object_uuid() {
    assert_eq!(
        hex::encode(obj_uuid()),
        golden_hex("object_uuid_dev0007_vendor0abc")
    );
}

#[test]
fn golden_iface_uuid_device() {
    assert_eq!(
        hex::encode(IFACE_UUID_DEVICE),
        golden_hex("iface_uuid_device")
    );
}

#[test]
fn golden_nrd_read() {
    let ar = ar_uuid();
    assert_eq!(
        hex::encode(nrd(&iod_read_request(&ar, 0, 1, 1, 4660, 8))),
        golden_hex("nrd_read_record")
    );
}

#[test]
fn golden_rpc_read() {
    let ar = ar_uuid();
    assert_eq!(
        hex::encode(read_record_request(
            &obj_uuid(),
            &IFACE_UUID_DEVICE,
            &activity_uuid(),
            &ar,
            0,
            0,
            1,
            1,
            4660,
            8
        )),
        golden_hex("rpc_read_record")
    );
}

#[test]
fn golden_rpc_write() {
    let ar = ar_uuid();
    assert_eq!(
        hex::encode(write_record_request(
            &obj_uuid(),
            &IFACE_UUID_DEVICE,
            &activity_uuid(),
            &ar,
            0,
            0,
            2,
            1,
            5000,
            &[0x01]
        )),
        golden_hex("rpc_write_5000")
    );
}

#[test]
fn length_of_body_matches_body_length() {
    let body = [0xAAu8; 300];
    let frame = rpc_request(
        &obj_uuid(),
        &IFACE_UUID_DEVICE,
        &activity_uuid(),
        7,
        READ,
        &body,
    );
    assert_eq!(frame.len(), 80 + body.len());
    let length_of_body = u16::from_be_bytes([frame[74], frame[75]]);
    assert_eq!(length_of_body as usize, body.len());
}

#[test]
fn sequence_number_is_caller_supplied() {
    // Sequence handling lives with the caller (RPCCon increments per request);
    // the builder must emit exactly the seq it was given.
    for seq in [0u32, 1, 0xDEAD_BEEF] {
        let frame = rpc_request(
            &obj_uuid(),
            &IFACE_UUID_DEVICE,
            &activity_uuid(),
            seq,
            READ,
            &[],
        );
        let got = u32::from_be_bytes([frame[64], frame[65], frame[66], frame[67]]);
        assert_eq!(got, seq);
    }
}

#[test]
fn nrd_counts_track_payload_length() {
    let out = nrd(&[0x55; 42]);
    assert_eq!(out.len(), 20 + 42);
    assert_eq!(u32::from_be_bytes([out[4], out[5], out[6], out[7]]), 42); // args_length
    assert_eq!(u32::from_be_bytes([out[16], out[17], out[18], out[19]]), 42); // actual_count
}

// ---------------------------------------------------------------------------
// Ports of profinet-py tests/test_protocol.py block-header/IOD constant tests
// (TestPNBlockHeader, TestPNIODWriteReq, TestPNIODWriteRes).
// ---------------------------------------------------------------------------

// TestPNBlockHeader::test_block_header_constants +
// TestPNIODWriteReq/TestPNIODWriteRes::test_block_type_constant
#[test]
fn iod_block_type_constants() {
    use profinet_rs::blocks::{
        IOD_READ_REQUEST_HEADER, IOD_WRITE_REQUEST_HEADER, IOD_WRITE_RESPONSE_HEADER,
    };
    assert_eq!(IOD_READ_REQUEST_HEADER, 0x0009);
    assert_eq!(IOD_WRITE_REQUEST_HEADER, 0x0008);
    assert_eq!(IOD_WRITE_RESPONSE_HEADER, 0x8008);
}

// TestPNBlockHeader::test_parse_block_header (0x0008/60/1.0 wire layout is
// what block_header() emits)
#[test]
fn block_header_builder_layout() {
    let data = profinet_rs::blocks::block_header(0x0008, 0x003C, 0x01, 0x00);
    assert_eq!(data, [0x00, 0x08, 0x00, 0x3C, 0x01, 0x00]);
}

#[test]
fn implicit_read_is_the_same_request_with_no_ar() {
    // Read Implicit addresses the device by IP alone: same IODReadReq, but the
    // AR UUID is zero and it goes out with opnum 0x05 instead of READ. A
    // device stack that rejects the Device Access AR still answers this.
    let explicit = read_record_request(
        &obj_uuid(),
        &IFACE_UUID_DEVICE,
        &activity_uuid(),
        &ar_uuid(),
        1,
        0,
        1,
        1,
        0xAFF0,
        4096,
    );
    let implicit = read_record_implicit_request(
        &obj_uuid(),
        &IFACE_UUID_DEVICE,
        &activity_uuid(),
        1,
        0,
        1,
        1,
        0xAFF0,
        4096,
    );
    assert_eq!(explicit.len(), implicit.len());

    let header = parse_rpc_header(&implicit).expect("RPC header");
    assert_eq!(header.operation_number, IMPLICIT_READ);

    // Rebuilding the explicit form with a zeroed AR UUID must reproduce the
    // implicit request everywhere except the opnum field.
    let zero_ar = read_record_request(
        &obj_uuid(),
        &IFACE_UUID_DEVICE,
        &activity_uuid(),
        &[0u8; 16],
        1,
        0,
        1,
        1,
        0xAFF0,
        4096,
    );
    let differing: Vec<usize> = (0..zero_ar.len())
        .filter(|&i| zero_ar[i] != implicit[i])
        .collect();
    assert_eq!(
        differing,
        vec![69],
        "only the opnum should differ, got {differing:?}"
    );
    assert_eq!(zero_ar[69], READ as u8);
    assert_eq!(implicit[69], IMPLICIT_READ as u8);
}
