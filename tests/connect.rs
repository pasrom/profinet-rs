//! Golden byte-fidelity tests for the Connect request PDU module, asserting
//! byte-for-byte equality against vectors generated from the Python
//! reference (tools/gen_connect_golden.py -> tests/golden/connect.json).
//!
//! Fixed inputs matching the oracle: ar_uuid 00..0f, activity_uuid 10..1f,
//! session_key 1, cm_mac 02:00:00:00:00:01, station name "controller",
//! device 0x0007 / vendor 0x0abc, seq 0, IOCR refs 1/2, alarm ref 1, and the
//! device GSDML io_slots with send_clock_factor 32 / reduction_ratio 128 /
//! watchdog_factor 6 / data_hold_factor 6.

use profinet_rs::connect::{
    alarm_cr_block, ar_block_req, build_connect_request, expected_submodule_block, iocr_block_req,
    IocrSetup, AR_PROPERTIES_DEVICE_ACCESS, AR_PROPERTIES_IOCAR, AR_TYPE_IOCAR_SINGLE,
    AR_TYPE_IOSAR,
};
use profinet_rs::gsdml::{load_gsdml, DeviceSlot};
use profinet_rs::rpc::{object_uuid, IFACE_UUID_DEVICE};

fn golden() -> serde_json::Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/connect.json"
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
    core::array::from_fn(|i| i as u8)
}

fn activity_uuid() -> [u8; 16] {
    core::array::from_fn(|i| 16 + i as u8)
}

const CM_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const SESSION_KEY: u16 = 0x0001;

/// IOCRSetup exactly as the oracle builds it: device GSDML io_slots (via
/// build_io_slots -> discovered-slot view -> build_io_slots_from_device) with
/// the cli.py cmd_cyclic timing factors.
fn setup() -> IocrSetup {
    let device = load_gsdml(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/demo.gsdml.xml"
    ))
    .expect("load demo GSDML");
    let device_slots: Vec<DeviceSlot> = device
        .build_io_slots(None, None, None)
        .expect("build_io_slots")
        .iter()
        .map(|s| DeviceSlot {
            slot: s.slot,
            subslot: s.subslot,
            module_ident: s.module_ident,
            submodule_ident: s.submodule_ident,
        })
        .collect();
    IocrSetup {
        io_slots: device
            .build_io_slots_from_device(&device_slots, None)
            .expect("build_io_slots_from_device"),
        send_clock_factor: 32,
        reduction_ratio: 128,
        watchdog_factor: 6,
        data_hold_factor: 6,
    }
}

#[test]
fn golden_io_slots_match_oracle() {
    // Guard: the slots feeding the block builders are the ones the oracle
    // used, so block mismatches can't hide a GSDML divergence.
    let g = golden();
    let slots = setup().io_slots;
    let golden_slots = g["io_slots"].as_array().expect("io_slots array");
    assert_eq!(slots.len(), golden_slots.len());
    for (s, gs) in slots.iter().zip(golden_slots) {
        assert_eq!(s.slot as u64, gs["slot"].as_u64().unwrap());
        assert_eq!(s.subslot as u64, gs["subslot"].as_u64().unwrap());
        assert_eq!(s.module_ident as u64, gs["module_ident"].as_u64().unwrap());
        assert_eq!(
            s.submodule_ident as u64,
            gs["submodule_ident"].as_u64().unwrap()
        );
        assert_eq!(s.input_length as u64, gs["input_length"].as_u64().unwrap());
        assert_eq!(
            s.output_length as u64,
            gs["output_length"].as_u64().unwrap()
        );
    }
}

#[test]
fn golden_ar_block_iocr_tp() {
    // The literal connect() IOCAR-path AR block (hardcoded name "tp").
    assert_eq!(
        hex::encode(ar_block_req(
            AR_TYPE_IOCAR_SINGLE,
            &ar_uuid(),
            SESSION_KEY,
            &CM_MAC,
            AR_PROPERTIES_IOCAR,
            b"tp",
        )),
        golden_hex("ar_block_iocr_tp")
    );
}

#[test]
fn golden_ar_block_device_access_tp() {
    // The literal connect() DeviceAccess-path AR block (no IOCRs).
    assert_eq!(
        hex::encode(ar_block_req(
            AR_TYPE_IOSAR,
            &ar_uuid(),
            SESSION_KEY,
            &CM_MAC,
            AR_PROPERTIES_DEVICE_ACCESS,
            b"tp",
        )),
        golden_hex("ar_block_device_access_tp")
    );
}

#[test]
fn golden_ar_block_iocr_controller() {
    assert_eq!(
        hex::encode(ar_block_req(
            AR_TYPE_IOCAR_SINGLE,
            &ar_uuid(),
            SESSION_KEY,
            &CM_MAC,
            AR_PROPERTIES_IOCAR,
            b"controller",
        )),
        golden_hex("ar_block_iocr_controller")
    );
}

#[test]
fn golden_iocr_block_input() {
    assert_eq!(
        hex::encode(iocr_block_req(1, 1, &setup())),
        golden_hex("iocr_block_input")
    );
}

#[test]
fn golden_iocr_block_output() {
    assert_eq!(
        hex::encode(iocr_block_req(2, 2, &setup())),
        golden_hex("iocr_block_output")
    );
}

#[test]
fn golden_alarm_cr_block() {
    assert_eq!(
        hex::encode(alarm_cr_block(1, 0, 0)),
        golden_hex("alarm_cr_block")
    );
}

#[test]
fn golden_expected_submodule_block() {
    assert_eq!(
        hex::encode(expected_submodule_block(&setup())),
        golden_hex("expected_submodule_block")
    );
}

#[test]
fn golden_connect_request() {
    assert_eq!(
        hex::encode(build_connect_request(
            &object_uuid(0x00, 0x07, 0x0A, 0xBC),
            &IFACE_UUID_DEVICE,
            &activity_uuid(),
            &ar_uuid(),
            SESSION_KEY,
            &CM_MAC,
            b"controller",
            &setup(),
            0,
        )),
        golden_hex("connect_request")
    );
}

#[test]
fn connect_body_block_order_and_lengths() {
    // Walk the NRD payload of the full request block by block (the wire
    // parser advances by 4 + block_length) and check connect()'s block order.
    let frame = build_connect_request(
        &object_uuid(0x00, 0x07, 0x0A, 0xBC),
        &IFACE_UUID_DEVICE,
        &activity_uuid(),
        &ar_uuid(),
        SESSION_KEY,
        &CM_MAC,
        b"controller",
        &setup(),
        0,
    );
    let body = &frame[80 + 20..]; // RPC header (80) + NRD header (20)
    let mut types = Vec::new();
    let mut off = 0;
    while off + 4 <= body.len() {
        let block_type = u16::from_be_bytes([body[off], body[off + 1]]);
        let block_length = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        types.push(block_type);
        off += 4 + block_length;
    }
    // Every block_length must land exactly on the next block boundary.
    assert_eq!(off, body.len());
    assert_eq!(types, [0x0101, 0x0102, 0x0102, 0x0103, 0x0104]);
}

#[test]
fn ar_block_length_tracks_station_name() {
    // block_length = 54 + name length (fmt_size - 2 generalized); total block
    // size is block_length + 4.
    for name in [&b"tp"[..], b"controller", b"x"] {
        let block = ar_block_req(
            AR_TYPE_IOCAR_SINGLE,
            &ar_uuid(),
            SESSION_KEY,
            &CM_MAC,
            AR_PROPERTIES_IOCAR,
            name,
        );
        let block_length = u16::from_be_bytes([block[2], block[3]]) as usize;
        assert_eq!(block_length, 54 + name.len());
        assert_eq!(block.len(), block_length + 4);
        // Station name length field sits right before the name bytes.
        let name_len = u16::from_be_bytes([block[56], block[57]]) as usize;
        assert_eq!(name_len, name.len());
        assert_eq!(&block[58..], name);
    }
}

#[test]
fn iocr_data_length_has_minimum_40() {
    // Input direction: 47 data + 1 IOPS + 4 IOCS = 52 > 40, so it is sent as
    // is; output direction: 1 + 1 + 4 = 6 -> padded up to the 40-byte minimum.
    // Both sides of the rule are covered by construction of the fixture.
    let s = setup();
    let input = iocr_block_req(1, 1, &s);
    let output = iocr_block_req(2, 2, &s);
    let data_length = |b: &[u8]| u16::from_be_bytes([b[16], b[17]]);
    assert_eq!(data_length(&input), 52);
    assert_eq!(data_length(&output), 40);
    // Frame IDs: the controller proposes 0xC000 + ref for the input CR, and
    // sends 0xFFFF for the output CR so the device assigns it and returns the
    // real one in the IOCRBlockRes. Proposing an output frame ID here is not
    // the controller's call, and a device may reject the Connect over it.
    assert_eq!(u16::from_be_bytes([input[18], input[19]]), 0xC001);
    assert_eq!(u16::from_be_bytes([output[18], output[19]]), 0xFFFF);
}

// ---------------------------------------------------------------------------
// Ports of profinet-py tests/test_protocol.py connect-block constant tests
// (TestPNAlarmCRBlockReq). The IOCRAPIObject layout test is not ported
// separately: the 6-byte slot/subslot/frame_offset packing is asserted
// byte-exactly by the golden IOCR tests above.
// ---------------------------------------------------------------------------

// TestPNAlarmCRBlockReq::test_block_type_constant + test_default_constants
#[test]
fn alarm_cr_block_constants() {
    use profinet_rs::connect::{
        DEFAULT_MAX_ALARM_DATA_LENGTH, DEFAULT_RTA_RETRIES, DEFAULT_RTA_TIMEOUT_FACTOR,
        DEFAULT_TAG_HEADER_HIGH, DEFAULT_TAG_HEADER_LOW,
    };
    // Block type 0x0103 sits in the built block's first two bytes.
    let block = alarm_cr_block(1, 0, 0);
    assert_eq!(u16::from_be_bytes([block[0], block[1]]), 0x0103);
    assert_eq!(DEFAULT_RTA_TIMEOUT_FACTOR, 1);
    assert_eq!(DEFAULT_RTA_RETRIES, 3);
    assert_eq!(DEFAULT_MAX_ALARM_DATA_LENGTH, 200);
    assert_eq!(DEFAULT_TAG_HEADER_HIGH, 0xC000);
    assert_eq!(DEFAULT_TAG_HEADER_LOW, 0xA000);
}
