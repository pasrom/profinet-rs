//! Golden byte-fidelity tests for the I&M / identification-record module
//! against vectors generated from the Python reference
//! (tools/gen_im_golden.py -> tests/golden/im.json): read-request bytes must
//! match byte-for-byte, and the response parsers must yield the same fields
//! profinet-py's parsers extract. Plus edge cases for the parsing tolerance.

use std::collections::BTreeMap;

use profinet_rs::gsdml::DeviceSlot;
use profinet_rs::im::{
    align4, block_type_name, decode_bytes, parse_block_header, parse_im0, parse_im1, parse_im2,
    parse_im3, parse_inm0_filter, parse_pd_real_data, parse_real_identification_data, InM0,
    InM0FilterData, InM1, InM2, InM3, SlotInfo, IM0, IM0_FILTER_DATA, IM1, IM15, IM2, IM3,
    PD_REAL_DATA, REAL_ID_API,
};
use profinet_rs::rpc::{object_uuid, read_record_request, IFACE_UUID_DEVICE};

fn golden() -> serde_json::Value {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/im.json"))
        .expect("read golden file");
    serde_json::from_str(&raw).expect("parse golden file")
}

fn entry_bytes(entry: &serde_json::Value) -> Vec<u8> {
    hex::decode(entry["hex"].as_str().expect("hex field")).expect("valid hex")
}

fn u64_of(entry: &serde_json::Value, field: &str) -> u64 {
    entry[field]
        .as_u64()
        .unwrap_or_else(|| panic!("field {field} missing"))
}

fn str_of<'a>(entry: &'a serde_json::Value, field: &str) -> &'a str {
    entry[field]
        .as_str()
        .unwrap_or_else(|| panic!("field {field} missing"))
}

// ---------------------------------------------------------------------------
// Record index constants
// ---------------------------------------------------------------------------

#[test]
fn record_index_constants_match_indices_py() {
    assert_eq!(IM0, 0xAFF0);
    assert_eq!(IM1, 0xAFF1);
    assert_eq!(IM2, 0xAFF2);
    assert_eq!(IM3, 0xAFF3);
    assert_eq!(IM15, 0xAFFF);
    assert_eq!(IM0_FILTER_DATA, 0xF840);
    assert_eq!(REAL_ID_API, 0xF000);
    assert_eq!(PD_REAL_DATA, 0xF841);
    assert_eq!(InM0::IDX, 0xAFF0);
    assert_eq!(InM1::IDX, 0xAFF1);
    assert_eq!(InM2::IDX, 0xAFF2);
    assert_eq!(InM3::IDX, 0xAFF3);
}

// ---------------------------------------------------------------------------
// READ request byte-fidelity
// ---------------------------------------------------------------------------

#[test]
fn golden_read_requests_byte_exact() {
    let golden = golden();
    let ar: [u8; 16] = std::array::from_fn(|i| i as u8);
    let act: [u8; 16] = std::array::from_fn(|i| 16 + i as u8);
    let obj = object_uuid(0x00, 0x07, 0x0a, 0xbc);

    for name in [
        "read_request_im0",
        "read_request_im1",
        "read_request_im2",
        "read_request_im3",
        "read_request_pd_real_data",
        "read_request_real_identification_data",
        "read_request_inm0_filter",
    ] {
        let entry = &golden[name];
        let req = read_record_request(
            &obj,
            &IFACE_UUID_DEVICE,
            &act,
            &ar,
            0,
            0,
            u64_of(entry, "slot") as u16,
            u64_of(entry, "subslot") as u16,
            u64_of(entry, "idx") as u16,
            4096,
        );
        assert_eq!(hex::encode(req), str_of(entry, "hex"), "{name}");
    }
}

// ---------------------------------------------------------------------------
// I&M0..3 response parsing against golden
// ---------------------------------------------------------------------------

#[test]
fn golden_im0_response_fields() {
    let golden = golden();
    let entry = &golden["im0_response"];
    let im0 = parse_im0(&entry_bytes(entry)).unwrap();

    assert_eq!(
        u64::from(im0.block_header.block_type),
        u64_of(entry, "block_type")
    );
    assert_eq!(
        u64::from(im0.block_header.block_length),
        u64_of(entry, "block_length")
    );
    assert_eq!(im0.block_header.type_name(), "I&M0");
    assert_eq!(u64::from(im0.vendor_id()), u64_of(entry, "vendor_id"));
    assert_eq!(
        u64::from(im0.vendor_id_high),
        u64_of(entry, "vendor_id_high")
    );
    assert_eq!(u64::from(im0.vendor_id_low), u64_of(entry, "vendor_id_low"));
    assert_eq!(hex::encode(im0.order_id), str_of(entry, "order_id_hex"));
    assert_eq!(im0.order_id_str(), str_of(entry, "order_id_str"));
    assert_eq!(
        hex::encode(im0.im_serial_number),
        str_of(entry, "serial_hex")
    );
    assert_eq!(im0.serial_number_str(), str_of(entry, "serial_str"));
    assert_eq!(
        u64::from(im0.im_hardware_revision),
        u64_of(entry, "hardware_revision")
    );
    assert_eq!(
        u64::from(im0.sw_revision_prefix),
        u64_of(entry, "sw_revision_prefix")
    );
    assert_eq!(
        u64::from(im0.im_sw_revision_functional_enhancement),
        u64_of(entry, "sw_enhancement")
    );
    assert_eq!(
        u64::from(im0.im_sw_revision_bug_fix),
        u64_of(entry, "sw_bug_fix")
    );
    assert_eq!(
        u64::from(im0.im_sw_revision_internal_change),
        u64_of(entry, "sw_internal_change")
    );
    assert_eq!(
        u64::from(im0.im_revision_counter),
        u64_of(entry, "revision_counter")
    );
    assert_eq!(u64::from(im0.im_profile_id), u64_of(entry, "profile_id"));
    assert_eq!(
        u64::from(im0.im_profile_specific_type),
        u64_of(entry, "profile_specific_type")
    );
    assert_eq!(u64::from(im0.im_version), u64_of(entry, "im_version"));
    assert_eq!(u64::from(im0.im_supported), u64_of(entry, "im_supported"));
    assert_eq!(im0.software_revision(), "V4.2.1");
}

#[test]
fn golden_im1_response_fields() {
    let golden = golden();
    let entry = &golden["im1_response"];
    let im1 = parse_im1(&entry_bytes(entry)).unwrap();
    assert_eq!(im1.block_header.block_type, 0x0021);
    assert_eq!(im1.tag_function_str(), str_of(entry, "tag_function_str"));
    assert_eq!(im1.tag_location_str(), str_of(entry, "tag_location_str"));
}

#[test]
fn golden_im2_response_fields() {
    let golden = golden();
    let entry = &golden["im2_response"];
    let im2 = parse_im2(&entry_bytes(entry)).unwrap();
    assert_eq!(im2.block_header.block_type, 0x0022);
    assert_eq!(im2.date_str(), str_of(entry, "date_str"));
}

#[test]
fn golden_im3_response_fields() {
    let golden = golden();
    let entry = &golden["im3_response"];
    let im3 = parse_im3(&entry_bytes(entry)).unwrap();
    assert_eq!(im3.block_header.block_type, 0x0023);
    assert_eq!(im3.descriptor_str(), str_of(entry, "descriptor_str"));
}

// ---------------------------------------------------------------------------
// PDRealData parsing against golden
// ---------------------------------------------------------------------------

#[test]
fn golden_pd_real_data_response() {
    let golden = golden();
    let entry = &golden["pd_real_data_response"];
    let pd = parse_pd_real_data(&entry_bytes(entry));

    // Slots with their nested block-type names.
    let exp_slots = entry["slots"].as_array().unwrap();
    assert_eq!(pd.slots.len(), exp_slots.len());
    for (slot, exp) in pd.slots.iter().zip(exp_slots) {
        assert_eq!(u64::from(slot.api), u64_of(exp, "api"));
        assert_eq!(u64::from(slot.slot), u64_of(exp, "slot"));
        assert_eq!(u64::from(slot.subslot), u64_of(exp, "subslot"));
        let exp_blocks: Vec<&str> = exp["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_str().unwrap())
            .collect();
        assert_eq!(slot.blocks, exp_blocks);
    }

    // Interface.
    let iface = pd.interface.as_ref().expect("interface parsed");
    let exp_if = &entry["interface"];
    assert_eq!(iface.chassis_id, str_of(exp_if, "chassis_id"));
    assert_eq!(iface.mac_str(), str_of(exp_if, "mac"));
    assert_eq!(iface.ip_str(), str_of(exp_if, "ip"));
    assert_eq!(iface.subnet_str(), str_of(exp_if, "subnet"));
    assert_eq!(iface.gateway_str(), str_of(exp_if, "gateway"));

    // Ports (incl. peers).
    let exp_ports = entry["ports"].as_array().unwrap();
    assert_eq!(pd.ports.len(), exp_ports.len());
    for (port, exp) in pd.ports.iter().zip(exp_ports) {
        assert_eq!(u64::from(port.slot), u64_of(exp, "slot"));
        assert_eq!(u64::from(port.subslot), u64_of(exp, "subslot"));
        assert_eq!(port.port_id, str_of(exp, "port_id"));
        assert_eq!(u64::from(port.mau_type), u64_of(exp, "mau_type"));
        assert_eq!(
            u64::from(port.link_state_port),
            u64_of(exp, "link_state_port")
        );
        assert_eq!(
            u64::from(port.link_state_link),
            u64_of(exp, "link_state_link")
        );
        assert_eq!(u64::from(port.media_type), u64_of(exp, "media_type"));
        assert_eq!(
            u64::from(port.domain_boundary),
            u64_of(exp, "domain_boundary")
        );
        assert_eq!(
            u64::from(port.multicast_boundary),
            u64_of(exp, "multicast_boundary")
        );
        assert_eq!(port.link_state(), "Up");
        let exp_peers = exp["peers"].as_array().unwrap();
        assert_eq!(port.peers.len(), exp_peers.len());
        for (peer, exp_peer) in port.peers.iter().zip(exp_peers) {
            assert_eq!(peer.port_id, str_of(exp_peer, "port_id"));
            assert_eq!(peer.chassis_id, str_of(exp_peer, "chassis_id"));
            assert_eq!(peer.mac_str(), str_of(exp_peer, "mac"));
        }
    }

    // Raw per-MultipleBlockHeader byte ranges.
    let exp_raw = entry["raw_blocks"].as_array().unwrap();
    assert_eq!(pd.raw_blocks.len(), exp_raw.len());
    for ((api, slot, subslot, raw), exp) in pd.raw_blocks.iter().zip(exp_raw) {
        assert_eq!(u64::from(*api), u64_of(exp, "api"));
        assert_eq!(u64::from(*slot), u64_of(exp, "slot"));
        assert_eq!(u64::from(*subslot), u64_of(exp, "subslot"));
        assert_eq!(hex::encode(raw), str_of(exp, "hex"));
    }
}

// ---------------------------------------------------------------------------
// RealIdentificationData parsing against golden
// ---------------------------------------------------------------------------

fn assert_real_id_matches(entry: &serde_json::Value) {
    let parsed = parse_real_identification_data(&entry_bytes(entry));
    let exp_version = entry["version"].as_array().unwrap();
    assert_eq!(
        (u64::from(parsed.version.0), u64::from(parsed.version.1)),
        (
            exp_version[0].as_u64().unwrap(),
            exp_version[1].as_u64().unwrap()
        )
    );
    let exp_slots = entry["slots"].as_array().unwrap();
    assert_eq!(parsed.slots.len(), exp_slots.len());
    for (slot, exp) in parsed.slots.iter().zip(exp_slots) {
        assert_eq!(u64::from(slot.api), u64_of(exp, "api"));
        assert_eq!(u64::from(slot.slot), u64_of(exp, "slot"));
        assert_eq!(u64::from(slot.subslot), u64_of(exp, "subslot"));
        assert_eq!(u64::from(slot.module_ident), u64_of(exp, "module_ident"));
        assert_eq!(
            u64::from(slot.submodule_ident),
            u64_of(exp, "submodule_ident")
        );
        assert!(slot.blocks.is_empty());
    }
}

#[test]
fn golden_real_identification_data_v11() {
    assert_real_id_matches(&golden()["real_identification_data_v11"]);
}

#[test]
fn golden_real_identification_data_v10() {
    assert_real_id_matches(&golden()["real_identification_data_v10"]);
}

#[test]
fn golden_real_identification_data_truncated_keeps_partial_slots() {
    assert_real_id_matches(&golden()["real_identification_data_truncated"]);
}

// ---------------------------------------------------------------------------
// I&M0FilterData parsing against golden
// ---------------------------------------------------------------------------

#[test]
fn golden_inm0_filter_response() {
    let golden = golden();
    let entry = &golden["inm0_filter_response"];
    let parsed = parse_inm0_filter(&entry_bytes(entry)).unwrap();

    let mut expected = InM0FilterData::new();
    for (api, mods) in entry["expected"].as_object().unwrap() {
        let api: u32 = api.parse().unwrap();
        let mut mod_map = BTreeMap::new();
        for (slot, info) in mods.as_object().unwrap() {
            let slot: u16 = slot.parse().unwrap();
            let module_ident = u64_of(info, "module_ident") as u32;
            let mut subslots = BTreeMap::new();
            for (subslot, submodule) in info["subslots"].as_object().unwrap() {
                subslots.insert(
                    subslot.parse::<u16>().unwrap(),
                    submodule.as_u64().unwrap() as u32,
                );
            }
            mod_map.insert(slot, (module_ident, subslots));
        }
        expected.insert(api, mod_map);
    }

    assert_eq!(parsed, expected);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_im_records_reject_short_payloads() {
    let golden = golden();
    let im0_bytes = entry_bytes(&golden["im0_response"]);
    let err = parse_im0(&im0_bytes[..59]).unwrap_err();
    assert!(err.contains("need 60 bytes"), "{err}");
    assert!(parse_im1(&[0u8; 59]).is_err());
    assert!(parse_im2(&[0u8; 21]).is_err());
    assert!(parse_im3(&[0u8; 59]).is_err());
}

#[test]
fn parse_im0_ignores_trailing_bytes_like_reference() {
    // The reference's fixed-size struct parse ignores anything past the
    // 60-byte record; devices may pad the record payload.
    let golden = golden();
    let exact = entry_bytes(&golden["im0_response"]);
    let mut padded = exact.clone();
    padded.extend_from_slice(&[0xAB; 8]);
    assert_eq!(parse_im0(&padded).unwrap(), parse_im0(&exact).unwrap());
}

#[test]
fn decode_bytes_matches_python_semantics() {
    // rstrip(b"\x00") strips only trailing NULs; interior ones survive.
    assert_eq!(decode_bytes(b"AB\x00C\x00\x00"), "AB\u{0}C");
    assert_eq!(decode_bytes(b"\x00\x00"), "");
    assert_eq!(decode_bytes(b""), "");
    // errors="replace" -> U+FFFD for invalid UTF-8.
    assert_eq!(decode_bytes(&[0x41, 0xFF, 0x42]), "A\u{FFFD}B");
}

#[test]
fn align4_matches_python() {
    assert_eq!(align4(0), 0);
    assert_eq!(align4(1), 4);
    assert_eq!(align4(4), 4);
    assert_eq!(align4(7), 8);
}

#[test]
fn parse_block_header_rejects_short_data() {
    let err = parse_block_header(&[0u8; 5], 0).unwrap_err();
    assert!(err.contains("requires 6 bytes"), "{err}");
    assert!(parse_block_header(&[0u8; 10], 5).is_err());
}

#[test]
fn parse_pd_real_data_tolerates_empty_and_foreign_blocks() {
    // Empty input parses to the empty result, like the reference.
    let empty = parse_pd_real_data(&[]);
    assert!(empty.slots.is_empty() && empty.interface.is_none() && empty.ports.is_empty());

    // A non-MultipleBlockHeader block is skipped entirely.
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x0251u16.to_be_bytes()); // PDPortStatistic
    buf.extend_from_slice(&4u16.to_be_bytes());
    buf.extend_from_slice(&[1, 0, 0xAA, 0xBB]);
    let parsed = parse_pd_real_data(&buf);
    assert!(parsed.slots.is_empty() && parsed.raw_blocks.is_empty());
}

#[test]
fn parse_real_identification_data_handles_empty_and_header_only() {
    let empty = parse_real_identification_data(&[]);
    assert_eq!(empty.version, (1, 0));
    assert!(empty.slots.is_empty());

    // Header only, no count following: returns with just the version.
    let golden = golden();
    let v11 = entry_bytes(&golden["real_identification_data_v11"]);
    let header_only = parse_real_identification_data(&v11[..6]);
    assert_eq!(header_only.version, (1, 1));
    assert!(header_only.slots.is_empty());
}

#[test]
fn parse_inm0_filter_rejects_truncation() {
    let golden = golden();
    let full = entry_bytes(&golden["inm0_filter_response"]);
    assert!(parse_inm0_filter(&full[..4]).is_err());
    assert!(parse_inm0_filter(&full[..full.len() - 1]).is_err());
}

#[test]
fn slot_info_converts_to_gsdml_device_slot() {
    let slot = SlotInfo {
        slot: 1,
        subslot: 2,
        api: 0,
        module_ident: 0x100,
        submodule_ident: 0x10001,
        blocks: vec!["I&M0".to_string()],
    };
    assert_eq!(
        slot.to_device_slot(),
        DeviceSlot {
            slot: 1,
            subslot: 2,
            module_ident: 0x100,
            submodule_ident: 0x10001,
        }
    );
}

#[test]
fn block_type_name_known_and_unknown() {
    assert_eq!(block_type_name(0x0020), "I&M0");
    assert_eq!(block_type_name(0x0400), "MultipleBlockHeader");
    assert_eq!(block_type_name(0xF841), "PDRealData");
    assert_eq!(block_type_name(0x1234), "Unknown(0x1234)");
}

// ---------------------------------------------------------------------------
// Ports of profinet-py tests/test_protocol.py (PNInM* structures) and
// tests/test_rpc.py (TestIMReading payload builders), against the pure
// parsers here instead of the Python mock-socket read_im* round trip. The
// I&M5 test is not ported (no InM5 struct in Rust).
// ---------------------------------------------------------------------------

mod py_parity {
    use profinet_rs::im::{parse_im0, parse_im1, parse_im2, parse_im3};

    // TestPNInMStructures::test_pnin_m0_idx .. test_pnin_m15_idx
    #[test]
    fn im_record_index_constants() {
        use profinet_rs::im;
        assert_eq!(im::IM0, 0xAFF0);
        assert_eq!(im::IM1, 0xAFF1);
        assert_eq!(im::IM2, 0xAFF2);
        assert_eq!(im::IM3, 0xAFF3);
        assert_eq!(im::IM4, 0xAFF4);
        assert_eq!(im::IM5, 0xAFF5);
        assert_eq!(im::IM6, 0xAFF6);
        assert_eq!(im::IM15, 0xAFFF);
    }

    fn header(block_type: u16, block_length: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(6);
        out.extend_from_slice(&block_type.to_be_bytes());
        out.extend_from_slice(&block_length.to_be_bytes());
        out.extend_from_slice(&[0x01, 0x00]);
        out
    }

    // TestPNInMStructures::test_parse_pnin_m0
    #[test]
    fn parse_im0_structure() {
        let mut data = vec![0u8; 64];
        data[..6].copy_from_slice(&header(0x0020, 58));
        data[6] = 0x00; // vendor_id_high
        data[7] = 0x2A; // vendor_id_low
        let order_id = b"6ES7 214-1AG40-0XB0";
        data[8..8 + order_id.len()].copy_from_slice(order_id);
        let serial = b"S V-A6B205082016";
        data[28..28 + serial.len()].copy_from_slice(serial);

        let im0 = parse_im0(&data).unwrap();
        assert_eq!(im0.vendor_id_high, 0x00);
        assert_eq!(im0.vendor_id_low, 0x2A);
        assert_eq!(im0.order_id_str(), "6ES7 214-1AG40-0XB0");
        assert_eq!(im0.serial_number_str(), "S V-A6B205082016");
    }

    // TestPNInMStructures::test_parse_pnin_m1
    #[test]
    fn parse_im1_structure() {
        let mut data = vec![0u8; 60];
        data[..6].copy_from_slice(&header(0x0021, 54));
        let tag_func = b"Motor Control Unit";
        data[6..6 + tag_func.len()].copy_from_slice(tag_func);

        let im1 = parse_im1(&data).unwrap();
        assert!(im1.tag_function_str().contains("Motor Control Unit"));
    }

    // TestPNInMStructures::test_parse_pnin_m2
    #[test]
    fn parse_im2_structure() {
        let mut data = vec![0u8; 22];
        data[..6].copy_from_slice(&header(0x0022, 16));
        data[6..22].copy_from_slice(b"2024-01-15 10:30");

        let im2 = parse_im2(&data).unwrap();
        assert!(im2.date_str().contains("2024-01-15"));
    }

    // TestPNInMStructures::test_parse_pnin_m3
    #[test]
    fn parse_im3_structure() {
        let mut data = vec![0u8; 60];
        data[..6].copy_from_slice(&header(0x0023, 54));
        let desc = b"Test descriptor";
        data[6..6 + desc.len()].copy_from_slice(desc);

        let im3 = parse_im3(&data).unwrap();
        assert!(im3.descriptor_str().contains("Test descriptor"));
    }

    // TestIMReading::test_read_im0 (the _create_im0_payload vector parsed
    // directly, without the mocked RPCCon.read)
    #[test]
    fn rpc_im0_payload_parses() {
        let mut data = header(0x0020, 58);
        data.extend_from_slice(&0x002Au16.to_be_bytes()); // vendor ID
        let mut order_id = b"ORDER-123456".to_vec();
        order_id.resize(20, 0);
        data.extend_from_slice(&order_id);
        let mut serial = b"SERIAL-001".to_vec();
        serial.resize(16, 0);
        data.extend_from_slice(&serial);
        data.extend_from_slice(&1u16.to_be_bytes()); // hardware revision
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x00]); // sw revision V01.02.03
        data.extend_from_slice(&1u16.to_be_bytes()); // revision counter
        data.extend_from_slice(&0xF600u16.to_be_bytes()); // profile ID
        data.extend_from_slice(&0x0001u16.to_be_bytes()); // profile type
        data.extend_from_slice(&[0x01, 0x00]); // I&M version 1.0
        data.extend_from_slice(&0x000Eu16.to_be_bytes()); // supports IM0-3

        let im0 = parse_im0(&data).unwrap();
        assert_eq!(im0.vendor_id_high, 0x00);
        assert_eq!(im0.vendor_id_low, 0x2A);
        assert_eq!(im0.vendor_id(), 0x002A);
        assert_eq!(im0.order_id_str(), "ORDER-123456");
        assert_eq!(im0.serial_number_str(), "SERIAL-001");
        assert_eq!(im0.im_supported, 0x000E);
    }

    // TestIMReading::test_read_im1
    #[test]
    fn rpc_im1_payload_parses() {
        let mut data = header(0x0021, 58);
        let mut tag_function = b"TAG-FUNCTION".to_vec();
        tag_function.resize(32, 0);
        data.extend_from_slice(&tag_function);
        let mut tag_location = b"TAG-LOCATION".to_vec();
        tag_location.resize(22, 0);
        data.extend_from_slice(&tag_location);

        let im1 = parse_im1(&data).unwrap();
        assert!(im1.tag_function_str().contains("TAG-FUNCTION"));
        assert_eq!(im1.tag_location_str(), "TAG-LOCATION");
    }

    // TestIMReading::test_read_im2
    #[test]
    fn rpc_im2_payload_parses() {
        let mut data = header(0x0022, 22);
        data.extend_from_slice(b"2024-01-15 10:30");
        let im2 = parse_im2(&data).unwrap();
        assert!(im2.date_str().contains("2024-01-15"));
    }

    // TestIMReading::test_read_im3
    #[test]
    fn rpc_im3_payload_parses() {
        let mut data = header(0x0023, 60);
        let mut descriptor = b"Device Descriptor Text".to_vec();
        descriptor.resize(54, 0);
        data.extend_from_slice(&descriptor);
        let im3 = parse_im3(&data).unwrap();
        assert!(im3.descriptor_str().contains("Device Descriptor"));
    }
}
