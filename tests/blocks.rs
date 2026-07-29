//! Ports of profinet-py tests/test_blocks.py (block parsers/builders) against
//! the Rust equivalents: `im` (BlockHeader, PDRealData, RealIdentificationData
//! parsers), `blocks` (IODWriteMultiple building + response parsing),
//! `connect` (ExpectedSubmoduleBlockReq) and `indices` (block type constants,
//! module/submodule state tables). Python hardcoded byte vectors are reused as
//! reference inputs. Python-only mechanics (repr/str, dataclass defaults,
//! builder method chaining) and features without a Rust equivalent
//! (parse_port_statistics, parse_module_diff_block) are not ported.

use profinet_rs::blocks::{
    iod_write_multiple_payload, parse_write_multiple_response, MultiWrite, WriteMultipleResult,
    IOD_WRITE_MULTIPLE_INDEX, IOD_WRITE_REQUEST_HEADER,
};
use profinet_rs::connect::{expected_submodule_block, IocrSetup};
use profinet_rs::gsdml::IoSlot;
use profinet_rs::im::{
    align4, parse_block_header, parse_multiple_block_header, parse_pd_interface_data_real,
    parse_pd_port_data_real, parse_pd_real_data, parse_real_identification_data, BlockHeader,
    InterfaceInfo, PeerInfo, PortInfo, SlotInfo,
};
use profinet_rs::indices;

fn be16(data: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([data[off], data[off + 1]])
}

fn be32(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn pad4(data: &mut Vec<u8>) {
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
}

// ---------------------------------------------------------------------------
// TestBlockHeader
// ---------------------------------------------------------------------------

// test_parse_block_header_valid
#[test]
fn parse_block_header_valid() {
    let mut data = Vec::new();
    data.extend_from_slice(&0x0400u16.to_be_bytes());
    data.extend_from_slice(&0x0090u16.to_be_bytes());
    data.extend_from_slice(&[0x01, 0x00]);

    let (header, offset) = parse_block_header(&data, 0).unwrap();
    assert_eq!(header.block_type, 0x0400);
    assert_eq!(header.block_length, 0x0090);
    assert_eq!(header.version_high, 1);
    assert_eq!(header.version_low, 0);
    assert_eq!(header.body_length(), 0x008E); // 0x0090 - 2
    assert_eq!(offset, 6);
}

// test_parse_block_header_short_data
#[test]
fn parse_block_header_short_data() {
    let err = parse_block_header(&[0x04, 0x00, 0x00], 0).unwrap_err();
    assert!(err.contains("requires 6 bytes"), "{err}");
}

// test_parse_block_header_with_offset
#[test]
fn parse_block_header_with_offset() {
    let mut data = vec![0xFF; 4]; // 4 bytes of padding
    data.extend_from_slice(&0x0240u16.to_be_bytes());
    data.extend_from_slice(&0x0024u16.to_be_bytes());
    data.extend_from_slice(&[0x01, 0x00]);

    let (header, offset) = parse_block_header(&data, 4).unwrap();
    assert_eq!(header.block_type, 0x0240);
    assert_eq!(header.block_length, 0x0024);
    assert_eq!(offset, 10); // 4 + 6
}

// test_block_header_type_name
#[test]
fn block_header_type_name() {
    let mut data = Vec::new();
    data.extend_from_slice(&indices::BLOCK_MULTIPLE_HEADER.to_be_bytes());
    data.extend_from_slice(&[0x00, 0x10, 1, 0]);
    let (header, _) = parse_block_header(&data, 0).unwrap();
    assert_eq!(header.type_name(), "MultipleBlockHeader");

    let mut data = Vec::new();
    data.extend_from_slice(&0x9999u16.to_be_bytes());
    data.extend_from_slice(&[0x00, 0x10, 1, 0]);
    let (header, _) = parse_block_header(&data, 0).unwrap();
    assert!(header.type_name().contains("Unknown"));
}

// TestBlockHeaderEdgeCases: test_body_length_with_zero_block_length,
// test_body_length_with_length_one, test_body_length_exactly_two,
// test_body_length_three
#[test]
fn block_header_body_length_edge_cases() {
    let header = |block_length| BlockHeader {
        block_type: 0x0400,
        block_length,
        version_high: 1,
        version_low: 0,
    };
    assert_eq!(header(0).body_length(), 0);
    assert_eq!(header(1).body_length(), 0);
    assert_eq!(header(2).body_length(), 0);
    assert_eq!(header(3).body_length(), 1);
}

// ---------------------------------------------------------------------------
// TestMultipleBlockHeader
// ---------------------------------------------------------------------------

// test_parse_multiple_block_header
#[test]
fn multiple_block_header() {
    let mut data = vec![0u8; 2]; // padding
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&0x8000u16.to_be_bytes());

    let (api, slot, subslot, body_offset) = parse_multiple_block_header(&data, 0).unwrap();
    assert_eq!(api, 0);
    assert_eq!(slot, 0);
    assert_eq!(subslot, 0x8000);
    assert_eq!(body_offset, 10); // 2 (padding) + 8 (api+slot+subslot)
}

// test_parse_multiple_block_header_nonzero_api
#[test]
fn multiple_block_header_nonzero_api() {
    let mut data = vec![0u8; 2];
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&2u16.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes());

    let (api, slot, subslot, _) = parse_multiple_block_header(&data, 0).unwrap();
    assert_eq!(api, 1);
    assert_eq!(slot, 2);
    assert_eq!(subslot, 1);
}

// test_parse_multiple_block_header_truncated
#[test]
fn multiple_block_header_truncated() {
    assert!(parse_multiple_block_header(&[0u8; 4], 0).is_err());
}

// ---------------------------------------------------------------------------
// TestPDInterfaceDataReal
// ---------------------------------------------------------------------------

// test_parse_interface_data
#[test]
fn interface_data_real_device_format() {
    // Alignment is relative to block start (6-byte header + body): for a
    // 10-byte chassis ID, header(6) + len(1) + chassis(10) = 17, aligned to
    // 20, so MAC starts at body offset 14 (3 bytes padding).
    let data = hex::decode(concat!(
        "0A",                   // chassis_len = 10
        "41414141414141414141", // "AAAAAAAAAA"
        "000000",               // 3 bytes padding (block offset 17 -> 20)
        "001122334455",         // MAC
        "0000",                 // 2 bytes padding (block offset 26 -> 28)
        "C0A80164",             // IP: 192.168.1.100
        "FFFFFF00",             // Subnet: 255.255.255.0
        "C0A80101",             // Gateway: 192.168.1.1
    ))
    .unwrap();

    let info = parse_pd_interface_data_real(&data, 0).unwrap();
    assert_eq!(info.chassis_id, "AAAAAAAAAA");
    assert_eq!(info.mac_address, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(info.ip_str(), "192.168.1.100");
    assert_eq!(info.subnet_str(), "255.255.255.0");
    assert_eq!(info.gateway_str(), "192.168.1.1");
}

// test_interface_info_mac_str
#[test]
fn interface_info_mac_str() {
    let info = InterfaceInfo {
        chassis_id: "test".to_string(),
        mac_address: [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45],
        ip_address: [0; 4],
        subnet_mask: [0; 4],
        gateway: [0; 4],
    };
    assert_eq!(info.mac_str(), "ab:cd:ef:01:23:45");
}

// ---------------------------------------------------------------------------
// TestPDPortDataReal
// ---------------------------------------------------------------------------

// test_parse_port_data_minimal
#[test]
fn port_data_minimal() {
    let port_id = b"port-001";
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&0x8001u16.to_be_bytes());
    data.push(port_id.len() as u8);
    data.extend_from_slice(port_id);
    data.push(0); // number of peers

    let port = parse_pd_port_data_real(&data, 0, 0, 0x8001);
    assert_eq!(port.slot, 0);
    assert_eq!(port.subslot, 0x8001);
    assert_eq!(port.port_id, "port-001");
    assert!(port.peers.is_empty());
}

// test_parse_port_data_with_peer
#[test]
fn port_data_with_peer() {
    let port_id = b"port-001";
    let peer_port = b"port-002";
    let peer_chassis = b"peer-dev";
    let peer_mac = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x66];

    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&0x8001u16.to_be_bytes());
    data.push(port_id.len() as u8);
    data.extend_from_slice(port_id);
    data.push(1); // number of peers
    pad4(&mut data);
    data.push(peer_port.len() as u8);
    data.extend_from_slice(peer_port);
    data.push(peer_chassis.len() as u8);
    data.extend_from_slice(peer_chassis);
    pad4(&mut data);
    data.extend_from_slice(&peer_mac);
    pad4(&mut data);
    data.extend_from_slice(&16u16.to_be_bytes()); // MAU type: 100BaseTX
    pad4(&mut data);

    let port = parse_pd_port_data_real(&data, 0, 0, 0);
    assert_eq!(port.port_id, "port-001");
    assert_eq!(port.peers.len(), 1);
    assert_eq!(port.peers[0].port_id, "port-002");
    assert_eq!(port.peers[0].chassis_id, "peer-dev");
}

// ---------------------------------------------------------------------------
// TestSlotInfo (repr test skipped: Python __repr__ mechanics)
// ---------------------------------------------------------------------------

// test_slot_info_with_idents
#[test]
fn slot_info_with_idents() {
    let slot = SlotInfo {
        api: 0,
        slot: 0,
        subslot: 1,
        module_ident: 0x12345678,
        submodule_ident: 0x00000001,
        blocks: Vec::new(),
    };
    assert_eq!(slot.module_ident, 0x12345678);
    assert_eq!(slot.submodule_ident, 0x00000001);
}

// ---------------------------------------------------------------------------
// TestPDRealData + TestPDRealDataEdgeCases
// ---------------------------------------------------------------------------

// test_parse_empty_data
#[test]
fn pd_real_data_empty() {
    let result = parse_pd_real_data(&[]);
    assert!(result.slots.is_empty());
    assert!(result.interface.is_none());
    assert!(result.ports.is_empty());
}

// test_parse_single_multiple_block
#[test]
fn pd_real_data_single_multiple_block() {
    // MultipleBlockHeader (0x0400) containing PDInterfaceDataReal (0x0240).
    let mut outer = Vec::new();
    outer.extend_from_slice(&0x0400u16.to_be_bytes());
    outer.extend_from_slice(&0u16.to_be_bytes()); // length patched below
    outer.extend_from_slice(&[1, 0]);
    outer.extend_from_slice(&[0, 0]); // padding
    outer.extend_from_slice(&0u32.to_be_bytes()); // API
    outer.extend_from_slice(&0u16.to_be_bytes()); // slot
    outer.extend_from_slice(&0x8000u16.to_be_bytes()); // subslot

    let chassis = b"test";
    let mut inner = Vec::new();
    inner.push(chassis.len() as u8);
    inner.extend_from_slice(chassis);
    pad4(&mut inner);
    inner.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // MAC
    pad4(&mut inner);
    inner.extend_from_slice(&[0xC0, 0xA8, 0x01, 0x01]); // IP
    inner.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x00]); // Subnet
    inner.extend_from_slice(&[0xC0, 0xA8, 0x01, 0x01]); // GW

    outer.extend_from_slice(&0x0240u16.to_be_bytes());
    outer.extend_from_slice(&((inner.len() + 2) as u16).to_be_bytes());
    outer.extend_from_slice(&[1, 0]);
    outer.extend_from_slice(&inner);

    let outer_length = (outer.len() - 4) as u16;
    outer[2..4].copy_from_slice(&outer_length.to_be_bytes());

    let result = parse_pd_real_data(&outer);
    assert_eq!(result.slots.len(), 1);
    assert_eq!(result.slots[0].slot, 0);
    assert_eq!(result.slots[0].subslot, 0x8000);
    let interface = result.interface.expect("interface parsed");
    assert_eq!(interface.chassis_id, "test");
}

// test_parse_truncated_block
#[test]
fn pd_real_data_truncated_block() {
    // Header claims 258 body bytes but only the header is provided; must not
    // panic, just return what it can.
    let mut data = Vec::new();
    data.extend_from_slice(&0x0400u16.to_be_bytes());
    data.extend_from_slice(&0x0100u16.to_be_bytes());
    data.extend_from_slice(&[1, 0]);
    let result = parse_pd_real_data(&data);
    assert!(result.slots.is_empty());
}

// test_parse_non_multiple_block_skipped
#[test]
fn pd_real_data_non_multiple_block_skipped() {
    let inner = [0u8; 10];
    let mut data = Vec::new();
    data.extend_from_slice(&0x0240u16.to_be_bytes());
    data.extend_from_slice(&((inner.len() + 2) as u16).to_be_bytes());
    data.extend_from_slice(&[1, 0]);
    data.extend_from_slice(&inner);
    let result = parse_pd_real_data(&data);
    assert!(result.slots.is_empty());
}

// ---------------------------------------------------------------------------
// TestRealIdentificationData
// ---------------------------------------------------------------------------

// test_parse_version_1_0
#[test]
fn real_identification_data_v10() {
    let mut data = Vec::new();
    data.extend_from_slice(&0x0013u16.to_be_bytes());
    data.extend_from_slice(&0u16.to_be_bytes()); // length patched below
    data.extend_from_slice(&[1, 0]);
    data.extend_from_slice(&2u16.to_be_bytes()); // NumberOfSlots
                                                 // Slot 0: 2 subslots.
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&0x00010001u32.to_be_bytes());
    data.extend_from_slice(&2u16.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&0x00000001u32.to_be_bytes());
    data.extend_from_slice(&0x8000u16.to_be_bytes());
    data.extend_from_slice(&0x00000002u32.to_be_bytes());
    // Slot 1: 1 subslot.
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&0x00020002u32.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&0x00000001u32.to_be_bytes());
    let length = (data.len() - 4) as u16;
    data[2..4].copy_from_slice(&length.to_be_bytes());

    let result = parse_real_identification_data(&data);
    assert_eq!(result.version, (1, 0));
    assert_eq!(result.slots.len(), 3); // 2 + 1 subslots total
    assert_eq!((result.slots[0].slot, result.slots[0].subslot), (0, 1));
    assert_eq!((result.slots[1].slot, result.slots[1].subslot), (0, 0x8000));
    assert_eq!((result.slots[2].slot, result.slots[2].subslot), (1, 1));
}

// test_parse_version_1_1_with_api
#[test]
fn real_identification_data_v11_with_api() {
    let mut data = Vec::new();
    data.extend_from_slice(&0x0013u16.to_be_bytes());
    data.extend_from_slice(&0u16.to_be_bytes()); // length patched below
    data.extend_from_slice(&[1, 1]);
    data.extend_from_slice(&1u16.to_be_bytes()); // NumberOfAPIs
    data.extend_from_slice(&0u32.to_be_bytes()); // API
    data.extend_from_slice(&1u16.to_be_bytes()); // NumberOfSlots
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&0x12345678u32.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&0x87654321u32.to_be_bytes());
    let length = (data.len() - 4) as u16;
    data[2..4].copy_from_slice(&length.to_be_bytes());

    let result = parse_real_identification_data(&data);
    assert_eq!(result.version, (1, 1));
    assert_eq!(result.slots.len(), 1);
    assert_eq!(result.slots[0].api, 0);
    assert_eq!(result.slots[0].slot, 0);
    assert_eq!(result.slots[0].subslot, 1);
    assert_eq!(result.slots[0].module_ident, 0x12345678);
    assert_eq!(result.slots[0].submodule_ident, 0x87654321);
}

// test_parse_empty_returns_empty
#[test]
fn real_identification_data_empty() {
    assert!(parse_real_identification_data(&[]).slots.is_empty());
}

// ---------------------------------------------------------------------------
// TestBlockTypeConstants
// ---------------------------------------------------------------------------

// test_block_type_constants_defined
#[test]
fn block_type_constants_defined() {
    assert_eq!(indices::BLOCK_MULTIPLE_HEADER, 0x0400);
    assert_eq!(indices::BLOCK_PD_PORT_DATA_REAL, 0x020F);
    assert_eq!(indices::BLOCK_PD_INTERFACE_DATA_REAL, 0x0240);
    assert_eq!(indices::BLOCK_PD_REAL_DATA, 0xF841);
    assert_eq!(indices::BLOCK_REAL_IDENTIFICATION_DATA, 0x0013);
    assert_eq!(indices::BLOCK_REAL_IDENTIFICATION_DATA_API, 0xF000);
}

// test_get_block_type_name
#[test]
fn get_block_type_name_lookup() {
    assert_eq!(indices::get_block_type_name(0x0400), "MultipleBlockHeader");
    assert_eq!(indices::get_block_type_name(0x020F), "PDPortDataReal");
    assert_eq!(indices::get_block_type_name(0x0240), "PDInterfaceDataReal");
    assert!(indices::get_block_type_name(0xFFFF).contains("Unknown"));
}

// test_block_type_names_dict
#[test]
fn block_type_names_table() {
    assert_eq!(indices::get_block_type_name(indices::BLOCK_IM0), "I&M0");
    assert_eq!(
        indices::get_block_type_name(indices::BLOCK_AR_DATA),
        "ARData"
    );
    assert_eq!(
        indices::get_block_type_name(indices::BLOCK_LOG_DATA),
        "LogData"
    );
}

// ---------------------------------------------------------------------------
// TestAlign4
// ---------------------------------------------------------------------------

// test_align4_already_aligned + test_align4_needs_padding
#[test]
fn align4_full_range() {
    assert_eq!(align4(0), 0);
    assert_eq!(align4(4), 4);
    assert_eq!(align4(8), 8);
    assert_eq!(align4(1), 4);
    assert_eq!(align4(2), 4);
    assert_eq!(align4(3), 4);
    assert_eq!(align4(5), 8);
    assert_eq!(align4(6), 8);
    assert_eq!(align4(7), 8);
}

// ---------------------------------------------------------------------------
// TestRealDeviceData (captured, anonymized device data)
// ---------------------------------------------------------------------------

// test_parse_real_pdrealdata_sample
#[test]
fn real_device_pd_real_data_sample() {
    let data = hex::decode(concat!(
        // MultipleBlockHeader for interface (slot 0, subslot 0x8000)
        "04000090", // type=0x0400, length=0x0090
        "01000000", // version 1.0, padding
        "00000000", // API = 0
        "00008000", // slot=0, subslot=0x8000
        // Nested PDInterfaceDataReal (0x0240)
        "0240",
        "0024",
        "0100",
        "0a",                   // chassis_id len = 10
        "41414141414141414141", // "AAAAAAAAAA" (anonymized)
        "0000",                 // padding
        "001122334455",         // MAC (anonymized)
        "0000",                 // padding
        "c0a80164",             // IP: 192.168.1.100
        "ffffff00",             // Subnet: 255.255.255.0
        "c0a80101",             // Gateway: 192.168.1.1
    ))
    .unwrap();

    let result = parse_pd_real_data(&data);
    assert!(!result.slots.is_empty());
    assert_eq!(result.slots[0].subslot, 0x8000);
}

// test_parse_real_identification_sample
#[test]
fn real_device_identification_sample() {
    let data = hex::decode(concat!(
        "00130046", // type=0x0013, length=0x0046
        "0101",     // version 1.1
        "0001",     // NumAPIs = 1
        "00000000", // API = 0
        "0003",     // NumSlots = 3
        // Slot 0: 3 subslots
        "0000", "00010001", "0003", "0001", "00000001", "8000", "00000002", "8001", "00000003",
        // Slot 1: 1 subslot
        "0001", "00020002", "0001", "0001", "00000001", // Slot 2: 1 subslot
        "0002", "00030003", "0001", "0001", "00000001",
    ))
    .unwrap();

    let result = parse_real_identification_data(&data);
    assert_eq!(result.version, (1, 1));
    assert_eq!(result.slots.len(), 5); // 3 + 1 + 1
    assert_eq!(result.slots[0].slot, 0);
    assert_eq!(result.slots[0].subslot, 1);
    assert_eq!(result.slots[0].api, 0);
    assert_eq!(result.slots[1].subslot, 0x8000);
    assert_eq!(result.slots[2].subslot, 0x8001);
}

// ---------------------------------------------------------------------------
// TestModuleDiffSubmodule / TestModuleDiffModule state names. The Python
// dataclasses and parse_module_diff_block have no Rust equivalent; the state
// name mapping the properties use lives in indices, tested here.
// ---------------------------------------------------------------------------

fn state_name(table: &[(u16, &'static str)], value: u16) -> Option<&'static str> {
    table.iter().find(|(v, _)| *v == value).map(|(_, n)| *n)
}

// test_state_name_ok, test_state_name_wrong, test_no_submodule_state,
// test_state_name_unknown
#[test]
fn submodule_state_names() {
    let names = &indices::SUBMODULE_STATE_NAMES;
    assert_eq!(state_name(names, indices::SUBMODULE_STATE_OK), Some("OK"));
    assert_eq!(
        state_name(names, indices::SUBMODULE_STATE_WRONG_SUBMODULE),
        Some("WrongSubmodule")
    );
    assert_eq!(
        state_name(names, indices::SUBMODULE_STATE_NO_SUBMODULE),
        Some("NoSubmodule")
    );
    assert_eq!(state_name(names, 0xBEEF), None); // Unknown state
}

// TestModuleDiffModule: test_state_name_proper, test_state_name_wrong,
// test_state_name_unknown
#[test]
fn module_state_names() {
    let names = &indices::MODULE_STATE_NAMES;
    assert_eq!(
        state_name(names, indices::MODULE_STATE_PROPER_MODULE),
        Some("ProperModule")
    );
    assert_eq!(
        state_name(names, indices::MODULE_STATE_WRONG_MODULE),
        Some("WrongModule")
    );
    assert_eq!(state_name(names, 0xDEAD), None); // Unknown state
}

// ---------------------------------------------------------------------------
// TestWriteMultipleResult
// ---------------------------------------------------------------------------

// test_success_property + test_failure_property
#[test]
fn write_multiple_result_success() {
    let ok = WriteMultipleResult {
        status: 0,
        ..WriteMultipleResult::default()
    };
    assert!(ok.success());
    let failed = WriteMultipleResult {
        status: 0x0001,
        ..WriteMultipleResult::default()
    };
    assert!(!failed.success());
}

// test_all_fields
#[test]
fn write_multiple_result_all_fields() {
    let result = WriteMultipleResult {
        seq_num: 5,
        api: 0,
        slot: 1,
        subslot: 0x8001,
        index: 0xAFF0,
        status: 0,
        additional_value1: 0x1234,
        additional_value2: 0x5678,
    };
    assert_eq!(result.seq_num, 5);
    assert_eq!(result.api, 0);
    assert_eq!(result.slot, 1);
    assert_eq!(result.subslot, 0x8001);
    assert_eq!(result.index, 0xAFF0);
    assert_eq!(result.additional_value1, 0x1234);
    assert_eq!(result.additional_value2, 0x5678);
}

// ---------------------------------------------------------------------------
// TestParseWriteMultipleResponse
// ---------------------------------------------------------------------------

// test_parse_empty_data
#[test]
fn parse_write_multiple_response_short_data() {
    assert!(parse_write_multiple_response(&[]).is_empty());
    assert!(parse_write_multiple_response(&[0u8; 32]).is_empty());
}

// test_parse_single_result
#[test]
fn parse_write_multiple_response_single_result() {
    // Minimal IODWriteMultipleRes header (64 bytes) followed by a single
    // IODWriteRes block (0x8008).
    let mut header = vec![0u8; 64];
    header[36..40].copy_from_slice(&56u32.to_be_bytes()); // record_data_length

    let mut block = vec![0u8; 56];
    block[0..2].copy_from_slice(&0x8008u16.to_be_bytes());
    block[2..4].copy_from_slice(&52u16.to_be_bytes());
    block[6..8].copy_from_slice(&0u16.to_be_bytes()); // seq_num
    block[24..28].copy_from_slice(&0u32.to_be_bytes()); // api
    block[28..30].copy_from_slice(&1u16.to_be_bytes()); // slot
    block[30..32].copy_from_slice(&1u16.to_be_bytes()); // subslot
    block[34..36].copy_from_slice(&0xAFF1u16.to_be_bytes()); // index
    block[40..42].copy_from_slice(&0u16.to_be_bytes()); // additional_value1
    block[42..44].copy_from_slice(&0u16.to_be_bytes()); // additional_value2
    block[44..48].copy_from_slice(&0u32.to_be_bytes()); // status (success)

    let mut data = header;
    data.extend_from_slice(&block);
    let results = parse_write_multiple_response(&data);

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].slot, 1);
    assert_eq!(results[0].subslot, 1);
    assert_eq!(results[0].index, 0xAFF1);
    assert!(results[0].success());
}

// ---------------------------------------------------------------------------
// TestIODWriteMultipleBuilder (against iod_write_multiple_payload; the
// method-chaining tests are Python builder mechanics and not ported)
// ---------------------------------------------------------------------------

// test_builder_constants
#[test]
fn write_multiple_builder_constants() {
    assert_eq!(IOD_WRITE_MULTIPLE_INDEX, 0xE040);
    assert_eq!(IOD_WRITE_REQUEST_HEADER, 0x0008);
    assert_eq!(indices::WRITE_MULTIPLE, 0xE040);
}

// test_build_single_write
#[test]
fn write_multiple_build_single_write() {
    let ar_uuid = [0xAAu8; 16];
    let writes: Vec<MultiWrite> = vec![(0, 0, 1, 0xAFF1, &[0x01, 0x02, 0x03])];
    let data = iod_write_multiple_payload(&ar_uuid, 0, &writes);

    // Outer header + inner block, outer block type 0x0008.
    assert!(data.len() > 64);
    assert_eq!(be16(&data, 0), 0x0008);
}

// test_build_multiple_writes
#[test]
fn write_multiple_build_two_writes() {
    let ar_uuid = [0xBBu8; 16];
    let writes: Vec<MultiWrite> = vec![
        (0, 0, 1, 0xAFF1, &[0x01, 0x02]),
        (0, 0, 1, 0xAFF2, &[0x03, 0x04]),
    ];
    let data = iod_write_multiple_payload(&ar_uuid, 0, &writes);
    assert!(data.len() > 128);
}

// test_build_empty
#[test]
fn write_multiple_build_empty() {
    let data = iod_write_multiple_payload(&[0u8; 16], 0, &[]);
    // Outer header only (64 bytes: 6 block header + 58 body).
    assert_eq!(data.len(), 64);
}

// ---------------------------------------------------------------------------
// TestExpectedSubmodule* (against expected_submodule_block; the Rust builder
// derives the submodule type and data descriptions from the IoSlot lengths,
// so the per-class to_bytes tests are asserted on the produced block layout)
// ---------------------------------------------------------------------------

fn setup_with(slots: Vec<IoSlot>) -> IocrSetup {
    IocrSetup {
        io_slots: slots,
        send_clock_factor: 32,
        reduction_ratio: 128,
        watchdog_factor: 6,
        data_hold_factor: 6,
    }
}

fn slot(slot: u16, subslot: u16, input_length: usize, output_length: usize) -> IoSlot {
    IoSlot {
        slot,
        subslot,
        module_ident: 0x00010001,
        submodule_ident: 0x00000001,
        input_length,
        output_length,
    }
}

/// Parsed view of one API entry's first submodule:
/// (properties, data descriptions as (type, length, iocs, iops)).
fn first_submodule(block: &[u8]) -> (u16, Vec<(u16, u16, u8, u8)>) {
    // header(6) + num_apis(2) + api(4) + slot(2) + module_ident(4) +
    // module_properties(2) + num_submodules(2) = 22, then the submodule:
    // subslot(2) + submodule_ident(4) + properties(2) at 28, DDs at 30.
    let properties = be16(block, 28);
    let dd_count = match properties & 0x3 {
        3 => 2,
        _ => 1,
    };
    let mut dds = Vec::new();
    let mut off = 30;
    for _ in 0..dd_count {
        dds.push((
            be16(block, off),
            be16(block, off + 2),
            block[off + 4],
            block[off + 5],
        ));
        off += 6;
    }
    (properties, dds)
}

// test_to_bytes_produces_valid_header + test_block_type_constant
#[test]
fn expected_submodule_block_header() {
    let data = expected_submodule_block(&setup_with(vec![slot(0, 1, 0, 0)]));
    assert_eq!(be16(&data, 0), 0x0104);
    assert_eq!(data[4], 1); // version high
    assert_eq!(data[5], 0); // version low
    assert_eq!(be16(&data, 2) as usize, data.len() - 4);
}

// test_add_submodule_no_io + test_to_bytes_no_io_with_data_description +
// test_submodule_type_no_io: NO_IO still gets 1 Input DataDescription with
// data_length=0 (per p-net reference).
#[test]
fn expected_submodule_no_io() {
    let data = expected_submodule_block(&setup_with(vec![slot(0, 1, 0, 0)]));
    let (properties, dds) = first_submodule(&data);
    assert_eq!(properties, 0); // NO_IO
    assert_eq!(dds, vec![(1, 0, 1, 1)]); // Input, length 0
}

// test_add_submodule_input + test_submodule_type_input +
// TestExpectedSubmoduleDataDescription::test_to_bytes (6-byte HHBB layout)
#[test]
fn expected_submodule_input() {
    let data = expected_submodule_block(&setup_with(vec![slot(0, 1, 10, 0)]));
    let (properties, dds) = first_submodule(&data);
    assert_eq!(properties, 1); // INPUT
    assert_eq!(dds, vec![(1, 10, 1, 1)]);
}

// test_add_submodule_output + test_submodule_type_output
#[test]
fn expected_submodule_output() {
    let data = expected_submodule_block(&setup_with(vec![slot(0, 1, 0, 8)]));
    let (properties, dds) = first_submodule(&data);
    assert_eq!(properties, 2); // OUTPUT
    assert_eq!(dds, vec![(2, 8, 1, 1)]);
}

// test_add_submodule_input_output + test_submodule_type_input_output
#[test]
fn expected_submodule_input_output() {
    let data = expected_submodule_block(&setup_with(vec![slot(0, 1, 10, 8)]));
    let (properties, dds) = first_submodule(&data);
    assert_eq!(properties, 3); // INPUT_OUTPUT
    assert_eq!(dds, vec![(1, 10, 1, 1), (2, 8, 1, 1)]);
}

// test_add_same_api_slot: submodules on the same slot share one API entry.
#[test]
fn expected_submodule_same_slot_reuses_entry() {
    let data = expected_submodule_block(&setup_with(vec![slot(0, 1, 0, 0), slot(0, 0x8000, 0, 0)]));
    assert_eq!(be16(&data, 6), 1); // NumberOfAPIs
    assert_eq!(be16(&data, 20), 2); // NumberOfSubmodules in the entry
}

// test_add_different_slot: different slots get separate API entries.
#[test]
fn expected_submodule_different_slots_separate_entries() {
    let data = expected_submodule_block(&setup_with(vec![slot(0, 1, 0, 0), slot(1, 1, 0, 0)]));
    assert_eq!(be16(&data, 6), 2); // NumberOfAPIs
}

// TestExpectedSubmoduleAPI::test_to_bytes: the API entry header is
// API(4) + slot(2) + module_ident(4) + module_properties(2) + count(2) = 14.
#[test]
fn expected_submodule_api_entry_layout() {
    let data = expected_submodule_block(&setup_with(vec![slot(3, 1, 0, 0)]));
    assert_eq!(be32(&data, 8), 0); // API
    assert_eq!(be16(&data, 12), 3); // slot number
    assert_eq!(be32(&data, 14), 0x00010001); // module ident
    assert_eq!(be16(&data, 18), 0); // module properties
    assert_eq!(be16(&data, 20), 1); // number of submodules (starts at 22)
}

// ---------------------------------------------------------------------------
// TestPortInfoProperties
// ---------------------------------------------------------------------------

fn port_with_link(link_state_link: u8) -> PortInfo {
    PortInfo {
        slot: 0,
        subslot: 0x8001,
        port_id: "port-001".to_string(),
        mau_type: 0,
        link_state_port: 0,
        link_state_link,
        media_type: 0,
        peers: Vec::new(),
        domain_boundary: 0,
        multicast_boundary: 0,
    }
}

// test_link_state_up + test_link_state_down + test_link_state_unknown_value
#[test]
fn port_info_link_state() {
    assert_eq!(port_with_link(1).link_state(), "Up");
    assert_eq!(port_with_link(2).link_state(), "Down");
    assert!(port_with_link(99).link_state().contains("Unknown"));
}

// test_peer_info_mac_str
#[test]
fn peer_info_mac_str() {
    let peer = PeerInfo {
        port_id: "port-001".to_string(),
        chassis_id: "test".to_string(),
        mac_address: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    };
    assert_eq!(peer.mac_str(), "00:11:22:33:44:55");
}
