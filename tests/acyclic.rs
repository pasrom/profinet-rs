//! Byte-fidelity tests for the acyclic services against golden vectors from
//! the Python reference (tools/gen_acyclic_golden.py -> tests/golden/
//! acyclic.json): IODWriteMultipleReq (0xE040) building and response
//! parsing, the Release request, and the EPM lookup request/response. The
//! EPM vectors were captured from profinet-py's epm_lookup itself (patched
//! socket + fixed activity UUID), so they are exactly the reference's wire
//! bytes and parse results.

use profinet_rs::blocks::{iod_write_multiple_payload, parse_write_multiple_response, MultiWrite};
use profinet_rs::epm::{
    epm_lookup_request, parse_epm_response, parse_epm_tower, string_to_uuid_bytes,
    uuid_bytes_to_string, UUID_EPM_V4, UUID_PNIO_DEVICE,
};
use profinet_rs::rpc;
use profinet_rs::transport::release_request;

fn golden() -> serde_json::Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/acyclic.json"
    ))
    .expect("read golden file");
    serde_json::from_str(&raw).expect("parse golden file")
}

fn entry_bytes(entry: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(entry[field].as_str().expect("hex field")).expect("valid hex")
}

fn fixed_uuid(entry: &serde_json::Value, field: &str) -> [u8; 16] {
    entry_bytes(entry, field).try_into().expect("16-byte uuid")
}

/// The fixed UUIDs mirrored from the generator.
const AR: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const ACT: [u8; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const OBJ: [u8; 16] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
];
const SESSION_KEY: u16 = 0x1234;

/// The golden writes as MultiWrite entries (api, slot, subslot, index, data).
fn golden_writes(entry: &serde_json::Value) -> Vec<(u32, u16, u16, u16, Vec<u8>)> {
    entry["writes"]
        .as_array()
        .expect("writes array")
        .iter()
        .map(|w| {
            (
                w["api"].as_u64().unwrap() as u32,
                w["slot"].as_u64().unwrap() as u16,
                w["subslot"].as_u64().unwrap() as u16,
                w["index"].as_u64().unwrap() as u16,
                entry_bytes(w, "data"),
            )
        })
        .collect()
}

#[test]
fn write_multiple_payload_matches_reference_builder() {
    let golden = golden();
    let entry = &golden["write_multiple_payload"];
    assert_eq!(fixed_uuid(entry, "ar_uuid"), AR);

    let writes = golden_writes(entry);
    let entries: Vec<MultiWrite> = writes
        .iter()
        .map(|(api, slot, subslot, index, data)| (*api, *slot, *subslot, *index, data.as_slice()))
        .collect();
    assert_eq!(
        iod_write_multiple_payload(&AR, 0, &entries),
        entry_bytes(entry, "hex")
    );
}

#[test]
fn write_multiple_payload_without_writes_is_bare_header() {
    // IODWriteMultipleBuilder with no writes: just the 64-byte outer header
    // with record_data_length 0.
    let payload = iod_write_multiple_payload(&AR, 0, &[]);
    assert_eq!(payload.len(), 64);
    assert_eq!(&payload[36..40], &[0, 0, 0, 0]);
}

#[test]
fn write_multiple_frame_matches_reference() {
    let golden = golden();
    let writes = golden_writes(&golden["write_multiple_payload"]);
    let entries: Vec<MultiWrite> = writes
        .iter()
        .map(|(api, slot, subslot, index, data)| (*api, *slot, *subslot, *index, data.as_slice()))
        .collect();
    let entry = &golden["write_multiple_frame"];
    let seq = entry["seq"].as_u64().unwrap() as u32;
    assert_eq!(
        rpc::write_multiple_request(&OBJ, &rpc::IFACE_UUID_DEVICE, &ACT, &AR, seq, &entries),
        entry_bytes(entry, "hex")
    );
}

#[test]
fn parse_write_multiple_response_matches_reference() {
    let golden = golden();
    let entry = &golden["write_multiple_response"];
    let results = parse_write_multiple_response(&entry_bytes(entry, "hex"));
    let expected = entry["results"].as_array().expect("results array");
    assert_eq!(results.len(), expected.len());
    for (r, e) in results.iter().zip(expected) {
        assert_eq!(u64::from(r.seq_num), e["seq_num"].as_u64().unwrap());
        assert_eq!(u64::from(r.api), e["api"].as_u64().unwrap());
        assert_eq!(u64::from(r.slot), e["slot"].as_u64().unwrap());
        assert_eq!(u64::from(r.subslot), e["subslot"].as_u64().unwrap());
        assert_eq!(u64::from(r.index), e["index"].as_u64().unwrap());
        assert_eq!(u64::from(r.status), e["status"].as_u64().unwrap());
        assert_eq!(
            u64::from(r.additional_value1),
            e["additional_value1"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(r.additional_value2),
            e["additional_value2"].as_u64().unwrap()
        );
        assert_eq!(r.success(), e["success"].as_bool().unwrap());
    }
}

#[test]
fn parse_write_multiple_response_edge_cases() {
    let golden = golden();
    let data = entry_bytes(&golden["write_multiple_response"], "hex");

    // Shorter than the 64-byte outer header: nothing to parse.
    assert!(parse_write_multiple_response(&data[..63]).is_empty());

    // A non-0x8008 block type ends the walk: corrupting the second entry's
    // header leaves only the first result.
    let mut corrupt = data.clone();
    corrupt[64 + 60] = 0x12;
    assert_eq!(parse_write_multiple_response(&corrupt).len(), 1);

    // Truncating into the last entry drops it (offset + 56 > end).
    let truncated = &data[..data.len() - 8];
    assert_eq!(parse_write_multiple_response(truncated).len(), 2);
}

#[test]
fn release_request_matches_reference() {
    let golden = golden();
    let entry = &golden["release_frame"];
    let seq = entry["seq"].as_u64().unwrap() as u32;
    let frame = release_request(&OBJ, &rpc::IFACE_UUID_DEVICE, &ACT, &AR, SESSION_KEY, seq);
    assert_eq!(frame, entry_bytes(entry, "hex"));
    // The NRD payload (after the 80-byte RPC header + 20-byte NRD) is the
    // 32-byte ReleaseBlockReq.
    assert_eq!(&frame[100..], entry_bytes(entry, "release_block"));
    assert_eq!(frame[68..70], rpc::RELEASE.to_be_bytes()); // opnum
}

#[test]
fn epm_lookup_request_matches_reference() {
    let golden = golden();
    for (name, filter) in [
        ("epm_request_all", None),
        ("epm_request_filtered", Some(UUID_PNIO_DEVICE)),
    ] {
        let entry = &golden[name];
        let activity = fixed_uuid(entry, "activity_uuid");
        assert_eq!(
            epm_lookup_request(&activity, filter).unwrap(),
            entry_bytes(entry, "hex"),
            "{name}"
        );
    }
}

#[test]
fn epm_lookup_request_rejects_bad_filter_uuid() {
    assert!(epm_lookup_request(&[0u8; 16], Some("not-a-uuid")).is_err());
    assert!(epm_lookup_request(&[0u8; 16], Some("zzzzzzzz-5d1f-11c9-91a4-08002b14a0fa")).is_err());
}

#[test]
fn parse_epm_response_matches_reference() {
    let golden = golden();
    let entry = &golden["epm_response"];
    let endpoints = parse_epm_response(&entry_bytes(entry, "hex"));
    let expected = entry["endpoints"].as_array().expect("endpoints array");
    assert_eq!(endpoints.len(), expected.len());
    for (ep, e) in endpoints.iter().zip(expected) {
        assert_eq!(ep.interface_uuid, e["interface_uuid"].as_str().unwrap());
        assert_eq!(
            u64::from(ep.interface_version_major),
            e["interface_version_major"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(ep.interface_version_minor),
            e["interface_version_minor"].as_u64().unwrap()
        );
        assert_eq!(ep.object_uuid, e["object_uuid"].as_str().unwrap());
        assert_eq!(ep.protocol, e["protocol"].as_str().unwrap());
        assert_eq!(u64::from(ep.port), e["port"].as_u64().unwrap());
        assert_eq!(ep.address, e["address"].as_str().unwrap());
        assert_eq!(ep.annotation, e["annotation"].as_str().unwrap());
        assert_eq!(ep.interface_name(), e["interface_name"].as_str().unwrap());
    }
}

#[test]
fn parse_epm_response_edge_cases() {
    let golden = golden();
    let data = entry_bytes(&golden["epm_response"], "hex");

    // Shorter than the 80-byte RPC header: no endpoints.
    assert!(parse_epm_response(&data[..79]).is_empty());

    // FAULT and other non-RESPONSE packet types: no endpoints.
    for packet_type in [0x03u8, 0x00, 0x06] {
        let mut other = data.clone();
        other[1] = packet_type;
        assert!(parse_epm_response(&other).is_empty(), "type {packet_type}");
    }

    // Truncating into the second entry's tower keeps only the first.
    let truncated = &data[..data.len() - 8];
    assert_eq!(parse_epm_response(truncated).len(), 1);
}

#[test]
fn parse_epm_tower_matches_reference() {
    let golden = golden();
    let entry = &golden["epm_tower"];
    let tower = entry_bytes(entry, "hex");
    let ep = parse_epm_tower(&tower).expect("tower parses");
    assert_eq!(ep.interface_uuid, entry["interface_uuid"].as_str().unwrap());
    assert_eq!(
        u64::from(ep.interface_version_major),
        entry["interface_version_major"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(ep.interface_version_minor),
        entry["interface_version_minor"].as_u64().unwrap()
    );
    assert_eq!(ep.protocol, entry["protocol"].as_str().unwrap());
    assert_eq!(u64::from(ep.port), entry["port"].as_u64().unwrap());
    assert_eq!(ep.address, entry["address"].as_str().unwrap());

    // Truncated tower parses to None, as in the reference.
    assert!(parse_epm_tower(&tower[..3]).is_none());
    // A tower whose floors survive but carry no interface UUID: None.
    let no_uuid = [0x01, 0x00, 0x01, 0x00, 0x0A, 0x02, 0x00, 0x00, 0x00];
    assert!(parse_epm_tower(&no_uuid).is_none());
}

#[test]
fn uuid_string_conversion_round_trips() {
    for uuid in [UUID_EPM_V4, UUID_PNIO_DEVICE] {
        let bytes = string_to_uuid_bytes(uuid).unwrap();
        assert_eq!(uuid_bytes_to_string(&bytes), uuid);
    }
    // Non-16-byte input maps to "" like the reference.
    assert_eq!(uuid_bytes_to_string(&[0u8; 15]), "");
    assert!(string_to_uuid_bytes("dea00001").is_err());
}

// ---------------------------------------------------------------------------
// Ports of profinet-py tests/test_rpc.py EPM/constants tests
// (TestRPCConstants, TestEPMEndpoint, TestUUIDConversion, TestParseEPMTower).
// Not ported: TestRPCConstantsExport (Python import mechanics), TestEPMLookup
// (live network sockets), RPC_BIND_PORT / UUID_NULL / interface-version
// constants that have no Rust equivalent.
// ---------------------------------------------------------------------------

mod py_parity {
    use profinet_rs::epm::{
        parse_epm_tower, string_to_uuid_bytes, uuid_bytes_to_string, EpmEndpoint, RPC_PORT,
        UUID_EPM_V4, UUID_PNIO_CONTROLLER, UUID_PNIO_DEVICE,
    };

    // TestRPCConstants::test_rpc_port_value
    #[test]
    fn rpc_port_value() {
        assert_eq!(RPC_PORT, 0x8894);
        assert_eq!(RPC_PORT, 34964);
        assert_eq!(profinet_rs::transport::RPC_PORT, 0x8894);
    }

    // TestRPCConstants::test_uuid_* values
    #[test]
    fn uuid_constant_values() {
        assert_eq!(UUID_EPM_V4, "e1af8308-5d1f-11c9-91a4-08002b14a0fa");
        assert_eq!(UUID_PNIO_DEVICE, "dea00001-6c97-11d1-8271-00a02442df7d");
        assert_eq!(UUID_PNIO_CONTROLLER, "dea00002-6c97-11d1-8271-00a02442df7d");
    }

    // TestRPCConstants::test_uuid_device_and_controller_differ_only_in_last_digit
    // (the differing digit is in the first field, per the reference test)
    #[test]
    fn uuid_device_and_controller_differ_only_in_one_digit() {
        assert_eq!(
            &UUID_PNIO_DEVICE[.."dea0000".len()],
            &UUID_PNIO_CONTROLLER[.."dea0000".len()]
        );
        assert_eq!(&UUID_PNIO_DEVICE[8..], &UUID_PNIO_CONTROLLER[8..]);
        assert_ne!(UUID_PNIO_DEVICE, UUID_PNIO_CONTROLLER);
    }

    // TestEPMEndpoint::test_epm_endpoint_defaults
    #[test]
    fn epm_endpoint_defaults() {
        let ep = EpmEndpoint::default();
        assert_eq!(ep.interface_uuid, "");
        assert_eq!(ep.interface_version_major, 0);
        assert_eq!(ep.interface_version_minor, 0);
        assert_eq!(ep.object_uuid, "");
        assert_eq!(ep.protocol, "");
        assert_eq!(ep.port, 0);
        assert_eq!(ep.address, "");
        assert_eq!(ep.annotation, "");
    }

    // TestEPMEndpoint::test_epm_endpoint_values
    #[test]
    fn epm_endpoint_values() {
        let ep = EpmEndpoint {
            interface_uuid: UUID_PNIO_DEVICE.to_string(),
            interface_version_major: 1,
            interface_version_minor: 0,
            protocol: "ncadg_ip_udp".to_string(),
            port: 34964,
            address: "192.168.1.100".to_string(),
            annotation: "S7-1500 6ES7 672-5DC01-0YA0".to_string(),
            ..EpmEndpoint::default()
        };
        assert_eq!(ep.interface_uuid, UUID_PNIO_DEVICE);
        assert_eq!(ep.port, 34964);
        assert_eq!(ep.annotation, "S7-1500 6ES7 672-5DC01-0YA0");
    }

    // TestEPMEndpoint::test_interface_name_*
    #[test]
    fn epm_endpoint_interface_names() {
        let named = |uuid: &str| EpmEndpoint {
            interface_uuid: uuid.to_string(),
            ..EpmEndpoint::default()
        };
        assert_eq!(named(UUID_PNIO_DEVICE).interface_name(), "PNIO-Device");
        assert_eq!(
            named(UUID_PNIO_CONTROLLER).interface_name(),
            "PNIO-Controller"
        );
        assert_eq!(named(UUID_EPM_V4).interface_name(), "EPM");
        assert!(named("12345678-1234-1234-1234-123456789abc")
            .interface_name()
            .contains("Unknown"));
    }

    // TestUUIDConversion::test_uuid_bytes_to_string_pnio_device
    #[test]
    fn uuid_bytes_to_string_pnio_device() {
        // PNIO Device UUID in DCE/RPC format (mixed-endian).
        let uuid_bytes = [
            0x01, 0x00, 0xA0, 0xDE, // time_low (LE)
            0x97, 0x6C, // time_mid (LE)
            0xD1, 0x11, // time_hi (LE)
            0x82, 0x71, // clock_seq (BE)
            0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D, // node (BE)
        ];
        assert_eq!(
            uuid_bytes_to_string(&uuid_bytes),
            "dea00001-6c97-11d1-8271-00a02442df7d"
        );
    }

    // TestUUIDConversion::test_uuid_bytes_to_string_null +
    // test_uuid_bytes_to_string_invalid_length
    #[test]
    fn uuid_bytes_to_string_null_and_invalid() {
        assert_eq!(
            uuid_bytes_to_string(&[0u8; 16]),
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(uuid_bytes_to_string(&[0u8; 10]), "");
    }

    // TestUUIDConversion::test_string_to_uuid_bytes_* + test_uuid_roundtrip
    #[test]
    fn uuid_string_roundtrips() {
        for uuid in [
            "00000000-0000-0000-0000-000000000000", // UUID_NULL
            UUID_EPM_V4,
            UUID_PNIO_DEVICE,
            UUID_PNIO_CONTROLLER,
        ] {
            let bytes = string_to_uuid_bytes(uuid).unwrap();
            assert_eq!(bytes.len(), 16);
            assert_eq!(uuid_bytes_to_string(&bytes), uuid, "roundtrip {uuid}");
        }
    }

    // TestUUIDConversion::test_string_to_uuid_bytes_invalid
    #[test]
    fn uuid_string_invalid_errors() {
        let err = string_to_uuid_bytes("invalid-uuid").unwrap_err();
        assert!(err.contains("Invalid UUID"), "{err}");
    }

    // TestParseEPMTower::test_parse_empty_tower + test_parse_short_tower +
    // test_parse_minimal_tower
    #[test]
    fn parse_epm_tower_degenerate_inputs() {
        assert!(parse_epm_tower(&[]).is_none());
        assert!(parse_epm_tower(&[0u8; 3]).is_none());
        // Floor count = 0: no interface UUID found.
        assert!(parse_epm_tower(&[0x00, 0x00]).is_none());
    }

    // TestParseEPMTower::test_parse_tower_with_uuid_floor
    #[test]
    fn parse_epm_tower_with_uuid_floor() {
        let mut tower = Vec::new();
        tower.extend_from_slice(&1u16.to_le_bytes()); // floor count

        // LHS: protocol ID (0x0D) + UUID (16 bytes) + version major (LE u16).
        let mut lhs = vec![0x0D];
        lhs.extend_from_slice(&string_to_uuid_bytes(UUID_PNIO_DEVICE).unwrap());
        lhs.extend_from_slice(&1u16.to_le_bytes());
        tower.extend_from_slice(&(lhs.len() as u16).to_le_bytes());
        tower.extend_from_slice(&lhs);

        // RHS: version minor (LE u16).
        tower.extend_from_slice(&2u16.to_le_bytes());
        tower.extend_from_slice(&0u16.to_le_bytes());

        let result = parse_epm_tower(&tower).expect("tower parses");
        assert_eq!(result.interface_uuid, UUID_PNIO_DEVICE);
        assert_eq!(result.interface_version_major, 1);
        assert_eq!(result.interface_version_minor, 0);
    }
}
