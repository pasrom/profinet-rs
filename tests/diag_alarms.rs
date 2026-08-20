//! Golden byte-fidelity tests for the diagnosis + alarms + alarm-listener
//! modules against vectors generated from the Python reference
//! (tools/gen_diag_alarm_golden.py -> tests/golden/diag_alarms.json): the
//! parsers must extract the same fields profinet-py's parsers do, and the
//! ack/RTA builders must produce byte-identical frames. Plus edge cases for
//! the parsing tolerance. The live listener path is bench-only (#[ignore]).

use profinet_rs::alarm_listener::{
    build_alarm_ack, build_layer2_ack_frame, check_layer2_frame, process_layer2_alarm,
    AlarmEndpoint, AlarmListener, RtaHeader, ETHERTYPE_PROFINET, FRAME_ID_ALARM_HIGH,
    FRAME_ID_ALARM_LOW,
};
use profinet_rs::alarms::{
    get_alarm_type_name, get_pe_mode_name, get_usi_name, parse_alarm_cr_res, parse_alarm_item,
    parse_alarm_notification, AlarmItem, BLOCK_ALARM_ACK_HIGH, BLOCK_ALARM_ACK_LOW,
    BLOCK_ALARM_CR_REQ, BLOCK_ALARM_CR_RES, BLOCK_ALARM_NOTIFICATION_HIGH,
    BLOCK_ALARM_NOTIFICATION_LOW, USI_CHANNEL_DIAGNOSIS, USI_EXT_CHANNEL_DIAGNOSIS, USI_IPARAMETER,
    USI_MAINTENANCE, USI_PE_ALARM, USI_PRAL_ALARM, USI_QUALIFIED_CHANNEL_DIAGNOSIS,
    USI_RS_ALARM_HIGH, USI_RS_ALARM_LOW, USI_RS_ALARM_SUBMODULE, USI_UPLOAD,
};
use profinet_rs::diagnosis::{
    decode_channel_error_type, decode_ext_channel_error_type, parse_diagnosis_block,
    parse_diagnosis_simple, ChannelProperties, DiagnosisData, DiagnosisKind,
};

fn golden() -> serde_json::Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/diag_alarms.json"
    ))
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

fn bool_of(entry: &serde_json::Value, field: &str) -> bool {
    entry[field]
        .as_bool()
        .unwrap_or_else(|| panic!("field {field} missing"))
}

fn str_of<'a>(entry: &'a serde_json::Value, field: &str) -> &'a str {
    entry[field]
        .as_str()
        .unwrap_or_else(|| panic!("field {field} missing"))
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_match_indices_py() {
    assert_eq!(BLOCK_ALARM_NOTIFICATION_HIGH, 0x0001);
    assert_eq!(BLOCK_ALARM_ACK_HIGH, 0x8001);
    assert_eq!(BLOCK_ALARM_NOTIFICATION_LOW, 0x0002);
    assert_eq!(BLOCK_ALARM_ACK_LOW, 0x8002);
    assert_eq!(BLOCK_ALARM_CR_REQ, 0x0103);
    assert_eq!(BLOCK_ALARM_CR_RES, 0x8103);
    assert_eq!(USI_CHANNEL_DIAGNOSIS, 0x8000);
    assert_eq!(USI_EXT_CHANNEL_DIAGNOSIS, 0x8002);
    assert_eq!(USI_QUALIFIED_CHANNEL_DIAGNOSIS, 0x8003);
    assert_eq!(USI_MAINTENANCE, 0x8100);
    assert_eq!(USI_UPLOAD, 0x8200);
    assert_eq!(USI_IPARAMETER, 0x8201);
    assert_eq!(USI_RS_ALARM_LOW, 0x8300);
    assert_eq!(USI_RS_ALARM_HIGH, 0x8301);
    assert_eq!(USI_RS_ALARM_SUBMODULE, 0x8302);
    assert_eq!(USI_PE_ALARM, 0x8310);
    assert_eq!(USI_PRAL_ALARM, 0x8320);
    assert_eq!(FRAME_ID_ALARM_HIGH, 0xFC01);
    assert_eq!(FRAME_ID_ALARM_LOW, 0xFE01);
    assert_eq!(ETHERTYPE_PROFINET, 0x8892);
}

// ---------------------------------------------------------------------------
// Diagnosis parsing vs golden
// ---------------------------------------------------------------------------

fn assert_diag_matches(name: &str, result: &DiagnosisData, expected: &serde_json::Value) {
    assert_eq!(result.api, u64_of(expected, "api") as u32, "{name}: api");
    assert_eq!(result.slot, u64_of(expected, "slot") as u16, "{name}: slot");
    assert_eq!(
        result.subslot,
        u64_of(expected, "subslot") as u16,
        "{name}: subslot"
    );
    assert_eq!(
        result.has_errors(),
        bool_of(expected, "has_errors"),
        "{name}: has_errors"
    );
    assert_eq!(
        result.has_maintenance_required(),
        bool_of(expected, "has_maintenance_required"),
        "{name}: has_maintenance_required"
    );
    assert_eq!(
        result.has_maintenance_demanded(),
        bool_of(expected, "has_maintenance_demanded"),
        "{name}: has_maintenance_demanded"
    );

    let exp_entries = expected["entries"].as_array().expect("entries array");
    assert_eq!(
        result.entries.len(),
        exp_entries.len(),
        "{name}: entry count"
    );
    for (i, (entry, exp)) in result.entries.iter().zip(exp_entries).enumerate() {
        let expected_kind = match str_of(exp, "kind") {
            "ChannelDiagnosis" => DiagnosisKind::Channel,
            "ExtChannelDiagnosis" => DiagnosisKind::Ext,
            "QualifiedChannelDiagnosis" => DiagnosisKind::Qualified,
            other => panic!("{name}[{i}]: unknown kind {other}"),
        };
        assert_eq!(entry.kind, expected_kind, "{name}[{i}]: kind");
        assert_eq!(entry.api, u64_of(exp, "api") as u32, "{name}[{i}]: api");
        assert_eq!(entry.slot, u64_of(exp, "slot") as u16, "{name}[{i}]: slot");
        assert_eq!(
            entry.subslot,
            u64_of(exp, "subslot") as u16,
            "{name}[{i}]: subslot"
        );
        assert_eq!(
            entry.channel_number,
            u64_of(exp, "channel_number") as u16,
            "{name}[{i}]: channel_number"
        );
        assert_eq!(
            entry.error_type,
            u64_of(exp, "error_type") as u16,
            "{name}[{i}]: error_type"
        );
        assert_eq!(
            entry.error_type_name,
            str_of(exp, "error_type_name"),
            "{name}[{i}]: error_type_name"
        );
        assert_eq!(
            entry.is_submodule_level(),
            bool_of(exp, "is_submodule_level"),
            "{name}[{i}]: is_submodule_level"
        );

        let props = &exp["channel_properties"];
        let p = &entry.channel_properties;
        assert_eq!(p.raw, u64_of(props, "raw") as u16, "{name}[{i}]: raw");
        assert_eq!(
            p.channel_type as u64,
            u64_of(props, "channel_type"),
            "{name}[{i}]: channel_type"
        );
        assert_eq!(
            p.accumulative as u64,
            u64_of(props, "accumulative"),
            "{name}[{i}]: accumulative"
        );
        assert_eq!(
            p.maintenance_required,
            bool_of(props, "maintenance_required"),
            "{name}[{i}]: maintenance_required"
        );
        assert_eq!(
            p.maintenance_demanded,
            bool_of(props, "maintenance_demanded"),
            "{name}[{i}]: maintenance_demanded"
        );
        assert_eq!(
            p.specifier as u64,
            u64_of(props, "specifier"),
            "{name}[{i}]: specifier"
        );
        assert_eq!(
            p.direction as u64,
            u64_of(props, "direction"),
            "{name}[{i}]: direction"
        );

        if exp.get("ext_error_type").is_some() {
            assert_eq!(
                entry.ext_error_type,
                u64_of(exp, "ext_error_type") as u16,
                "{name}[{i}]: ext_error_type"
            );
            assert_eq!(
                entry.ext_error_type_name,
                str_of(exp, "ext_error_type_name"),
                "{name}[{i}]: ext_error_type_name"
            );
            assert_eq!(
                entry.ext_add_value,
                u64_of(exp, "ext_add_value") as u32,
                "{name}[{i}]: ext_add_value"
            );
        }
        if exp.get("qualifier").is_some() {
            assert_eq!(
                entry.qualifier,
                u64_of(exp, "qualifier") as u32,
                "{name}[{i}]: qualifier"
            );
        }
    }
}

#[test]
fn golden_diagnosis_block_parsing() {
    let golden = golden();
    for name in [
        "diag_channel_single",
        "diag_ext_channel",
        "diag_qualified_channel",
        "diag_mixed_entries",
        "diag_with_location_header",
        "diag_unknown_usi",
        "diag_truncated_ext",
        "diag_empty",
        "diag_short",
        "diag_no_block_header",
    ] {
        let entry = &golden[name];
        assert!(!entry.is_null(), "missing golden vector {name}");
        let data = entry_bytes(entry);
        let result = parse_diagnosis_block(
            &data,
            u64_of(entry, "api") as u32,
            u64_of(entry, "slot") as u16,
            u64_of(entry, "subslot") as u16,
        );
        assert_eq!(result.raw_data, data, "{name}: raw_data");
        assert_diag_matches(name, &result, &entry["expected"]);
    }
}

#[test]
fn golden_diagnosis_simple_parsing() {
    let golden = golden();
    let entry = &golden["diag_simple"];
    let data = entry_bytes(entry);
    let result = parse_diagnosis_simple(
        &data,
        u64_of(entry, "api") as u32,
        u64_of(entry, "slot") as u16,
        u64_of(entry, "subslot") as u16,
    );
    assert_eq!(result.raw_data, data);
    assert_diag_matches("diag_simple", &result, &entry["expected"]);
}

#[test]
fn diagnosis_get_by_channel() {
    let golden = golden();
    let data = entry_bytes(&golden["diag_mixed_entries"]);
    let result = parse_diagnosis_block(&data, 0, 0, 0);
    assert_eq!(result.get_by_channel(0x8001).len(), 1);
    assert_eq!(result.get_by_channel(0x8002).len(), 1);
    assert_eq!(result.get_by_channel(0x0007).len(), 0);
}

// ---------------------------------------------------------------------------
// Decode tables vs golden sweeps
// ---------------------------------------------------------------------------

#[test]
fn golden_decode_channel_error_type() {
    let golden = golden();
    for case in golden["decode_channel_error_type"]["cases"]
        .as_array()
        .expect("cases")
    {
        let value = case[0].as_u64().expect("value") as u16;
        let expected = case[1].as_str().expect("name");
        assert_eq!(
            decode_channel_error_type(value),
            expected,
            "error type 0x{value:04X}"
        );
    }
}

#[test]
fn golden_decode_ext_channel_error_type() {
    let golden = golden();
    for case in golden["decode_ext_channel_error_type"]["cases"]
        .as_array()
        .expect("cases")
    {
        let cet = case[0].as_u64().expect("cet") as u16;
        let ext = case[1].as_u64().expect("ext") as u16;
        let expected = case[2].as_str().expect("name");
        assert_eq!(
            decode_ext_channel_error_type(cet, ext),
            expected,
            "cet 0x{cet:04X} ext 0x{ext:04X}"
        );
    }
}

#[test]
fn golden_name_helpers() {
    let golden = golden();
    for case in golden["get_usi_name"]["cases"].as_array().expect("cases") {
        let value = case[0].as_u64().expect("value") as u16;
        assert_eq!(
            get_usi_name(value),
            case[1].as_str().expect("name"),
            "usi 0x{value:04X}"
        );
    }
    for case in golden["get_alarm_type_name"]["cases"]
        .as_array()
        .expect("cases")
    {
        let value = case[0].as_u64().expect("value") as u16;
        assert_eq!(
            get_alarm_type_name(value),
            case[1].as_str().expect("name"),
            "alarm type 0x{value:04X}"
        );
    }
    for case in golden["get_pe_mode_name"]["cases"]
        .as_array()
        .expect("cases")
    {
        let value = case[0].as_u64().expect("value") as u8;
        assert_eq!(
            get_pe_mode_name(value),
            case[1].as_str().expect("name"),
            "pe mode 0x{value:02X}"
        );
    }
}

// ---------------------------------------------------------------------------
// AlarmNotification parsing vs golden
// ---------------------------------------------------------------------------

fn assert_item_matches(name: &str, i: usize, item: &AlarmItem, exp: &serde_json::Value) {
    assert_eq!(
        item.user_structure_id(),
        u64_of(exp, "user_structure_id") as u16,
        "{name}[{i}]: usi"
    );
    assert_eq!(
        item.usi_name(),
        str_of(exp, "usi_name"),
        "{name}[{i}]: usi_name"
    );
    match (str_of(exp, "kind"), item) {
        ("DiagnosisItem", AlarmItem::Diagnosis(d)) => {
            assert_eq!(d.channel_number, u64_of(exp, "channel_number") as u16);
            assert_eq!(
                d.channel_properties,
                u64_of(exp, "channel_properties") as u16
            );
            assert_eq!(
                d.channel_error_type,
                u64_of(exp, "channel_error_type") as u16
            );
            assert_eq!(
                d.ext_channel_error_type,
                u64_of(exp, "ext_channel_error_type") as u16
            );
            assert_eq!(
                d.ext_channel_add_value,
                u64_of(exp, "ext_channel_add_value") as u32
            );
            assert_eq!(
                d.qualified_channel_qualifier,
                u64_of(exp, "qualified_channel_qualifier") as u32
            );
            let props = &exp["props"];
            assert_eq!(
                d.channel_number_value(),
                u64_of(props, "channel_number_value") as u16
            );
            assert_eq!(d.is_accumulative(), bool_of(props, "is_accumulative"));
            assert_eq!(d.channel_type(), u64_of(props, "channel_type") as u16);
            assert_eq!(d.is_extended(), bool_of(props, "is_extended"));
            assert_eq!(d.is_qualified(), bool_of(props, "is_qualified"));
        }
        ("MaintenanceItem", AlarmItem::Maintenance(m)) => {
            assert_eq!(m.block_type, u64_of(exp, "block_type") as u16);
            assert_eq!(m.block_length, u64_of(exp, "block_length") as u16);
            assert_eq!(m.block_version, u64_of(exp, "block_version") as u16);
            assert_eq!(
                m.maintenance_status,
                u64_of(exp, "maintenance_status") as u32
            );
            let props = &exp["props"];
            assert_eq!(
                m.maintenance_required(),
                bool_of(props, "maintenance_required")
            );
            assert_eq!(
                m.maintenance_demanded(),
                bool_of(props, "maintenance_demanded")
            );
        }
        ("UploadRetrievalItem", AlarmItem::UploadRetrieval(u)) => {
            assert_eq!(u.block_type, u64_of(exp, "block_type") as u16);
            assert_eq!(u.block_length, u64_of(exp, "block_length") as u16);
            assert_eq!(u.block_version, u64_of(exp, "block_version") as u16);
            assert_eq!(u.ur_record_index, u64_of(exp, "ur_record_index") as u32);
            assert_eq!(u.ur_record_length, u64_of(exp, "ur_record_length") as u32);
        }
        ("PE_AlarmItem", AlarmItem::Pe(p)) => {
            assert_eq!(p.block_type, u64_of(exp, "block_type") as u16);
            assert_eq!(p.block_length, u64_of(exp, "block_length") as u16);
            assert_eq!(p.block_version, u64_of(exp, "block_version") as u16);
            assert_eq!(
                p.pe_operational_mode,
                u64_of(exp, "pe_operational_mode") as u8
            );
        }
        ("RS_AlarmItem", AlarmItem::Rs(r)) => {
            assert_eq!(r.rs_alarm_info, u64_of(exp, "rs_alarm_info") as u16);
        }
        ("PRAL_AlarmItem", AlarmItem::Pral(p)) => {
            assert_eq!(p.channel_number, u64_of(exp, "channel_number") as u16);
            assert_eq!(
                p.pral_channel_properties,
                u64_of(exp, "pral_channel_properties") as u16
            );
            assert_eq!(p.pral_reason, u64_of(exp, "pral_reason") as u16);
            assert_eq!(p.pral_ext_reason, u64_of(exp, "pral_ext_reason") as u16);
            assert_eq!(
                hex::encode(&p.pral_reason_add_value),
                str_of(exp, "pral_reason_add_value")
            );
        }
        ("AlarmItem", AlarmItem::Generic { raw_data, .. }) => {
            assert_eq!(hex::encode(raw_data), str_of(exp, "raw_data"));
        }
        (kind, item) => panic!("{name}[{i}]: expected {kind}, got {item:?}"),
    }
}

#[test]
fn golden_alarm_notifications() {
    let golden = golden();
    for name in [
        "alarm_diag_channel",
        "alarm_ext_and_qualified",
        "alarm_maintenance",
        "alarm_upload_retrieval",
        "alarm_rs",
        "alarm_pe",
        "alarm_pral",
        "alarm_unknown_usi",
        "alarm_no_items",
        "alarm_truncated_item",
    ] {
        let entry = &golden[name];
        assert!(!entry.is_null(), "missing golden vector {name}");
        let data = entry_bytes(entry);
        let alarm = parse_alarm_notification(&data).expect(name);
        let exp = &entry["expected"];

        assert_eq!(alarm.block_type, u64_of(exp, "block_type") as u16, "{name}");
        let ver = exp["block_version"].as_array().expect("block_version");
        assert_eq!(
            alarm.block_version,
            (
                ver[0].as_u64().unwrap() as u8,
                ver[1].as_u64().unwrap() as u8
            ),
            "{name}"
        );
        assert_eq!(alarm.alarm_type, u64_of(exp, "alarm_type") as u16, "{name}");
        assert_eq!(
            alarm.alarm_type_name(),
            str_of(exp, "alarm_type_name"),
            "{name}"
        );
        assert_eq!(alarm.api, u64_of(exp, "api") as u32, "{name}");
        assert_eq!(
            alarm.slot_number,
            u64_of(exp, "slot_number") as u16,
            "{name}"
        );
        assert_eq!(
            alarm.subslot_number,
            u64_of(exp, "subslot_number") as u16,
            "{name}"
        );
        assert_eq!(
            alarm.module_ident_number,
            u64_of(exp, "module_ident_number") as u32,
            "{name}"
        );
        assert_eq!(
            alarm.submodule_ident_number,
            u64_of(exp, "submodule_ident_number") as u32,
            "{name}"
        );
        assert_eq!(
            alarm.alarm_sequence_number,
            u64_of(exp, "alarm_sequence_number") as u16,
            "{name}"
        );
        assert_eq!(
            alarm.channel_diagnosis,
            bool_of(exp, "channel_diagnosis"),
            "{name}"
        );
        assert_eq!(
            alarm.manufacturer_specific,
            bool_of(exp, "manufacturer_specific"),
            "{name}"
        );
        assert_eq!(
            alarm.submodule_diagnosis_state,
            bool_of(exp, "submodule_diagnosis_state"),
            "{name}"
        );
        assert_eq!(
            alarm.ar_diagnosis_state,
            bool_of(exp, "ar_diagnosis_state"),
            "{name}"
        );
        assert_eq!(
            alarm.is_high_priority(),
            bool_of(exp, "is_high_priority"),
            "{name}"
        );
        assert_eq!(
            alarm.is_low_priority(),
            bool_of(exp, "is_low_priority"),
            "{name}"
        );
        assert_eq!(alarm.location(), str_of(exp, "location"), "{name}");
        assert_eq!(
            hex::encode(&alarm.raw_payload),
            str_of(exp, "raw_payload"),
            "{name}"
        );

        let exp_items = exp["items"].as_array().expect("items");
        assert_eq!(alarm.items.len(), exp_items.len(), "{name}: item count");
        for (i, (item, exp_item)) in alarm.items.iter().zip(exp_items).enumerate() {
            assert_item_matches(name, i, item, exp_item);
        }
    }
}

// ---------------------------------------------------------------------------
// RTA header / AlarmAck / Layer-2 frames vs golden
// ---------------------------------------------------------------------------

#[test]
fn golden_rta_header_roundtrip() {
    let golden = golden();
    let entry = &golden["rta_header"];
    let data = entry_bytes(entry);

    let hdr = RtaHeader::from_bytes(&data).expect("parse RTA header");
    assert_eq!(
        hdr.alarm_dst_endpoint,
        u64_of(entry, "alarm_dst_endpoint") as u16
    );
    assert_eq!(
        hdr.alarm_src_endpoint,
        u64_of(entry, "alarm_src_endpoint") as u16
    );
    assert_eq!(hdr.pdu_type, u64_of(entry, "pdu_type") as u8);
    assert_eq!(hdr.add_flags, u64_of(entry, "add_flags") as u8);
    assert_eq!(hdr.send_seq_num, u64_of(entry, "send_seq_num") as u16);
    assert_eq!(hdr.ack_seq_num, u64_of(entry, "ack_seq_num") as u16);
    assert_eq!(hdr.var_part_len, u64_of(entry, "var_part_len") as u16);
    assert_eq!(hdr.to_bytes().to_vec(), data, "rebuild is byte-exact");
    assert_eq!(
        hdr.pdu_type,
        (RtaHeader::RTA_TYPE_DATA << 4) | RtaHeader::VERSION_1
    );
}

#[test]
fn golden_alarm_ack_byte_exact() {
    let golden = golden();
    let alarm =
        parse_alarm_notification(&entry_bytes(&golden["alarm_diag_channel"])).expect("alarm");
    assert_eq!(
        build_alarm_ack(&alarm),
        entry_bytes(&golden["alarm_ack"]),
        "AlarmAck PDU bytes"
    );
}

#[test]
fn golden_layer2_ack_frame_byte_exact() {
    let golden = golden();
    let entry = &golden["layer2_ack_frame"];
    let alarm =
        parse_alarm_notification(&entry_bytes(&golden["alarm_diag_channel"])).expect("alarm");

    let device_mac: [u8; 6] = hex::decode(str_of(entry, "device_mac"))
        .unwrap()
        .try_into()
        .unwrap();
    let controller_mac: [u8; 6] = hex::decode(str_of(entry, "controller_mac"))
        .unwrap()
        .try_into()
        .unwrap();
    let endpoint = AlarmEndpoint {
        interface: String::new(),
        controller_ref: u64_of(entry, "controller_ref") as u16,
        device_ref: u64_of(entry, "device_ref") as u16,
        device_mac,
        transport: 0,
        ..Default::default()
    };
    let frame = build_layer2_ack_frame(
        &endpoint,
        &controller_mac,
        u64_of(entry, "send_seq_num") as u16,
        u64_of(entry, "ack_seq_num") as u16,
        &build_alarm_ack(&alarm),
        alarm.is_high_priority(),
    );
    assert_eq!(frame, entry_bytes(entry), "L2 AlarmAck frame bytes");
}

#[test]
fn golden_layer2_inbound_alarm_frame() {
    let golden = golden();
    let entry = &golden["layer2_inbound_alarm_frame"];
    let frame = entry_bytes(entry);
    let device_mac: [u8; 6] = hex::decode(str_of(entry, "device_mac"))
        .unwrap()
        .try_into()
        .unwrap();

    let (high, payload) = check_layer2_frame(&frame, &device_mac).expect("frame accepted");
    assert!(!high, "frame ID 0xFE01 is low priority");

    let controller_ref = u64_of(entry, "controller_ref") as u16;
    let (rta, alarm) = process_layer2_alarm(payload, controller_ref)
        .expect("parse ok")
        .expect("addressed to us");
    let rta = rta.expect("RTA header present");
    assert_eq!(rta.alarm_dst_endpoint, controller_ref);
    assert_eq!(
        rta.send_seq_num,
        u64_of(entry, "rta_send_seq_num") as u16,
        "recv seq tracking source"
    );

    // The wrapped notification is the alarm_diag_channel vector.
    let exp = &golden["alarm_diag_channel"]["expected"];
    assert_eq!(alarm.alarm_type, u64_of(exp, "alarm_type") as u16);
    assert_eq!(alarm.alarm_sequence_number, 0x0123);
    assert!(alarm.channel_diagnosis);
    assert_eq!(alarm.items.len(), 1);

    // Wrong destination reference is silently ignored.
    assert_eq!(
        process_layer2_alarm(payload, controller_ref + 1).expect("parse ok"),
        None
    );
}

#[test]
fn golden_alarm_cr_res() {
    let golden = golden();
    let entry = &golden["alarm_cr_res"];
    let data = entry_bytes(entry);
    assert_eq!(
        parse_alarm_cr_res(&data),
        Some(u64_of(entry, "local_alarm_reference") as u16)
    );
    // Without the 0x8103 block, nothing is found.
    assert_eq!(parse_alarm_cr_res(&data[..12]), None);
    assert_eq!(parse_alarm_cr_res(&[]), None);
}

// ---------------------------------------------------------------------------
// Edge cases beyond the golden vectors
// ---------------------------------------------------------------------------

#[test]
fn alarm_notification_too_short_errors() {
    assert!(parse_alarm_notification(&[]).is_err());
    // One byte short of BlockHeader(6) + Body(20).
    assert!(parse_alarm_notification(&[0u8; 25]).is_err());
}

#[test]
fn item_less_alarm_is_accepted_at_26_bytes() {
    // BlockHeader(6) + Body(20), BlockLength 22. Rejected while the body was
    // taken as 22 bytes, which also pushed the item cursor two bytes into the
    // first item of any alarm that did carry one.
    let pdu = hex::decode("000200160100000b000000000001000100000030000001310042").unwrap();
    assert_eq!(pdu.len(), 26);
    let alarm = parse_alarm_notification(&pdu).expect("item-less alarm must parse");
    assert_eq!(alarm.alarm_type, 11);
    assert_eq!(alarm.alarm_sequence_number, 0x42);
    assert!(alarm.items.is_empty());
    assert!(alarm.raw_payload.is_empty());
}

#[test]
fn ethernet_padding_past_block_length_yields_no_phantom_items() {
    // Same PDU padded to the 60-byte Ethernet minimum. BlockLength bounds the
    // parse, so the padding must not surface as items with USI 0x0000.
    let mut pdu = hex::decode("000200160100000b000000000001000100000030000001310042").unwrap();
    pdu.resize(60, 0x00);
    let alarm = parse_alarm_notification(&pdu).expect("padded alarm must parse");
    assert!(alarm.items.is_empty(), "phantom items: {:?}", alarm.items);
    assert!(alarm.raw_payload.is_empty());
}

#[test]
fn alarm_item_insufficient_data_errors() {
    assert!(parse_alarm_item(&[], 0).is_err());
    assert!(parse_alarm_item(&[0x80], 0).is_err());
    // USI says maintenance but the body is truncated.
    assert!(parse_alarm_item(&[0x81, 0x00, 0x00], 0).is_err());
}

#[test]
fn channel_properties_reserved_values_fall_back() {
    use profinet_rs::diagnosis::{
        ChannelAccumulative, ChannelDirection, ChannelSpecifier, ChannelType,
    };
    // Accumulative 7 and specifier 7 are reserved -> reference defaults.
    let props = ChannelProperties::from_u16((7 << 2) | (7 << 8));
    assert_eq!(props.accumulative, ChannelAccumulative::No);
    assert_eq!(props.specifier, ChannelSpecifier::AllDisappears);
    assert_eq!(props.channel_type, ChannelType::Reserved);
    assert_eq!(props.direction, ChannelDirection::Manufacturer);

    let props = ChannelProperties::from_u16(0xFFFF);
    assert_eq!(props.channel_type, ChannelType::Submodule);
    assert_eq!(props.direction, ChannelDirection::Bidirectional);
    assert!(props.maintenance_required);
    assert!(props.maintenance_demanded);
}

#[test]
fn layer2_frame_filtering_rejects_foreign_frames() {
    let golden = golden();
    let mut frame = entry_bytes(&golden["layer2_inbound_alarm_frame"]);
    let device_mac: [u8; 6] = hex::decode("020000000002").unwrap().try_into().unwrap();

    // Too short.
    assert_eq!(check_layer2_frame(&frame[..15], &device_mac), None);
    // Wrong source MAC.
    assert_eq!(check_layer2_frame(&frame, &[0u8; 6]), None);
    // Wrong EtherType.
    let mut wrong_et = frame.clone();
    wrong_et[12] = 0x08;
    wrong_et[13] = 0x00;
    assert_eq!(check_layer2_frame(&wrong_et, &device_mac), None);
    // Non-alarm frame ID.
    frame[14] = 0x80;
    frame[15] = 0x00;
    assert_eq!(check_layer2_frame(&frame, &device_mac), None);
}

#[test]
fn layer2_frame_accepts_vlan_tag() {
    let golden = golden();
    let entry = &golden["layer2_inbound_alarm_frame"];
    let frame = entry_bytes(entry);
    let device_mac: [u8; 6] = hex::decode(str_of(entry, "device_mac"))
        .unwrap()
        .try_into()
        .unwrap();

    let (_, plain) = check_layer2_frame(&frame, &device_mac).expect("untagged accepted");
    let plain = plain.to_vec();

    // Insert an 802.1Q tag (TPID 0x8100 + 2-byte TCI) after the source MAC.
    let mut tagged = frame[..12].to_vec();
    tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x00]);
    tagged.extend_from_slice(&frame[12..]);

    let (_, payload) = check_layer2_frame(&tagged, &device_mac).expect("VLAN-tagged accepted");
    assert_eq!(
        payload,
        &plain[..],
        "VLAN tag must not change the RTA payload"
    );
}

#[test]
fn process_layer2_alarm_skips_non_data_pdu() {
    let golden = golden();
    let entry = &golden["layer2_inbound_alarm_frame"];
    let frame = entry_bytes(entry);
    let device_mac: [u8; 6] = hex::decode(str_of(entry, "device_mac"))
        .unwrap()
        .try_into()
        .unwrap();
    let controller_ref = u64_of(entry, "controller_ref") as u16;
    let (_, payload) = check_layer2_frame(&frame, &device_mac).expect("accepted");

    // The DATA PDU parses to an alarm...
    assert!(process_layer2_alarm(payload, controller_ref)
        .unwrap()
        .is_some());

    // ...but an ACK PDU (type nibble 0x03) has no notification body: skip it
    // rather than misparse whatever follows the RTA header.
    let mut ack = payload.to_vec();
    ack[4] = (RtaHeader::RTA_TYPE_ACK << 4) | RtaHeader::VERSION_1;
    assert_eq!(process_layer2_alarm(&ack, controller_ref).unwrap(), None);
}

// ---------------------------------------------------------------------------
// Live listener path (bench-only)
// ---------------------------------------------------------------------------

/// Live alarm reception needs an established AR with AlarmCR on a real
/// device plus capture privileges; exercised by the bench binary. Run with
/// PROFINET_IFACE / PROFINET_DEVICE_MAC set and --ignored to smoke-test
/// socket setup and clean shutdown.
#[test]
#[ignore]
fn live_alarm_listener_starts_and_stops() {
    let iface = std::env::var("PROFINET_IFACE").expect("PROFINET_IFACE");
    let mac_hex = std::env::var("PROFINET_DEVICE_MAC").expect("PROFINET_DEVICE_MAC");
    let device_mac: [u8; 6] = hex::decode(mac_hex.replace(':', ""))
        .expect("valid MAC")
        .try_into()
        .expect("6 bytes");

    let mut listener = AlarmListener::new(
        AlarmEndpoint {
            interface: iface,
            controller_ref: 1,
            device_ref: 42,
            device_mac,
            transport: 0,
            ..Default::default()
        },
        None,
    );
    listener.add_callback(|alarm| println!("alarm: {}", alarm.alarm_type_name()));
    listener.start().expect("listener start");
    assert!(listener.is_running());
    std::thread::sleep(std::time::Duration::from_millis(100));
    listener.stop();
    assert!(!listener.is_running());
}

// ---------------------------------------------------------------------------
// Ports of profinet-py tests/test_protocol.py RTA-header constant tests
// (TestPNRTAHeader; the alarm block type constants are already asserted in
// constants_match_indices_py above).
// ---------------------------------------------------------------------------

// TestPNRTAHeader::test_rta_type_constants + test_version_constants
#[test]
fn rta_header_constants() {
    use profinet_rs::alarm_listener::RtaHeader;
    assert_eq!(RtaHeader::RTA_TYPE_DATA, 0x01);
    assert_eq!(RtaHeader::RTA_TYPE_NACK, 0x02);
    assert_eq!(RtaHeader::RTA_TYPE_ACK, 0x03);
    assert_eq!(RtaHeader::RTA_TYPE_ERR, 0x04);
    assert_eq!(RtaHeader::VERSION_1, 0x01);
    assert_eq!(RtaHeader::VERSION_2, 0x02);
}
