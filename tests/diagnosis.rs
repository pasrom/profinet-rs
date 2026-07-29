//! Ports of profinet-py tests/test_diagnosis.py against the Rust `diagnosis`
//! module. Python models Ext/Qualified channel diagnosis as subclasses of
//! ChannelDiagnosis; the Rust port flattens them into one `ChannelDiagnosis`
//! struct tagged by `DiagnosisKind`, so the isinstance() checks become kind
//! assertions and the subclass-default tests assert the flattened defaults.
//! The Python CHANNEL_ERROR_TYPES / EXT_CHANNEL_ERROR_TYPES_MAP dicts are not
//! exported by the Rust module (they back the decode_* functions), so their
//! membership tests are ported as decode-result assertions. The Python
//! package-import test (TestImportsFromModule) has no Rust equivalent and is
//! omitted.

use profinet_rs::diagnosis::{
    decode_channel_error_type, decode_ext_channel_error_type, parse_diagnosis_block,
    parse_diagnosis_simple, ChannelAccumulative, ChannelDiagnosis, ChannelDirection,
    ChannelProperties, ChannelSpecifier, ChannelType, DiagnosisData, DiagnosisKind,
    USI_CHANNEL_DIAGNOSIS, USI_EXT_CHANNEL_DIAGNOSIS, USI_MAINTENANCE, USI_MULTIPLE,
    USI_QUALIFIED_CHANNEL_DIAGNOSIS,
};

// --- TestUserStructureIdentifier ---------------------------------------------

#[test]
fn usi_channel_diagnosis_value() {
    assert_eq!(USI_CHANNEL_DIAGNOSIS, 0x8000);
}

#[test]
fn usi_ext_channel_diagnosis_value() {
    assert_eq!(USI_EXT_CHANNEL_DIAGNOSIS, 0x8002);
}

#[test]
fn usi_qualified_channel_diagnosis_value() {
    assert_eq!(USI_QUALIFIED_CHANNEL_DIAGNOSIS, 0x8003);
}

#[test]
fn usi_multiple_value() {
    assert_eq!(USI_MULTIPLE, 0x8001);
}

#[test]
fn usi_maintenance_value() {
    assert_eq!(USI_MAINTENANCE, 0x8100);
}

// --- TestChannelType ---------------------------------------------------------

#[test]
fn channel_type_reserved_value() {
    assert_eq!(ChannelType::Reserved as u16, 0);
}

#[test]
fn channel_type_specific_value() {
    assert_eq!(ChannelType::Specific as u16, 1);
}

#[test]
fn channel_type_all_value() {
    assert_eq!(ChannelType::All as u16, 2);
}

#[test]
fn channel_type_submodule_value() {
    assert_eq!(ChannelType::Submodule as u16, 3);
}

// --- TestChannelDirection ----------------------------------------------------

#[test]
fn channel_direction_manufacturer_value() {
    assert_eq!(ChannelDirection::Manufacturer as u16, 0);
}

#[test]
fn channel_direction_input_value() {
    assert_eq!(ChannelDirection::Input as u16, 1);
}

#[test]
fn channel_direction_output_value() {
    assert_eq!(ChannelDirection::Output as u16, 2);
}

#[test]
fn channel_direction_bidirectional_value() {
    assert_eq!(ChannelDirection::Bidirectional as u16, 3);
}

// --- TestChannelAccumulative -------------------------------------------------

#[test]
fn channel_accumulative_no_value() {
    assert_eq!(ChannelAccumulative::No as u16, 0);
}

#[test]
fn channel_accumulative_main_fault_value() {
    assert_eq!(ChannelAccumulative::MainFault as u16, 1);
}

#[test]
fn channel_accumulative_additional_fault_value() {
    assert_eq!(ChannelAccumulative::AdditionalFault as u16, 2);
}

// --- TestChannelSpecifier ----------------------------------------------------

#[test]
fn channel_specifier_all_disappears_value() {
    assert_eq!(ChannelSpecifier::AllDisappears as u16, 0);
}

#[test]
fn channel_specifier_appears_value() {
    assert_eq!(ChannelSpecifier::Appears as u16, 1);
}

#[test]
fn channel_specifier_disappears_value() {
    assert_eq!(ChannelSpecifier::Disappears as u16, 2);
}

#[test]
fn channel_specifier_disappears_other_value() {
    assert_eq!(ChannelSpecifier::DisappearsOther as u16, 3);
}

// --- TestChannelProperties ---------------------------------------------------

#[test]
fn props_default_values() {
    let props = ChannelProperties::default();
    assert_eq!(props.raw, 0);
    assert_eq!(props.channel_type, ChannelType::Reserved);
    assert_eq!(props.accumulative, ChannelAccumulative::No);
    assert!(!props.maintenance_required);
    assert!(!props.maintenance_demanded);
    assert_eq!(props.specifier, ChannelSpecifier::AllDisappears);
    assert_eq!(props.direction, ChannelDirection::Manufacturer);
}

#[test]
fn props_from_uint16_zero() {
    let props = ChannelProperties::from_u16(0x0000);
    assert_eq!(props.raw, 0);
    assert_eq!(props.channel_type, ChannelType::Reserved);
    assert_eq!(props.accumulative, ChannelAccumulative::No);
    assert!(!props.maintenance_required);
    assert!(!props.maintenance_demanded);
    assert_eq!(props.specifier, ChannelSpecifier::AllDisappears);
    assert_eq!(props.direction, ChannelDirection::Manufacturer);
}

#[test]
fn props_from_uint16_channel_type() {
    assert_eq!(
        ChannelProperties::from_u16(0x0001).channel_type,
        ChannelType::Specific
    );
    assert_eq!(
        ChannelProperties::from_u16(0x0002).channel_type,
        ChannelType::All
    );
    assert_eq!(
        ChannelProperties::from_u16(0x0003).channel_type,
        ChannelType::Submodule
    );
}

#[test]
fn props_from_uint16_accumulative() {
    assert_eq!(
        ChannelProperties::from_u16(0x0004).accumulative,
        ChannelAccumulative::MainFault
    );
    assert_eq!(
        ChannelProperties::from_u16(0x0008).accumulative,
        ChannelAccumulative::AdditionalFault
    );
}

#[test]
fn props_from_uint16_maintenance_required() {
    let props = ChannelProperties::from_u16(0x0020);
    assert!(props.maintenance_required);
    assert!(!props.maintenance_demanded);
}

#[test]
fn props_from_uint16_maintenance_demanded() {
    let props = ChannelProperties::from_u16(0x0040);
    assert!(!props.maintenance_required);
    assert!(props.maintenance_demanded);
}

#[test]
fn props_from_uint16_both_maintenance_flags() {
    let props = ChannelProperties::from_u16(0x0060);
    assert!(props.maintenance_required);
    assert!(props.maintenance_demanded);
}

#[test]
fn props_from_uint16_specifier() {
    assert_eq!(
        ChannelProperties::from_u16(0x0100).specifier,
        ChannelSpecifier::Appears
    );
    assert_eq!(
        ChannelProperties::from_u16(0x0200).specifier,
        ChannelSpecifier::Disappears
    );
}

#[test]
fn props_from_uint16_direction() {
    assert_eq!(
        ChannelProperties::from_u16(0x0800).direction,
        ChannelDirection::Input
    );
    assert_eq!(
        ChannelProperties::from_u16(0x1000).direction,
        ChannelDirection::Output
    );
    assert_eq!(
        ChannelProperties::from_u16(0x1800).direction,
        ChannelDirection::Bidirectional
    );
}

#[test]
fn props_from_uint16_complex_value() {
    // Specific channel, main fault, maintenance required, appears, output.
    let value = 0x0001 | 0x0004 | 0x0020 | 0x0100 | 0x1000; // 0x1125
    let props = ChannelProperties::from_u16(value);
    assert_eq!(props.channel_type, ChannelType::Specific);
    assert_eq!(props.accumulative, ChannelAccumulative::MainFault);
    assert!(props.maintenance_required);
    assert_eq!(props.specifier, ChannelSpecifier::Appears);
    assert_eq!(props.direction, ChannelDirection::Output);
}

// --- TestChannelDiagnosis ----------------------------------------------------

#[test]
fn channel_diag_default_values() {
    let diag = ChannelDiagnosis::default();
    assert_eq!(diag.api, 0);
    assert_eq!(diag.slot, 0);
    assert_eq!(diag.subslot, 0);
    assert_eq!(diag.channel_number, 0);
    assert_eq!(diag.error_type, 0);
    assert_eq!(diag.error_type_name, "");
    assert!(!diag.is_submodule_level());
}

#[test]
fn channel_diag_is_submodule_level() {
    let diag = ChannelDiagnosis {
        channel_number: 0x8000,
        ..Default::default()
    };
    assert!(diag.is_submodule_level());

    let diag = ChannelDiagnosis {
        channel_number: 0x0001,
        ..Default::default()
    };
    assert!(!diag.is_submodule_level());
}

#[test]
fn channel_diag_with_values() {
    let props = ChannelProperties {
        maintenance_required: true,
        ..Default::default()
    };
    let diag = ChannelDiagnosis {
        api: 0,
        slot: 1,
        subslot: 2,
        channel_number: 3,
        channel_properties: props,
        error_type: 0x0001,
        error_type_name: "Short circuit".to_string(),
        ..Default::default()
    };
    assert_eq!(diag.slot, 1);
    assert_eq!(diag.subslot, 2);
    assert_eq!(diag.channel_number, 3);
    assert_eq!(diag.error_type, 0x0001);
    assert_eq!(diag.error_type_name, "Short circuit");
    assert!(diag.channel_properties.maintenance_required);
}

// --- TestExtChannelDiagnosis -------------------------------------------------

#[test]
fn ext_diag_default_values() {
    // An Ext-kind entry's ext fields default to zero / empty.
    let diag = ChannelDiagnosis {
        kind: DiagnosisKind::Ext,
        ..Default::default()
    };
    assert_eq!(diag.ext_error_type, 0);
    assert_eq!(diag.ext_error_type_name, "");
    assert_eq!(diag.ext_add_value, 0);
}

#[test]
fn ext_diag_inherits_channel_diagnosis() {
    let diag = ChannelDiagnosis {
        kind: DiagnosisKind::Ext,
        slot: 1,
        channel_number: 2,
        error_type: 0x8000,
        ext_error_type: 0x8000,
        ..Default::default()
    };
    assert_eq!(diag.slot, 1);
    assert_eq!(diag.channel_number, 2);
    assert_eq!(diag.error_type, 0x8000);
    assert_eq!(diag.ext_error_type, 0x8000);
}

#[test]
fn ext_diag_with_full_values() {
    let diag = ChannelDiagnosis {
        kind: DiagnosisKind::Ext,
        api: 0,
        slot: 1,
        subslot: 2,
        channel_number: 3,
        error_type: 0x8000,
        error_type_name: "Data transmission impossible".to_string(),
        ext_error_type: 0x8000,
        ext_error_type_name: "Link state mismatch - Loss of link".to_string(),
        ext_add_value: 0x1234_5678,
        ..Default::default()
    };
    assert_eq!(diag.error_type_name, "Data transmission impossible");
    assert_eq!(
        diag.ext_error_type_name,
        "Link state mismatch - Loss of link"
    );
    assert_eq!(diag.ext_add_value, 0x1234_5678);
}

// --- TestQualifiedChannelDiagnosis -------------------------------------------

#[test]
fn qualified_diag_default_values() {
    let diag = ChannelDiagnosis {
        kind: DiagnosisKind::Qualified,
        ..Default::default()
    };
    assert_eq!(diag.qualifier, 0);
}

#[test]
fn qualified_diag_inherits_ext_channel_diagnosis() {
    let diag = ChannelDiagnosis {
        kind: DiagnosisKind::Qualified,
        slot: 1,
        ext_error_type: 0x8000,
        qualifier: 0xABCD,
        ..Default::default()
    };
    assert_eq!(diag.slot, 1);
    assert_eq!(diag.ext_error_type, 0x8000);
    assert_eq!(diag.qualifier, 0xABCD);
}

// --- TestDiagnosisData -------------------------------------------------------

#[test]
fn diag_data_default_values() {
    let data = DiagnosisData::default();
    assert_eq!(data.api, 0);
    assert_eq!(data.slot, 0);
    assert_eq!(data.subslot, 0);
    assert_eq!(data.entries, vec![]);
    assert_eq!(data.raw_data, Vec::<u8>::new());
    assert!(!data.has_errors());
    assert!(!data.has_maintenance_required());
    assert!(!data.has_maintenance_demanded());
}

#[test]
fn diag_data_has_errors() {
    let mut data = DiagnosisData::default();
    assert!(!data.has_errors());
    data.entries.push(ChannelDiagnosis::default());
    assert!(data.has_errors());
}

#[test]
fn diag_data_has_maintenance_required() {
    let mut data = DiagnosisData::default();
    data.entries.push(ChannelDiagnosis {
        channel_properties: ChannelProperties {
            maintenance_required: true,
            ..Default::default()
        },
        ..Default::default()
    });
    assert!(data.has_maintenance_required());
    assert!(!data.has_maintenance_demanded());
}

#[test]
fn diag_data_has_maintenance_demanded() {
    let mut data = DiagnosisData::default();
    data.entries.push(ChannelDiagnosis {
        channel_properties: ChannelProperties {
            maintenance_demanded: true,
            ..Default::default()
        },
        ..Default::default()
    });
    assert!(!data.has_maintenance_required());
    assert!(data.has_maintenance_demanded());
}

#[test]
fn diag_data_get_by_channel() {
    let mut data = DiagnosisData::default();
    data.entries.push(ChannelDiagnosis {
        channel_number: 1,
        ..Default::default()
    });
    data.entries.push(ChannelDiagnosis {
        channel_number: 2,
        ..Default::default()
    });
    data.entries.push(ChannelDiagnosis {
        channel_number: 1,
        ..Default::default()
    });
    assert_eq!(data.get_by_channel(1).len(), 2);
    assert_eq!(data.get_by_channel(2).len(), 1);
    assert_eq!(data.get_by_channel(3).len(), 0);
}

// --- TestDecodeChannelErrorType ----------------------------------------------

#[test]
fn decode_channel_standard_errors() {
    assert_eq!(decode_channel_error_type(0x0001), "Short circuit");
    assert_eq!(decode_channel_error_type(0x0002), "Undervoltage");
    assert_eq!(decode_channel_error_type(0x0003), "Overvoltage");
    assert_eq!(decode_channel_error_type(0x0004), "Overload");
    assert_eq!(decode_channel_error_type(0x0005), "Overtemperature");
    assert_eq!(decode_channel_error_type(0x0006), "Line break");
    assert_eq!(decode_channel_error_type(0x0009), "Error");
}

#[test]
fn decode_channel_network_errors() {
    assert_eq!(
        decode_channel_error_type(0x8000),
        "Data transmission impossible"
    );
    assert_eq!(decode_channel_error_type(0x8001), "Remote mismatch");
    assert_eq!(
        decode_channel_error_type(0x8002),
        "Media redundancy mismatch"
    );
    assert_eq!(decode_channel_error_type(0x8003), "Sync mismatch");
}

#[test]
fn decode_channel_reserved_errors() {
    assert!(decode_channel_error_type(0x0050).contains("Reserved"));
}

#[test]
fn decode_channel_manufacturer_specific() {
    assert!(decode_channel_error_type(0x0100).contains("Manufacturer-specific"));
    assert!(decode_channel_error_type(0x7FFF).contains("Manufacturer-specific"));
}

#[test]
fn decode_channel_profile_specific() {
    assert!(decode_channel_error_type(0x9000).contains("Profile-specific"));
}

#[test]
fn decode_channel_unknown() {
    assert!(decode_channel_error_type(0xFFFF).contains("Reserved"));
}

// --- TestDecodeExtChannelErrorType -------------------------------------------

#[test]
fn decode_ext_data_transmission_impossible() {
    assert!(decode_ext_channel_error_type(0x8000, 0x8000).contains("Loss of link"));
    assert!(decode_ext_channel_error_type(0x8000, 0x8001).contains("MAUType mismatch"));
    assert!(decode_ext_channel_error_type(0x8000, 0x8002).contains("Line delay mismatch"));
}

#[test]
fn decode_ext_remote_mismatch() {
    assert!(decode_ext_channel_error_type(0x8001, 0x8000).contains("Peer name of station mismatch"));
    assert!(decode_ext_channel_error_type(0x8001, 0x8005).contains("No peer detected"));
}

#[test]
fn decode_ext_media_redundancy_mismatch() {
    assert!(decode_ext_channel_error_type(0x8002, 0x8000).contains("Manager role fail"));
    assert!(decode_ext_channel_error_type(0x8002, 0x8003).contains("MRP ring open"));
}

#[test]
fn decode_ext_sync_mismatch() {
    assert!(decode_ext_channel_error_type(0x8003, 0x8000).contains("No sync message received"));
}

#[test]
fn decode_ext_manufacturer_specific() {
    assert!(decode_ext_channel_error_type(0x8000, 0x0100).contains("Manufacturer-specific"));
}

#[test]
fn decode_ext_accumulative_info() {
    assert!(decode_ext_channel_error_type(0x0001, 0x8000).contains("Accumulative info"));
}

// --- TestChannelErrorTypesConstant (ported as decode-result assertions) ------

#[test]
fn channel_error_types_contains_basic_errors() {
    // 0x0001 / 0x0006 / 0x0010 are defined, not fallback-decoded.
    assert_eq!(decode_channel_error_type(0x0001), "Short circuit");
    assert_eq!(decode_channel_error_type(0x0006), "Line break");
    assert_eq!(decode_channel_error_type(0x0010), "Parameterization fault");
}

#[test]
fn channel_error_types_contains_network_errors() {
    assert_eq!(
        decode_channel_error_type(0x8000),
        "Data transmission impossible"
    );
    assert_eq!(decode_channel_error_type(0x8001), "Remote mismatch");
    assert_eq!(
        decode_channel_error_type(0x8002),
        "Media redundancy mismatch"
    );
}

// --- TestExtChannelErrorTypesMap (ported as decode-result assertions) --------

#[test]
fn ext_error_types_map_contains_data_transmission_impossible() {
    assert_eq!(
        decode_ext_channel_error_type(0x8000, 0x8000),
        "Link state mismatch - Loss of link"
    );
}

#[test]
fn ext_error_types_map_contains_remote_mismatch() {
    assert_eq!(
        decode_ext_channel_error_type(0x8001, 0x8005),
        "No peer detected"
    );
}

#[test]
fn ext_error_types_map_contains_media_redundancy() {
    assert_eq!(
        decode_ext_channel_error_type(0x8002, 0x8000),
        "Manager role fail"
    );
}

// --- TestParseDiagnosisBlock -------------------------------------------------

#[test]
fn parse_block_empty_data() {
    assert_eq!(parse_diagnosis_block(b"", 0, 0, 0).entries, vec![]);
}

#[test]
fn parse_block_too_short_data() {
    assert_eq!(
        parse_diagnosis_block(b"\x00\x01\x02", 0, 0, 0).entries,
        vec![]
    );
}

#[test]
fn parse_block_stores_raw_data() {
    let data = b"\x00\x01\x02\x03\x04\x05";
    assert_eq!(parse_diagnosis_block(data, 0, 0, 0).raw_data, data);
}

#[test]
fn parse_block_api_slot_subslot_preserved() {
    let result = parse_diagnosis_block(&[0u8; 10], 1, 2, 3);
    assert_eq!(result.api, 1);
    assert_eq!(result.slot, 2);
    assert_eq!(result.subslot, 3);
}

#[test]
fn parse_block_channel_diagnosis() {
    // BlockHeader(6) + ChannelNumber + ChannelProperties + USI + ChannelErrorType.
    let data = b"\x00\x10\x00\x08\x01\x00\x00\x01\x00\x00\x80\x00\x00\x01";
    let result = parse_diagnosis_block(data, 0, 0, 0);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].channel_number, 1);
    assert_eq!(result.entries[0].error_type, 0x0001);
    assert_eq!(result.entries[0].error_type_name, "Short circuit");
}

#[test]
fn parse_block_ext_channel_diagnosis() {
    let data = b"\x00\x10\x00\x10\x01\x00\x00\x02\x00\x20\x80\x02\x80\x00\x80\x00\x12\x34\x56\x78";
    let result = parse_diagnosis_block(data, 0, 0, 0);
    assert_eq!(result.entries.len(), 1);
    let entry = &result.entries[0];
    assert_eq!(entry.kind, DiagnosisKind::Ext);
    assert_eq!(entry.channel_number, 2);
    assert!(entry.channel_properties.maintenance_required);
    assert_eq!(entry.error_type, 0x8000);
    assert_eq!(entry.ext_error_type, 0x8000);
    assert_eq!(entry.ext_add_value, 0x1234_5678);
}

#[test]
fn parse_block_qualified_channel_diagnosis() {
    let data = b"\x00\x10\x00\x14\x01\x00\x00\x03\x00\x00\x80\x03\x80\x01\x80\x05\x00\x00\x00\x01\xab\xcd\xef\x01";
    let result = parse_diagnosis_block(data, 0, 0, 0);
    assert_eq!(result.entries.len(), 1);
    let entry = &result.entries[0];
    assert_eq!(entry.kind, DiagnosisKind::Qualified);
    assert_eq!(entry.channel_number, 3);
    assert_eq!(entry.error_type, 0x8001);
    assert_eq!(entry.ext_error_type, 0x8005);
    assert_eq!(entry.qualifier, 0xABCD_EF01);
}

// --- TestParseDiagnosisSimple ------------------------------------------------

#[test]
fn parse_simple_empty_data() {
    assert_eq!(parse_diagnosis_simple(b"", 0, 0, 0).entries, vec![]);
}

#[test]
fn parse_simple_too_short_data() {
    assert_eq!(
        parse_diagnosis_simple(b"\x00\x01\x02", 0, 0, 0).entries,
        vec![]
    );
}

#[test]
fn parse_simple_entry() {
    // BlockHeader(6) + ChannelNumber + ChannelProperties + ChannelErrorType.
    let data = b"\x00\x10\x00\x06\x01\x00\x00\x01\x00\x00\x00\x06";
    let result = parse_diagnosis_simple(data, 0, 0, 0);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].channel_number, 1);
    assert_eq!(result.entries[0].error_type, 0x0006);
    assert_eq!(result.entries[0].error_type_name, "Line break");
}

#[test]
fn parse_simple_multiple_entries() {
    let data = b"\x00\x10\x00\x0c\x01\x00\x00\x01\x00\x00\x00\x01\x00\x02\x00\x20\x00\x06";
    let result = parse_diagnosis_simple(data, 0, 0, 0);
    assert_eq!(result.entries.len(), 2);
    assert_eq!(result.entries[0].channel_number, 1);
    assert_eq!(result.entries[0].error_type, 0x0001);
    assert_eq!(result.entries[1].channel_number, 2);
    assert_eq!(result.entries[1].error_type, 0x0006);
    assert!(result.entries[1].channel_properties.maintenance_required);
}

#[test]
fn parse_simple_stops_at_zero_entry() {
    // A fully zero entry ends the walk; the trailing entry is not parsed.
    let data = b"\x00\x10\x00\x12\x01\x00\
                 \x00\x01\x00\x00\x00\x01\
                 \x00\x00\x00\x00\x00\x00\
                 \x00\x02\x00\x00\x00\x06";
    let result = parse_diagnosis_simple(data, 0, 0, 0);
    assert_eq!(result.entries.len(), 1);
}
