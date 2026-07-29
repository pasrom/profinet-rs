//! Parity tests for vendors.rs (vendors.py), indices.rs (indices.py) and
//! errors.rs (exceptions.py).

use profinet_rs::errors::PnioError;
use profinet_rs::indices;
use profinet_rs::vendors::{get_vendor_name, lookup_vendor, PROFINET_VENDOR_MAP};

#[test]
fn vendor_known_ids() {
    assert_eq!(get_vendor_name(0x002A), "SIEMENS AG");
    assert_eq!(get_vendor_name(1), "Acromag");
    assert_eq!(get_vendor_name(42), "SIEMENS AG");
    assert_eq!(get_vendor_name(17), "Endress+Hauser");
    assert_eq!(get_vendor_name(0xFFFF), "IO-LINK Community");
    assert_eq!(
        get_vendor_name(61440),
        "PROFIBUS Nutzerorganisation e.V. / GSD"
    );
}

#[test]
fn vendor_unknown_fallback() {
    // 4 is absent from the registry
    assert_eq!(get_vendor_name(4), "Unknown (0x0004)");
    assert_eq!(lookup_vendor(4), None);
    assert_eq!(get_vendor_name(0xBEE7), "Unknown (0xBEE7)");
}

#[test]
fn vendor_table_full_and_sorted() {
    // Full table ported from vendors.py (2178 entries)
    assert_eq!(PROFINET_VENDOR_MAP.len(), 2178);
    // Sorted + unique so binary search is valid
    assert!(PROFINET_VENDOR_MAP.windows(2).all(|w| w[0].0 < w[1].0));
    assert_eq!(lookup_vendor(0x002A), Some("SIEMENS AG"));
}

#[test]
fn index_constant_values() {
    assert_eq!(indices::IM0, 0xAFF0);
    assert_eq!(indices::IM0_FILTER_DATA, 0xF840);
    assert_eq!(indices::PD_REAL_DATA, 0xF841);
    assert_eq!(indices::REAL_ID_SUBSLOT, 0x8001);
    assert_eq!(indices::DIAG_DEVICE, 0xF80C);
    assert_eq!(indices::MODULE_DIFF_BLOCK, 0xE002);
    assert_eq!(indices::WRITE_MULTIPLE, 0xE040);
    assert_eq!(indices::BLOCK_AR_REQ, 0x0101);
    assert_eq!(indices::BLOCK_MODULE_DIFF_BLOCK, 0x8104);
    assert_eq!(indices::CONTROL_CMD_APPLICATION_READY, 0x0002);
    assert_eq!(indices::SUBSLOT_INTERFACE, 0x8000);
}

#[test]
fn index_names_and_scopes() {
    assert_eq!(indices::get_block_type_name(0x0020), "I&M0");
    assert_eq!(indices::get_block_type_name(0x1234), "Unknown(0x1234)");
    assert_eq!(indices::get_alarm_type_name(0x0001), "Diagnosis");
    assert_eq!(indices::get_usi_name(0x8000), "ChannelDiagnosis");
    assert_eq!(
        indices::get_usi_name(0x1234),
        "ManufacturerSpecific(0x1234)"
    );
    assert_eq!(indices::get_usi_name(0x9001), "ProfileSpecific(0x9001)");
    assert_eq!(indices::get_index_name(0xAFF0), "I&M0");
    assert_eq!(indices::get_index_name(0xAFF7), "I&M7");
    assert_eq!(indices::get_index_name(0xF841), "PDRealData");
    assert_eq!(indices::get_index_name(0x1234), "User-specific (0x1234)");
    assert_eq!(indices::get_scope(0x1234), "user");
    assert_eq!(indices::get_scope(0x800A), "subslot");
    assert_eq!(indices::get_scope(0xAFF0), "slot");
    assert_eq!(indices::get_scope(0xE002), "ar");
    assert_eq!(indices::get_scope(0xF841), "device");
    assert_eq!(indices::all_standard_indices().len(), 41);
    assert_eq!(indices::get_pe_mode_name(0x05), "PE_EnergySavingMode_5");
    assert_eq!(indices::get_pe_mode_name(0xF0), "PE_Operate");
}

#[test]
fn pnio_error_from_args_status() {
    // Docstring example: wire bytes [0x01,0x40,0x81,0xDB] parsed big-endian as
    // 0x014081DB -> byte-swap -> 0xDB814001 = RMPM "Unknown blocks in request"
    let e = PnioError::from_args_status(0x014081DB);
    assert_eq!(e.error_code, 0xDB);
    assert_eq!(e.error_decode, PnioError::DECODE_PNIO);
    assert_eq!(e.error_code1, PnioError::CM_EC1_RMPM);
    assert_eq!(e.error_code2, PnioError::RMPM_UNKNOWN_BLOCKS);
    assert_eq!(e.message, "Unknown blocks in request");
}

#[test]
fn pnio_error_from_bytes_and_display() {
    // PNIORW invalid-index error
    let e = PnioError::from_bytes(&[0xDE, 0x80, 0xB0, 0x00]);
    assert_eq!(e.message, "Index not supported");
    assert!(!e.is_cm_error());
    assert_eq!(
        e.to_string(),
        "Index not supported [ErrorCode1=0xB0, ErrorCode2=0x00]"
    );

    // PNIO-CM error with block name in Display
    let cm = PnioError::from_codes(0xDB, PnioError::DECODE_PNIO_CM, 0x01, 0x02);
    assert!(cm.is_cm_error());
    assert_eq!(cm.block_name(), "ARBlockReq");
    assert_eq!(
        cm.to_string(),
        "Out of AR resources [CM:ARBlockReq, EC2=0x02]"
    );

    // Truncated input
    let short = PnioError::from_bytes(&[0x01, 0x02]);
    assert_eq!(short.message, "Incomplete error data");
}
