//! Ports of profinet-py tests/test_exceptions.py against the Rust `errors`
//! module.
//!
//! Nineteen Python tests exercise the exception CLASS hierarchy and have no
//! Rust equivalent: the reference's ProfinetError subclass tree
//! (DCP/RPC/Validation/Socket errors, RPCFaultError) is a Python-only
//! `issubclass`/`raise`/`except` mechanism, whereas the Rust port uses
//! `Result<_, String>` plus the flat `ProfinetError` enum. The omitted groups
//! are TestExceptionHierarchy (12 subclass checks), TestRPCFaultError (3:
//! fault_code default/custom, message), TestExceptionCatching (3: catch
//! base/DCP/RPC variants), and test_pnio_error_inherits_rpc_error. The
//! remaining ten TestPNIOError tests map to the `PnioError` struct and are
//! ported below.

use profinet_rs::errors::PnioError;

/// PnioError carrying a message with the given error codes (the reference's
/// `PNIOError(message, error_code=..., ...)` constructor).
fn pnio(
    message: &str,
    error_code: u8,
    error_decode: u8,
    error_code1: u8,
    error_code2: u8,
) -> PnioError {
    PnioError {
        message: message.to_string(),
        error_code,
        error_decode,
        error_code1,
        error_code2,
    }
}

#[test]
fn pnio_default_values() {
    let error = pnio("test error", 0, 0, 0, 0);
    assert_eq!(error.error_code, 0);
    assert_eq!(error.error_decode, 0);
    assert_eq!(error.error_code1, 0);
    assert_eq!(error.error_code2, 0);
}

#[test]
fn pnio_custom_values() {
    let error = pnio("test", 0xDE, 0x80, 0xB2, 0x07);
    assert_eq!(error.error_code, 0xDE);
    assert_eq!(error.error_decode, 0x80);
    assert_eq!(error.error_code1, 0xB2);
    assert_eq!(error.error_code2, 0x07);
}

#[test]
fn pnio_from_args_status_invalid_slot() {
    // Wire [0x07,0xB2,0x80,0xDE] parsed big-endian 0x07B280DE, byte-swapped to
    // ErrorCode=0xDE, ErrorDecode=0x80, ErrorCode1=0xB2, ErrorCode2=0x07.
    let error = PnioError::from_args_status(0x07B280DE);
    assert_eq!(error.error_code, 0xDE);
    assert_eq!(error.error_decode, 0x80);
    assert_eq!(error.error_code1, 0xB2);
    assert_eq!(error.error_code2, 0x07);
    assert!(error.to_string().contains("Invalid slot"), "got {error}");
}

#[test]
fn pnio_from_args_status_invalid_subslot() {
    let error = PnioError::from_args_status(0x08B280DE);
    assert_eq!(error.error_code, 0xDE);
    assert_eq!(error.error_decode, 0x80);
    assert_eq!(error.error_code1, 0xB2);
    assert_eq!(error.error_code2, 0x08);
    assert!(error.to_string().contains("Invalid subslot"), "got {error}");
}

#[test]
fn pnio_from_args_status_invalid_index() {
    let error = PnioError::from_args_status(0x00B080DE);
    assert_eq!(error.error_code, 0xDE);
    assert_eq!(error.error_decode, 0x80);
    assert_eq!(error.error_code1, 0xB0);
    assert_eq!(error.error_code2, 0x00);
    assert!(
        error.to_string().contains("Index not supported"),
        "got {error}"
    );
}

#[test]
fn pnio_from_args_status_invalid_api() {
    let error = PnioError::from_args_status(0x06B480DE);
    assert_eq!(error.error_code, 0xDE);
    assert_eq!(error.error_decode, 0x80);
    assert_eq!(error.error_code1, 0xB4);
    assert_eq!(error.error_code2, 0x06);
    assert!(error.to_string().contains("Invalid API"), "got {error}");
}

#[test]
fn pnio_from_args_status_rmpm_error() {
    let error = PnioError::from_args_status(0x014081DB);
    assert_eq!(error.error_code, 0xDB); // IODConnectRes
    assert_eq!(error.error_decode, 0x81); // PNIO
    assert_eq!(error.error_code1, 0x40); // RMPM
    assert_eq!(error.error_code2, 0x01); // Unknown blocks
    assert!(error.to_string().contains("Unknown blocks"), "got {error}");
}

#[test]
fn pnio_from_args_status_unknown_error() {
    let error = PnioError::from_args_status(0xFFB280DE);
    assert_eq!(error.error_code, 0xDE);
    assert_eq!(error.error_code2, 0xFF);
    assert!(error.to_string().contains("Unknown"), "got {error}");
}

#[test]
fn pnio_str_format() {
    let error = pnio("Test message", 0, 0, 0xB2, 0x07);
    let result = error.to_string();
    assert!(result.contains("Test message"), "got {result}");
    assert!(result.contains("0xB2"), "got {result}");
    assert!(result.contains("0x07"), "got {result}");
}

#[test]
fn pnio_error_constants() {
    assert_eq!(PnioError::PNIO_ERROR, 0xDE);
    assert_eq!(PnioError::EC1_INVALID_INDEX, 0xB0);
    assert_eq!(PnioError::EC1_RESOURCE, 0xB2);
    assert_eq!(PnioError::EC1_APPLICATION, 0xB4);
    assert_eq!(PnioError::EC2_INVALID_SLOT, 0x07);
    assert_eq!(PnioError::EC2_INVALID_SUBSLOT, 0x08);
    assert_eq!(PnioError::EC2_INVALID_API, 0x06);
}
