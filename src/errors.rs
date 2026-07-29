//! PROFINET error hierarchy.
//!
//! Ported from `profinet/exceptions.py`. Python's exception subclass tree is
//! flattened into the [`ProfinetError`] enum; `PNIOError` (with its error-code
//! constants and message tables) becomes the [`PnioError`] struct.
//!
//! NOTE: existing modules still use `Result<_, String>` and have NOT been
//! refactored to this type — it is provided for parity and for new code.
//! `impl From<ProfinetError> for String` exists so it can flow into the old
//! call sites where convenient.

use std::fmt;

// =============================================================================
// PNIOError constants (associated consts on PnioError in Python's class body)
// =============================================================================

/// PNIO application error with error codes.
///
/// Error code structure (4 bytes):
///     Byte 0: ErrorCode (0x01=App, 0xCF=RTA, 0xDA=AlarmAck, 0xDB=IODConn, etc.)
///     Byte 1: ErrorDecode (0x40=PNIO-CM, 0x80=PNIORW, 0x81=PNIO)
///     Byte 2: ErrorCode1 (category/block type)
///     Byte 3: ErrorCode2 (specific error)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PnioError {
    pub message: String,
    pub error_code: u8,
    pub error_decode: u8,
    pub error_code1: u8,
    pub error_code2: u8,
}

impl PnioError {
    // ErrorDecode values
    /// Connection Management errors
    pub const DECODE_PNIO_CM: u8 = 0x40;
    /// Read/Write errors
    pub const DECODE_PNIORW: u8 = 0x80;
    /// General PNIO errors
    pub const DECODE_PNIO: u8 = 0x81;

    // ErrorCode values
    pub const PNIO_ERROR: u8 = 0xDE;
    /// Application error
    pub const ERROR_APP: u8 = 0x01;
    /// RTA error
    pub const ERROR_RTA: u8 = 0xCF;
    /// Alarm Ack error
    pub const ERROR_ALARM_ACK: u8 = 0xDA;
    /// IOD Connect error
    pub const ERROR_IOD_CONN: u8 = 0xDB;
    /// IOD Release error
    pub const ERROR_IOD_REL: u8 = 0xDC;
    /// IOD Control error
    pub const ERROR_IOD_CTRL: u8 = 0xDD;
    /// IOD Read/Write error
    pub const ERROR_IOD_RW: u8 = 0xDE;
    /// MPM error
    pub const ERROR_MPM: u8 = 0xDF;

    // ErrorCode1 categories for PNIORW (ErrorDecode=0x80) per IEC 61158-6
    /// Invalid index
    pub const EC1_INVALID_INDEX: u8 = 0xB0;
    /// Write length error
    pub const EC1_WRITE_LENGTH: u8 = 0xB1;
    /// Slot/Subslot errors
    pub const EC1_RESOURCE: u8 = 0xB2;
    /// Access errors
    pub const EC1_ACCESS: u8 = 0xB3;
    /// API errors
    pub const EC1_APPLICATION: u8 = 0xB4;
    pub const EC1_USER_SPECIFIC_1: u8 = 0xB5;
    pub const EC1_USER_SPECIFIC_2: u8 = 0xB6;
    pub const EC1_USER_SPECIFIC_3: u8 = 0xB7;
    pub const EC1_USER_SPECIFIC_4: u8 = 0xB8;
    pub const EC1_USER_SPECIFIC_5: u8 = 0xB9;

    // ErrorCode2 for EC1_INVALID_INDEX (0xB0)
    pub const EC2_INDEX_UNSUPPORTED: u8 = 0x00;
    /// Index exists but not written yet
    pub const EC2_INDEX_NOT_WRITTEN: u8 = 0x05;

    // ErrorCode2 for EC1_WRITE_LENGTH (0xB1)
    pub const EC2_WRITE_LENGTH_ERROR: u8 = 0x00;
    pub const EC2_WRITE_TOO_SHORT: u8 = 0x01;
    pub const EC2_WRITE_TOO_LONG: u8 = 0x02;
    /// Write protected
    pub const EC2_WRITE_ACCESS_DENIED: u8 = 0x03;

    // ErrorCode2 for EC1_RESOURCE (0xB2)
    pub const EC2_INVALID_SLOT: u8 = 0x07;
    pub const EC2_INVALID_SUBSLOT: u8 = 0x08;
    /// No data for this module
    pub const EC2_MODULE_NO_DATA: u8 = 0x09;

    // ErrorCode2 for EC1_ACCESS (0xB3)
    pub const EC2_ACCESS_INVALID_AREA: u8 = 0x00;
    pub const EC2_ACCESS_DENIED: u8 = 0x03;
    pub const EC2_ACCESS_INVALID_RANGE: u8 = 0x04;
    pub const EC2_ACCESS_INVALID_STATE: u8 = 0x05;
    pub const EC2_ACCESS_DENIED_LOCAL: u8 = 0x06;

    // ErrorCode2 for EC1_APPLICATION (0xB4)
    pub const EC2_READ_ERROR: u8 = 0x00;
    pub const EC2_WRITE_ERROR: u8 = 0x01;
    pub const EC2_MODULE_FAILURE: u8 = 0x02;
    pub const EC2_BUSY: u8 = 0x04;
    pub const EC2_VERSION_CONFLICT: u8 = 0x05;
    pub const EC2_INVALID_API: u8 = 0x06;
    pub const EC2_NOT_BACKUP_ALLOWED: u8 = 0x07;
    pub const EC2_ALARM_PENDING: u8 = 0x08;

    // PNIO-CM ErrorCode1 values (block type references)
    // Request blocks (0x01-0x0F)
    /// ARBlockReq error
    pub const CM_EC1_AR: u8 = 0x01;
    /// IOCRBlockReq error
    pub const CM_EC1_IOCR: u8 = 0x02;
    /// AlarmCRBlockReq error
    pub const CM_EC1_ALARM_CR: u8 = 0x03;
    /// ExpectedSubmoduleBlockReq error
    pub const CM_EC1_EXPECTED_SUBMOD: u8 = 0x04;
    /// ModuleDiffBlock error
    pub const CM_EC1_MODULE_DIFF: u8 = 0x05;
    /// AR-RPC error
    pub const CM_EC1_AR_RPC: u8 = 0x06;
    // Response blocks (0x81-0x8F = 0x80 | request type)
    /// ARBlockRes error
    pub const CM_EC1_AR_RES: u8 = 0x81;
    /// IOCRBlockRes error
    pub const CM_EC1_IOCR_RES: u8 = 0x82;
    /// AlarmCRBlockRes error
    pub const CM_EC1_ALARM_CR_RES: u8 = 0x83;
    /// ModuleDiffBlockRes error
    pub const CM_EC1_MODULE_DIFF_RES: u8 = 0x84;
    // CM internal
    /// Parameter server errors
    pub const CM_EC1_PRM_SERVER: u8 = 0x3D;
    /// CM Controller errors
    pub const CM_EC1_CMCTL: u8 = 0x3E;
    /// CM Device errors
    pub const CM_EC1_CMDEV: u8 = 0x3F;
    /// Remote Protocol Machine errors
    pub const CM_EC1_RMPM: u8 = 0x40;
    /// Faulty record
    pub const CM_EC1_FAULTY_RECORD: u8 = 0xFD;
    /// Faulty AR block
    pub const CM_EC1_FAULTY_AR: u8 = 0xFE;
    /// Faulty block (general)
    pub const CM_EC1_FAULTY_BLOCK: u8 = 0xFF;

    // PNIO ErrorCode2 values for RMPM (CM_EC1_RMPM = 0x40)
    /// Invalid argument length
    pub const RMPM_ARGS_LEN_INVALID: u8 = 0x00;
    /// Unknown blocks in request
    pub const RMPM_UNKNOWN_BLOCKS: u8 = 0x01;
    /// Required IOCR missing
    pub const RMPM_IOCR_MISSING: u8 = 0x02;
    /// Wrong AlarmCR block count
    pub const RMPM_WRONG_ALCR_COUNT: u8 = 0x03;
    /// Out of AR resources
    pub const RMPM_OUT_OF_AR_RESOURCES: u8 = 0x04;

    // PNIO-CM ErrorCode2 values for AR (CM_EC1_AR = 0x01)
    pub const CM_AR_INVALID_TYPE: u8 = 0x00;
    pub const CM_AR_ALREADY_ACTIVE: u8 = 0x01;
    pub const CM_AR_OUT_OF_AR: u8 = 0x02;
    pub const CM_AR_OUT_OF_PROVIDER: u8 = 0x03;
    pub const CM_AR_OUT_OF_CONSUMER: u8 = 0x04;
    pub const CM_AR_OUT_OF_ALARM: u8 = 0x05;
    pub const CM_AR_OUT_OF_MEMORY: u8 = 0x06;
    pub const CM_AR_INVALID_SESSION: u8 = 0x07;
    pub const CM_AR_UUID_CONFLICT: u8 = 0x08;

    // PNIO-CM ErrorCode2 values for IOCR (CM_EC1_IOCR = 0x02)
    pub const CM_IOCR_INVALID_TYPE: u8 = 0x00;
    pub const CM_IOCR_OUT_OF_RESOURCES: u8 = 0x01;
    pub const CM_IOCR_INVALID_FRAME_ID: u8 = 0x02;
    pub const CM_IOCR_INVALID_RT_CLASS: u8 = 0x03;
    pub const CM_IOCR_INVALID_DATA_LEN: u8 = 0x04;
    pub const CM_IOCR_CYCLE_CONFLICT: u8 = 0x05;
    pub const CM_IOCR_WATCHDOG_ERR: u8 = 0x06;

    // PNIO-CM ErrorCode2 values for ExpectedSubmodule (CM_EC1_EXPECTED_SUBMOD = 0x04)
    pub const CM_SUBMOD_INVALID_SLOT: u8 = 0x00;
    pub const CM_SUBMOD_INVALID_SUBSLOT: u8 = 0x01;
    pub const CM_SUBMOD_WRONG_MODULE: u8 = 0x02;
    pub const CM_SUBMOD_WRONG_SUBMOD: u8 = 0x03;
    pub const CM_SUBMOD_IO_LEN_MISMATCH: u8 = 0x04;

    // PNIO-CM ErrorCode2 values for CMDEV (CM_EC1_CMDEV = 0x3F)
    pub const CM_DEV_STATE_CONFLICT: u8 = 0x00;
    pub const CM_DEV_CONNECT_RESOURCE: u8 = 0x01;
    pub const CM_DEV_ALREADY_OWNED: u8 = 0x02;
    pub const CM_DEV_AR_SET_ABORT: u8 = 0x03;

    /// Human-readable error messages for PNIORW (ErrorDecode=0x80),
    /// keyed by (ErrorCode1, ErrorCode2).
    pub const PNIORW_ERROR_MESSAGES: [((u8, u8), &'static str); 23] = [
        // EC1=0xB0 Invalid Index
        ((Self::EC1_INVALID_INDEX, 0x00), "Index not supported"),
        (
            (Self::EC1_INVALID_INDEX, 0x05),
            "Index exists but not written",
        ),
        // EC1=0xB1 Write Length
        ((Self::EC1_WRITE_LENGTH, 0x00), "Write length error"),
        ((Self::EC1_WRITE_LENGTH, 0x01), "Write data too short"),
        ((Self::EC1_WRITE_LENGTH, 0x02), "Write data too long"),
        (
            (Self::EC1_WRITE_LENGTH, 0x03),
            "Write access denied (write protected)",
        ),
        // EC1=0xB2 Resource
        ((Self::EC1_RESOURCE, 0x00), "Resource not available"),
        (
            (Self::EC1_RESOURCE, Self::EC2_INVALID_SLOT),
            "Invalid slot number",
        ),
        (
            (Self::EC1_RESOURCE, Self::EC2_INVALID_SUBSLOT),
            "Invalid subslot number",
        ),
        (
            (Self::EC1_RESOURCE, Self::EC2_MODULE_NO_DATA),
            "Module has no data",
        ),
        // EC1=0xB3 Access
        ((Self::EC1_ACCESS, 0x00), "Access denied (invalid area)"),
        ((Self::EC1_ACCESS, 0x03), "Access denied"),
        ((Self::EC1_ACCESS, 0x04), "Access denied (invalid range)"),
        (
            (Self::EC1_ACCESS, 0x05),
            "Access denied (invalid state for access)",
        ),
        ((Self::EC1_ACCESS, 0x06), "Access denied (local control)"),
        // EC1=0xB4 Application
        ((Self::EC1_APPLICATION, 0x00), "Read error"),
        ((Self::EC1_APPLICATION, 0x01), "Write error"),
        ((Self::EC1_APPLICATION, 0x02), "Module failure"),
        ((Self::EC1_APPLICATION, 0x04), "Resource busy"),
        ((Self::EC1_APPLICATION, 0x05), "Version conflict"),
        (
            (Self::EC1_APPLICATION, Self::EC2_INVALID_API),
            "Invalid API number",
        ),
        ((Self::EC1_APPLICATION, 0x07), "Backup not allowed"),
        ((Self::EC1_APPLICATION, 0x08), "Alarm pending"),
    ];

    /// Human-readable error messages for PNIO (ErrorDecode=0x81).
    /// Includes RMPM (Remote Protocol Machine) errors.
    pub const PNIO_ERROR_MESSAGES: [((u8, u8), &'static str); 6] = [
        // RMPM errors (EC1=0x40)
        (
            (Self::CM_EC1_RMPM, Self::RMPM_ARGS_LEN_INVALID),
            "Invalid arguments length",
        ),
        (
            (Self::CM_EC1_RMPM, Self::RMPM_UNKNOWN_BLOCKS),
            "Unknown blocks in request",
        ),
        (
            (Self::CM_EC1_RMPM, Self::RMPM_IOCR_MISSING),
            "Required IOCR block missing",
        ),
        (
            (Self::CM_EC1_RMPM, Self::RMPM_WRONG_ALCR_COUNT),
            "Wrong AlarmCR block count",
        ),
        (
            (Self::CM_EC1_RMPM, Self::RMPM_OUT_OF_AR_RESOURCES),
            "Out of AR resources",
        ),
        // CMDEV errors (EC1=0x3D) when ErrorDecode=0x81
        (
            (Self::CM_EC1_PRM_SERVER, 0x00),
            "Parameter server state conflict",
        ),
    ];

    /// Human-readable error messages for PNIO-CM (ErrorDecode=0x40).
    pub const PNIOCM_ERROR_MESSAGES: [((u8, u8), &'static str); 46] = [
        // AR Request errors (EC1=0x01)
        (
            (Self::CM_EC1_AR, Self::CM_AR_INVALID_TYPE),
            "Invalid AR type",
        ),
        (
            (Self::CM_EC1_AR, Self::CM_AR_ALREADY_ACTIVE),
            "AR already active",
        ),
        (
            (Self::CM_EC1_AR, Self::CM_AR_OUT_OF_AR),
            "Out of AR resources",
        ),
        (
            (Self::CM_EC1_AR, Self::CM_AR_OUT_OF_PROVIDER),
            "Out of provider resources",
        ),
        (
            (Self::CM_EC1_AR, Self::CM_AR_OUT_OF_CONSUMER),
            "Out of consumer resources",
        ),
        (
            (Self::CM_EC1_AR, Self::CM_AR_OUT_OF_ALARM),
            "Out of alarm resources",
        ),
        (
            (Self::CM_EC1_AR, Self::CM_AR_OUT_OF_MEMORY),
            "Out of memory",
        ),
        (
            (Self::CM_EC1_AR, Self::CM_AR_INVALID_SESSION),
            "Invalid session key",
        ),
        (
            (Self::CM_EC1_AR, Self::CM_AR_UUID_CONFLICT),
            "AR UUID conflict",
        ),
        // AR Response errors (EC1=0x81) - same error codes, response context
        (
            (Self::CM_EC1_AR_RES, Self::CM_AR_INVALID_TYPE),
            "Invalid AR type (in response)",
        ),
        (
            (Self::CM_EC1_AR_RES, Self::CM_AR_ALREADY_ACTIVE),
            "AR already active",
        ),
        (
            (Self::CM_EC1_AR_RES, Self::CM_AR_OUT_OF_AR),
            "Out of AR resources",
        ),
        (
            (Self::CM_EC1_AR_RES, Self::CM_AR_OUT_OF_PROVIDER),
            "Out of provider resources",
        ),
        (
            (Self::CM_EC1_AR_RES, Self::CM_AR_OUT_OF_CONSUMER),
            "Out of consumer resources",
        ),
        (
            (Self::CM_EC1_AR_RES, Self::CM_AR_OUT_OF_ALARM),
            "Out of alarm resources",
        ),
        (
            (Self::CM_EC1_AR_RES, Self::CM_AR_OUT_OF_MEMORY),
            "Out of memory",
        ),
        (
            (Self::CM_EC1_AR_RES, Self::CM_AR_INVALID_SESSION),
            "Invalid session key",
        ),
        (
            (Self::CM_EC1_AR_RES, Self::CM_AR_UUID_CONFLICT),
            "AR UUID conflict",
        ),
        // IOCR Request errors (EC1=0x02)
        (
            (Self::CM_EC1_IOCR, Self::CM_IOCR_INVALID_TYPE),
            "Invalid IOCR type",
        ),
        (
            (Self::CM_EC1_IOCR, Self::CM_IOCR_OUT_OF_RESOURCES),
            "Out of IOCR resources",
        ),
        (
            (Self::CM_EC1_IOCR, Self::CM_IOCR_INVALID_FRAME_ID),
            "Invalid frame ID",
        ),
        (
            (Self::CM_EC1_IOCR, Self::CM_IOCR_INVALID_RT_CLASS),
            "Invalid RT class",
        ),
        (
            (Self::CM_EC1_IOCR, Self::CM_IOCR_INVALID_DATA_LEN),
            "Invalid IO data length",
        ),
        (
            (Self::CM_EC1_IOCR, Self::CM_IOCR_CYCLE_CONFLICT),
            "Cycle time conflict",
        ),
        (
            (Self::CM_EC1_IOCR, Self::CM_IOCR_WATCHDOG_ERR),
            "Watchdog configuration error",
        ),
        // IOCR Response errors (EC1=0x82)
        (
            (Self::CM_EC1_IOCR_RES, Self::CM_IOCR_INVALID_TYPE),
            "Invalid IOCR type (in response)",
        ),
        (
            (Self::CM_EC1_IOCR_RES, Self::CM_IOCR_OUT_OF_RESOURCES),
            "Out of IOCR resources",
        ),
        (
            (Self::CM_EC1_IOCR_RES, Self::CM_IOCR_INVALID_FRAME_ID),
            "Invalid frame ID",
        ),
        (
            (Self::CM_EC1_IOCR_RES, Self::CM_IOCR_INVALID_RT_CLASS),
            "Invalid RT class",
        ),
        (
            (Self::CM_EC1_IOCR_RES, Self::CM_IOCR_INVALID_DATA_LEN),
            "Invalid IO data length",
        ),
        (
            (Self::CM_EC1_IOCR_RES, Self::CM_IOCR_CYCLE_CONFLICT),
            "Cycle time conflict",
        ),
        (
            (Self::CM_EC1_IOCR_RES, Self::CM_IOCR_WATCHDOG_ERR),
            "Watchdog configuration error",
        ),
        // AlarmCR errors (EC1=0x03)
        ((Self::CM_EC1_ALARM_CR, 0x00), "Invalid AlarmCR type"),
        ((Self::CM_EC1_ALARM_CR, 0x01), "Out of AlarmCR resources"),
        (
            (Self::CM_EC1_ALARM_CR_RES, 0x00),
            "Invalid AlarmCR type (in response)",
        ),
        (
            (Self::CM_EC1_ALARM_CR_RES, 0x01),
            "Out of AlarmCR resources",
        ),
        // ExpectedSubmodule errors (EC1=0x04) — see EXPECTED_SUBMOD_MESSAGES
        (
            (Self::CM_EC1_EXPECTED_SUBMOD, Self::CM_SUBMOD_INVALID_SLOT),
            "Invalid slot in ExpectedSubmodule",
        ),
        (
            (
                Self::CM_EC1_EXPECTED_SUBMOD,
                Self::CM_SUBMOD_INVALID_SUBSLOT,
            ),
            "Invalid subslot in ExpectedSubmodule",
        ),
        (
            (Self::CM_EC1_EXPECTED_SUBMOD, Self::CM_SUBMOD_WRONG_MODULE),
            "Wrong module ident number",
        ),
        (
            (Self::CM_EC1_EXPECTED_SUBMOD, Self::CM_SUBMOD_WRONG_SUBMOD),
            "Wrong submodule ident number",
        ),
        (
            (
                Self::CM_EC1_EXPECTED_SUBMOD,
                Self::CM_SUBMOD_IO_LEN_MISMATCH,
            ),
            "IO data length mismatch",
        ),
        // CMDEV errors (EC1=0x3F)
        (
            (Self::CM_EC1_CMDEV, Self::CM_DEV_STATE_CONFLICT),
            "Device state conflict (AR may be active)",
        ),
        (
            (Self::CM_EC1_CMDEV, Self::CM_DEV_CONNECT_RESOURCE),
            "Connect resource unavailable",
        ),
        (
            (Self::CM_EC1_CMDEV, Self::CM_DEV_ALREADY_OWNED),
            "Device already owned by another controller",
        ),
        (
            (Self::CM_EC1_CMDEV, Self::CM_DEV_AR_SET_ABORT),
            "AR set aborted",
        ),
        // Faulty block errors (EC1=0xFF)
        ((Self::CM_EC1_FAULTY_BLOCK, 0x00), "Faulty block structure"),
    ];

    /// Block type names for PNIO-CM (request and response blocks).
    pub const CM_BLOCK_NAMES: [(u8, &'static str); 23] = [
        // Request blocks (0x01-0x0F)
        (0x01, "ARBlockReq"),
        (0x02, "IOCRBlockReq"),
        (0x03, "AlarmCRBlockReq"),
        (0x04, "ExpectedSubmoduleBlockReq"),
        (0x05, "ModuleDiffBlock"),
        (0x06, "ARRPCBlock"),
        (0x07, "IRInfoBlock"),
        (0x08, "SRInfoBlock"),
        (0x09, "ARFSUBlock"),
        (0x10, "IODControlReq"),
        (0x11, "IODControlRes"),
        // Response blocks (0x81-0x8F = 0x80 | request type)
        (0x81, "ARBlockRes"),
        (0x82, "IOCRBlockRes"),
        (0x83, "AlarmCRBlockRes"),
        (0x84, "ModuleDiffBlockRes"),
        (0x85, "ARServerBlockRes"),
        // CM internal blocks
        (0x3D, "PrmServer"),
        (0x3E, "CMCTL"),
        (0x3F, "CMDEV"),
        (0x40, "CMRPC"),
        // Faulty blocks
        (0xFD, "FaultyRecord"),
        (0xFE, "FaultyAR"),
        (0xFF, "FaultyBlock"),
    ];

    fn lookup(table: &[((u8, u8), &'static str)], key: (u8, u8)) -> Option<&'static str> {
        table.iter().find(|&&(k, _)| k == key).map(|&(_, m)| m)
    }

    fn cm_block_name(error_code1: u8) -> Option<&'static str> {
        Self::CM_BLOCK_NAMES
            .iter()
            .find(|&&(c, _)| c == error_code1)
            .map(|&(_, n)| n)
    }

    /// Create `PnioError` from 4-byte error status
    /// `[ErrorCode, ErrorDecode, ErrorCode1, ErrorCode2]`.
    pub fn from_bytes(data: &[u8]) -> PnioError {
        if data.len() < 4 {
            return PnioError {
                message: "Incomplete error data".to_string(),
                error_code: 0,
                error_decode: 0,
                error_code1: 0,
                error_code2: 0,
            };
        }
        Self::from_codes(data[0], data[1], data[2], data[3])
    }

    /// Create `PnioError` from an ArgsStatus field.
    ///
    /// Note: make_packet parses ArgsMaximumStatus as big-endian (">I"),
    /// but DCE/RPC uses little-endian. We byte-swap to get correct values
    /// matching the PNIO status layout:
    ///     Bits 31-24: ErrorCode  (service type: 0xDB=Connect, 0xDE=Read/Write)
    ///     Bits 23-16: ErrorDecode (0x81=PNIO, 0x80=PNIORW)
    ///     Bits 15-8:  ErrorCode1 (category)
    ///     Bits 7-0:   ErrorCode2 (specific error)
    ///
    /// Example: Wire bytes `[0x01,0x40,0x81,0xDB]` → big-endian parse 0x014081DB
    ///          → byte-swap → 0xDB814001 = RMPM Connect Unknown Blocks
    pub fn from_args_status(args_status: u32) -> PnioError {
        let swapped = args_status.swap_bytes();
        let error_code = ((swapped >> 24) & 0xFF) as u8;
        let error_decode = ((swapped >> 16) & 0xFF) as u8;
        let error_code1 = ((swapped >> 8) & 0xFF) as u8;
        let error_code2 = (swapped & 0xFF) as u8;
        Self::from_codes(error_code, error_decode, error_code1, error_code2)
    }

    /// Create `PnioError` with human-readable message from error codes
    /// (mirrors `_create_from_codes`).
    pub fn from_codes(
        error_code: u8,
        error_decode: u8,
        error_code1: u8,
        error_code2: u8,
    ) -> PnioError {
        let key = (error_code1, error_code2);

        let msg = if error_decode == Self::DECODE_PNIO_CM {
            // PNIO-CM (Connection Management) error
            if let Some(m) = Self::lookup(&Self::PNIOCM_ERROR_MESSAGES, key) {
                m.to_string()
            } else {
                let block_name = Self::cm_block_name(error_code1)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| format!("block 0x{error_code1:02X}"));
                format!("Unknown CM error in {block_name}")
            }
        } else if error_decode == Self::DECODE_PNIO {
            // PNIO error (includes RMPM errors)
            if let Some(m) = Self::lookup(&Self::PNIO_ERROR_MESSAGES, key) {
                m.to_string()
            } else if let Some(m) = Self::lookup(&Self::PNIORW_ERROR_MESSAGES, key) {
                m.to_string()
            } else {
                "Unknown PNIO error".to_string()
            }
        } else if error_decode == Self::DECODE_PNIORW {
            // PNIO Read/Write error
            if let Some(m) = Self::lookup(&Self::PNIORW_ERROR_MESSAGES, key) {
                m.to_string()
            } else {
                "Unknown PNIORW error".to_string()
            }
        } else {
            format!("Unknown error (Decode=0x{error_decode:02X})")
        };

        PnioError {
            message: msg,
            error_code,
            error_decode,
            error_code1,
            error_code2,
        }
    }

    /// True if this is a Connection Management error.
    pub fn is_cm_error(&self) -> bool {
        self.error_decode == Self::DECODE_PNIO_CM
    }

    /// Get the block name for CM errors (empty string otherwise).
    pub fn block_name(&self) -> String {
        if self.is_cm_error() {
            Self::cm_block_name(self.error_code1)
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("Unknown(0x{:02X})", self.error_code1))
        } else {
            String::new()
        }
    }
}

impl fmt::Display for PnioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_cm_error() {
            write!(
                f,
                "{} [CM:{}, EC2=0x{:02X}]",
                self.message,
                self.block_name(),
                self.error_code2
            )
        } else {
            write!(
                f,
                "{} [ErrorCode1=0x{:02X}, ErrorCode2=0x{:02X}]",
                self.message, self.error_code1, self.error_code2
            )
        }
    }
}

impl std::error::Error for PnioError {}

// =============================================================================
// ProfinetError — flattened port of the Python exception hierarchy
// =============================================================================

/// Base error for all PROFINET errors.
///
/// Mirrors the exception hierarchy in exceptions.py; Python subclasses become
/// enum variants (DCPError -> `Dcp`, DCPTimeoutError -> `DcpTimeout`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfinetError {
    /// DCP protocol errors.
    Dcp(String),
    /// DCP operation timed out.
    DcpTimeout(String),
    /// Device not found via DCP.
    DcpDeviceNotFound(String),
    /// DCE/RPC protocol errors.
    Rpc(String),
    /// RPC operation timed out.
    RpcTimeout(String),
    /// RPC returned fault response.
    RpcFault { message: String, fault_code: u32 },
    /// Failed to establish RPC connection.
    RpcConnection(String),
    /// PNIO application error with error codes.
    Pnio(PnioError),
    /// Input validation error.
    Validation(String),
    /// Invalid MAC address format.
    InvalidMac(String),
    /// Invalid IP address format.
    InvalidIp(String),
    /// Socket operation error.
    Socket(String),
    /// Insufficient permissions for raw socket.
    PermissionDenied(String),
}

impl fmt::Display for ProfinetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfinetError::Dcp(m)
            | ProfinetError::DcpTimeout(m)
            | ProfinetError::DcpDeviceNotFound(m)
            | ProfinetError::Rpc(m)
            | ProfinetError::RpcTimeout(m)
            | ProfinetError::RpcConnection(m)
            | ProfinetError::Validation(m)
            | ProfinetError::InvalidMac(m)
            | ProfinetError::InvalidIp(m)
            | ProfinetError::Socket(m)
            | ProfinetError::PermissionDenied(m) => write!(f, "{m}"),
            ProfinetError::RpcFault { message, .. } => write!(f, "{message}"),
            ProfinetError::Pnio(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProfinetError {}

impl From<PnioError> for ProfinetError {
    fn from(e: PnioError) -> Self {
        ProfinetError::Pnio(e)
    }
}

/// Bridge into the existing `Result<_, String>` call sites.
impl From<ProfinetError> for String {
    fn from(e: ProfinetError) -> Self {
        e.to_string()
    }
}
