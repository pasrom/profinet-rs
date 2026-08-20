//! Byte-exact Connect request PDU building, ported from
//! `profinet-py/profinet/rpc.py` (`RPCCon.connect` and its block builders
//! `_build_iocr_block`, `_build_alarm_cr_block`,
//! `_build_expected_submodule_block`), `protocol.py` (PNARBlockRequest,
//! PNIOCRBlockReqHeader, PNAlarmCRBlockReq) and `blocks.py`
//! (ExpectedSubmoduleBlockReq).
//!
//! This module only builds request bytes; the UDP transport and connect
//! response parsing live in a later module. Blocks are concatenated directly
//! without inter-block padding, exactly as `connect()` assembles the NRD
//! payload (the parser advances by 4 + block_length).

use crate::gsdml::IoSlot;
use crate::rpc;

/// AR types (PNARBlockRequest.ar_type in `connect()`).
pub const AR_TYPE_IOCAR_SINGLE: u16 = 0x0001; // IO Controller AR, cyclic IO
pub const AR_TYPE_IOSAR: u16 = 0x0006; // IO Supervisor AR / DeviceAccess

/// ARProperties as `connect()` selects them: State=Active(1) +
/// PrmServer=CM_Initiator(bit 4), plus DeviceAccess(bit 8) without IOCRs.
pub const AR_PROPERTIES_IOCAR: u32 = 0x0000_0011;
pub const AR_PROPERTIES_DEVICE_ACCESS: u32 = 0x0000_0111;

/// CMInitiatorObjectUUID: `RPCCon.local_object_uuid`, the fixed local object
/// UUID OBJECT_UUID_PREFIX ++ 00 01 76 54 32 10.
pub const CM_INITIATOR_OBJECT_UUID: [u8; 16] = [
    0xDE, 0xA0, 0x00, 0x00, 0x6C, 0x97, 0x11, 0xD1, 0x82, 0x71, 0x00, 0x01, 0x76, 0x54, 0x32, 0x10,
];

/// AlarmCRBlockReq defaults (PNAlarmCRBlockReq statics).
pub const DEFAULT_RTA_TIMEOUT_FACTOR: u16 = 1;
pub const DEFAULT_RTA_RETRIES: u16 = 3;
pub const DEFAULT_MAX_ALARM_DATA_LENGTH: u16 = 200;
pub const DEFAULT_TAG_HEADER_HIGH: u16 = 0xC000;
pub const DEFAULT_TAG_HEADER_LOW: u16 = 0xA000;

/// Configuration for IOCR setup (IOCRSetup): slot list plus timing factors
/// consumed by [`iocr_block_req`] and [`expected_submodule_block`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocrSetup {
    /// IO slots to include in cyclic exchange.
    pub io_slots: Vec<IoSlot>,
    /// Base clock multiplier (32 = 1ms base clock).
    pub send_clock_factor: u16,
    /// Cycle time = send_clock_factor * reduction_ratio * 31.25us.
    pub reduction_ratio: u16,
    /// Watchdog timeout = watchdog_factor * cycle_time.
    pub watchdog_factor: u16,
    /// Data hold time = data_hold_factor * cycle_time.
    pub data_hold_factor: u16,
}

/// PNBlockHeader: block_type ++ block_length ++ version 1.0.
fn block_header(out: &mut Vec<u8>, block_type: u16, block_length: u16) {
    out.extend_from_slice(&block_type.to_be_bytes());
    out.extend_from_slice(&block_length.to_be_bytes());
    out.push(0x01); // version high
    out.push(0x00); // version low
}

// The argument list mirrors the wire fields one-to-one, so the count is
// inherent to the record layout rather than an API-design smell.
#[allow(clippy::too_many_arguments)]
/// ARBlockReq (0x0101) exactly as `connect()` builds it inline via
/// PNARBlockRequest, with the station name parameterized (the reference
/// hardcodes "tp"; block_length generalizes its `fmt_size - 2` to
/// 54 + name length, identical for a 2-byte name). Timeout factor (100) and
/// UDP RT port (0x8892) are the fixed values connect() always sends;
/// CMInitiatorObjectUUID is the fixed local object UUID.
pub fn ar_block_req(
    ar_type: u16,
    ar_uuid: &[u8; 16],
    session_key: u16,
    cm_mac: &[u8; 6],
    ar_properties: u32,
    cm_station_name: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(58 + cm_station_name.len());
    block_header(&mut out, 0x0101, (54 + cm_station_name.len()) as u16);
    out.extend_from_slice(&ar_type.to_be_bytes());
    out.extend_from_slice(ar_uuid);
    out.extend_from_slice(&session_key.to_be_bytes());
    out.extend_from_slice(cm_mac); // CMInitiatorMacAdd
    out.extend_from_slice(&CM_INITIATOR_OBJECT_UUID);
    out.extend_from_slice(&ar_properties.to_be_bytes());
    out.extend_from_slice(&100u16.to_be_bytes()); // CMInitiatorActivityTimeoutFactor
    out.extend_from_slice(&0x8892u16.to_be_bytes()); // InitiatorUDPRTPort
    out.extend_from_slice(&(cm_station_name.len() as u16).to_be_bytes());
    out.extend_from_slice(cm_station_name);
    out
}

/// IOCRAPIObject: slot ++ subslot ++ frame_offset (6 bytes).
fn iocr_api_object(out: &mut Vec<u8>, slot: u16, subslot: u16, frame_offset: u16) {
    out.extend_from_slice(&slot.to_be_bytes());
    out.extend_from_slice(&subslot.to_be_bytes());
    out.extend_from_slice(&frame_offset.to_be_bytes());
}

/// IOCRBlockReq (0x0102) as `_build_iocr_block`: fixed 46-byte header plus
/// one API sub-block (api 0) listing an IODataObject per submodule carrying
/// data in this IOCR's direction, then an IOCS entry for every other
/// submodule; frame offsets accumulate data length + 1 IOPS byte per data
/// object and 1 byte per IOCS. `iocr_type` is 1=Input (the controller proposes
/// frame_id 0xC000+ref, in the RTC1 range) or 2=Output (the controller sends
/// 0xFFFF and the device assigns the frame ID, returning it in the
/// IOCRBlockRes of the Connect response).
pub fn iocr_block_req(iocr_type: u16, iocr_reference: u16, setup: &IocrSetup) -> Vec<u8> {
    // IODataObjects: submodules with data in this direction.
    let mut objects = Vec::new();
    let mut num_objects: u16 = 0;
    let mut frame_offset: usize = 0;
    for slot in &setup.io_slots {
        let data_len = if iocr_type == 1 {
            slot.input_length
        } else {
            slot.output_length
        };
        if data_len > 0 {
            iocr_api_object(&mut objects, slot.slot, slot.subslot, frame_offset as u16);
            frame_offset += data_len + 1; // data + IOPS
            num_objects += 1;
        }
    }

    // IOCS entries: all other submodules (each contributes 1 status byte).
    let mut iocs = Vec::new();
    let mut iocs_count: u16 = 0;
    for slot in &setup.io_slots {
        if iocr_type == 1 && slot.input_length > 0 {
            continue;
        }
        if iocr_type == 2 && slot.output_length > 0 {
            continue;
        }
        iocr_api_object(&mut iocs, slot.slot, slot.subslot, frame_offset as u16);
        frame_offset += 1;
        iocs_count += 1;
    }

    // Pad to minimum 40 bytes.
    let data_length = frame_offset.max(40) as u16;

    // IOCRAPI: API(4) ++ nbr_io_data(2) ++ io_data[] ++ nbr_iocs(2) ++ iocs[].
    let api_block_len = 4 + 2 + objects.len() + 2 + iocs.len();
    let frame_id = if iocr_type == 1 {
        // Input CR: the controller proposes a frame ID in the RTC1 range.
        0xC000 + iocr_reference
    } else {
        // Output CR: 0xFFFF asks the device to assign it, which it returns in
        // the IOCRBlockRes. Proposing one here is not the controller's call.
        0xFFFF
    };

    let mut out = Vec::with_capacity(46 + api_block_len);
    block_header(&mut out, 0x0102, (46 + api_block_len - 4) as u16);
    out.extend_from_slice(&iocr_type.to_be_bytes());
    out.extend_from_slice(&iocr_reference.to_be_bytes());
    out.extend_from_slice(&0x8892u16.to_be_bytes()); // LT (PROFINET EtherType)
    out.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // IOCRProperties: RT_CLASS_1
    out.extend_from_slice(&data_length.to_be_bytes());
    out.extend_from_slice(&frame_id.to_be_bytes());
    out.extend_from_slice(&setup.send_clock_factor.to_be_bytes());
    out.extend_from_slice(&setup.reduction_ratio.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // phase (1-based)
    out.extend_from_slice(&0u16.to_be_bytes()); // sequence
    out.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // frame_send_offset
    out.extend_from_slice(&setup.watchdog_factor.to_be_bytes());
    out.extend_from_slice(&setup.data_hold_factor.to_be_bytes());
    out.extend_from_slice(&0xC000u16.to_be_bytes()); // IOCRTagHeader
    out.extend_from_slice(&[0u8; 6]); // IOCRMulticastMAC
    out.extend_from_slice(&1u16.to_be_bytes()); // NumberOfAPIs
    out.extend_from_slice(&0u32.to_be_bytes()); // API
    out.extend_from_slice(&num_objects.to_be_bytes());
    out.extend_from_slice(&objects);
    out.extend_from_slice(&iocs_count.to_be_bytes());
    out.extend_from_slice(&iocs);
    out
}

/// AlarmCRBlockReq (0x0103) as `_build_alarm_cr_block`: 26 fixed bytes.
/// `transport` 0=Layer2 (LT 0x8892) / 1=UDP (LT 0x0800), `priority` 0=low /
/// 1=high; AlarmCRProperties packs them as (transport << 1) | priority.
pub fn alarm_cr_block(local_alarm_reference: u16, transport: u16, priority: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(26);
    block_header(&mut out, 0x0103, 22);
    out.extend_from_slice(&0x0001u16.to_be_bytes()); // AlarmCRType: standard
    let lt: u16 = if transport == 0 { 0x8892 } else { 0x0800 };
    out.extend_from_slice(&lt.to_be_bytes());
    out.extend_from_slice(&(((transport as u32) << 1) | priority as u32).to_be_bytes());
    out.extend_from_slice(&DEFAULT_RTA_TIMEOUT_FACTOR.to_be_bytes());
    out.extend_from_slice(&DEFAULT_RTA_RETRIES.to_be_bytes());
    out.extend_from_slice(&local_alarm_reference.to_be_bytes());
    out.extend_from_slice(&DEFAULT_MAX_ALARM_DATA_LENGTH.to_be_bytes());
    out.extend_from_slice(&DEFAULT_TAG_HEADER_HIGH.to_be_bytes());
    out.extend_from_slice(&DEFAULT_TAG_HEADER_LOW.to_be_bytes());
    out
}

/// ExpectedSubmoduleBlockReq (0x0104) as `_build_expected_submodule_block` +
/// `ExpectedSubmoduleBlockReq.to_bytes`: submodules are grouped into one API
/// entry per (api 0, slot) in first-seen order, the entry's module ident
/// taken from the first submodule; SubmoduleProperties is the type derived
/// from the IO lengths (0=NO_IO, 1=INPUT, 2=OUTPUT, 3=INPUT_OUTPUT) and the
/// data-description count is implied by it (NO_IO gets one Input description
/// with length 0, INPUT_OUTPUT gets Input then Output).
pub fn expected_submodule_block(setup: &IocrSetup) -> Vec<u8> {
    // API entries: (slot, module_ident, submodule bytes, submodule count).
    let mut apis: Vec<(u16, u32, Vec<u8>, u16)> = Vec::new();

    for slot in &setup.io_slots {
        let submodule_type: u16 = match (slot.input_length > 0, slot.output_length > 0) {
            (true, true) => 3,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 0,
        };

        let idx = match apis.iter().position(|(s, ..)| *s == slot.slot) {
            Some(idx) => idx,
            None => {
                apis.push((slot.slot, slot.module_ident, Vec::new(), 0));
                apis.len() - 1
            }
        };
        let entry = &mut apis[idx];

        // ExpectedSubmodule: subslot ++ submodule_ident ++ properties, then
        // the data descriptions (type, data_length, length_iocs, length_iops).
        let sub = &mut entry.2;
        sub.extend_from_slice(&slot.subslot.to_be_bytes());
        sub.extend_from_slice(&slot.submodule_ident.to_be_bytes());
        sub.extend_from_slice(&submodule_type.to_be_bytes());
        let mut dds: Vec<(u16, u16)> = Vec::new(); // (data_description, length)
        if submodule_type == 0 || submodule_type == 1 || submodule_type == 3 {
            dds.push((1, slot.input_length as u16)); // Input (0 for NO_IO)
        }
        if submodule_type == 2 || submodule_type == 3 {
            dds.push((2, slot.output_length as u16)); // Output
        }
        for (dd, len) in dds {
            sub.extend_from_slice(&dd.to_be_bytes());
            sub.extend_from_slice(&len.to_be_bytes());
            sub.push(1); // length_iocs
            sub.push(1); // length_iops
        }
        entry.3 += 1;
    }

    // Body: NumberOfAPIs ++ per API: api ++ slot ++ module_ident ++
    // module_properties(0) ++ num_submodules ++ submodules.
    let mut body = Vec::new();
    body.extend_from_slice(&(apis.len() as u16).to_be_bytes());
    for (slot, module_ident, submodules, num_submodules) in &apis {
        body.extend_from_slice(&0u32.to_be_bytes()); // API
        body.extend_from_slice(&slot.to_be_bytes());
        body.extend_from_slice(&module_ident.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // ModuleProperties
        body.extend_from_slice(&num_submodules.to_be_bytes());
        body.extend_from_slice(submodules);
    }

    let mut out = Vec::with_capacity(6 + body.len());
    block_header(&mut out, 0x0104, (body.len() + 2) as u16);
    out.extend_from_slice(&body);
    out
}

// The argument list mirrors the wire fields one-to-one, so the count is
// inherent to the record layout rather than an API-design smell.
#[allow(clippy::too_many_arguments)]
/// Full Connect Record RPC request for a fresh connection, exactly as
/// `connect()` with an IOCR setup assembles it: ARBlockReq (IOCARSingle) ->
/// input IOCRBlockReq -> output IOCRBlockReq -> AlarmCRBlockReq ->
/// ExpectedSubmoduleBlockReq, wrapped in NRD and the RPC request header
/// (op=CONNECT). The IOCR references (input 1, output 2) and local alarm
/// reference (1) are the values a fresh RPCCon's counters assign.
pub fn build_connect_request(
    object_uuid: &[u8; 16],
    iface_uuid: &[u8; 16],
    activity_uuid: &[u8; 16],
    ar_uuid: &[u8; 16],
    session_key: u16,
    cm_mac: &[u8; 6],
    cm_station_name: &[u8],
    setup: &IocrSetup,
    seq: u32,
) -> Vec<u8> {
    let mut body = ar_block_req(
        AR_TYPE_IOCAR_SINGLE,
        ar_uuid,
        session_key,
        cm_mac,
        AR_PROPERTIES_IOCAR,
        cm_station_name,
    );
    body.extend_from_slice(&iocr_block_req(1, 1, setup)); // input IOCR
    body.extend_from_slice(&iocr_block_req(2, 2, setup)); // output IOCR
    body.extend_from_slice(&alarm_cr_block(1, 0, 0));
    body.extend_from_slice(&expected_submodule_block(setup));
    rpc::rpc_request(
        object_uuid,
        iface_uuid,
        activity_uuid,
        seq,
        rpc::CONNECT,
        &rpc::nrd(&body),
    )
}

// The argument list mirrors the wire fields one-to-one, like
// build_connect_request above.
#[allow(clippy::too_many_arguments)]
/// Connect Record RPC request for a Device-Access AR, exactly as `connect()`
/// without an IOCRSetup assembles it: a lone ARBlockReq with AR type IOSAR
/// (0x0006) and the DeviceAccess ARProperties (0x0111) — no IOCR, AlarmCR or
/// ExpectedSubmodule blocks. This is the acyclic read/write-only AR the
/// high-level [`crate::device::ProfinetDevice`] establishes.
pub fn build_device_access_connect_request(
    object_uuid: &[u8; 16],
    iface_uuid: &[u8; 16],
    activity_uuid: &[u8; 16],
    ar_uuid: &[u8; 16],
    session_key: u16,
    cm_mac: &[u8; 6],
    cm_station_name: &[u8],
    seq: u32,
) -> Vec<u8> {
    let body = ar_block_req(
        AR_TYPE_IOSAR,
        ar_uuid,
        session_key,
        cm_mac,
        AR_PROPERTIES_DEVICE_ACCESS,
        cm_station_name,
    );
    rpc::rpc_request(
        object_uuid,
        iface_uuid,
        activity_uuid,
        seq,
        rpc::CONNECT,
        &rpc::nrd(&body),
    )
}
