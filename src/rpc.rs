//! Byte-exact DCE/RPC framing for PROFINET IO, ported from
//! `profinet-py/profinet/rpc.py` (`RPCCon._create_rpc`, `_create_nrd`,
//! object-UUID setup) and `protocol.py` (PNRPCHeader, PNNRDData).
//!
//! This module only builds request bytes; the UDP transport and response
//! parsing live in later modules.

/// PNRPCHeader packet type: request.
pub const REQUEST: u8 = 0x00;

/// PNRPCHeader operation numbers.
pub const CONNECT: u16 = 0x00;
pub const RELEASE: u16 = 0x01;
pub const READ: u16 = 0x02;
pub const WRITE: u16 = 0x03;
pub const CONTROL: u16 = 0x04;
pub const IMPLICIT_READ: u16 = 0x05;

/// PNRPCHeader.IFACE_UUID_DEVICE: PNIO-Device interface UUID in big-endian
/// byte order (matching drep=0x00 in `_create_rpc`).
pub const IFACE_UUID_DEVICE: [u8; 16] = [
    0xDE, 0xA0, 0x00, 0x01, 0x6C, 0x97, 0x11, 0xD1, 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D,
];

/// PNRPCHeader.OBJECT_UUID_PREFIX: shared 10-byte prefix of PNIO object UUIDs.
pub const OBJECT_UUID_PREFIX: [u8; 10] =
    [0xDE, 0xA0, 0x00, 0x00, 0x6C, 0x97, 0x11, 0xD1, 0x82, 0x71];

/// Remote object UUID as built in `RPCCon.__init__`:
/// OBJECT_UUID_PREFIX ++ 00 01 ++ device id ++ vendor id.
pub fn object_uuid(dev_high: u8, dev_low: u8, ven_high: u8, ven_low: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..10].copy_from_slice(&OBJECT_UUID_PREFIX);
    out[10..].copy_from_slice(&[0x00, 0x01, dev_high, dev_low, ven_high, ven_low]);
    out
}

/// PNNRDData wrapper as built by `_create_nrd`: args_maximum_status(1500) ++
/// args_length ++ maximum_count(1500) ++ offset(0) ++ actual_count ++ payload,
/// all big-endian.
pub fn nrd(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(20 + payload.len());
    out.extend_from_slice(&1500u32.to_be_bytes()); // args_maximum_status
    out.extend_from_slice(&len.to_be_bytes()); // args_length
    out.extend_from_slice(&1500u32.to_be_bytes()); // maximum_count
    out.extend_from_slice(&0u32.to_be_bytes()); // offset
    out.extend_from_slice(&len.to_be_bytes()); // actual_count
    out.extend_from_slice(payload);
    out
}

// PNRPCHeader request as built by `_create_rpc`: 80-byte header (all
// multi-byte fields big-endian per drep=00 00 00) followed by the body.
// The argument list mirrors the wire fields one-to-one, so the count is
// inherent to the record layout rather than an API-design smell.
#[allow(clippy::too_many_arguments)]
pub fn rpc_request(
    object_uuid: &[u8; 16],
    iface_uuid: &[u8; 16],
    activity_uuid: &[u8; 16],
    seq: u32,
    operation: u16,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(80 + body.len());
    out.push(0x04); // version
    out.push(REQUEST); // packet_type
    out.push(0x20); // flags1
    out.push(0x00); // flags2
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // drep (BE, ASCII, IEEE float)
    out.push(0x00); // serial_high
    out.extend_from_slice(object_uuid);
    out.extend_from_slice(iface_uuid);
    out.extend_from_slice(activity_uuid);
    out.extend_from_slice(&0u32.to_be_bytes()); // server_boot_time
    out.extend_from_slice(&1u32.to_be_bytes()); // interface_version
    out.extend_from_slice(&seq.to_be_bytes()); // sequence_number
    out.extend_from_slice(&operation.to_be_bytes()); // operation_number
    out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // interface_hint
    out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // activity_hint
    out.extend_from_slice(&(body.len() as u16).to_be_bytes()); // length_of_body
    out.extend_from_slice(&0u16.to_be_bytes()); // fragment_number
    out.push(0x00); // authentication_protocol
    out.push(0x00); // serial_low
    out.extend_from_slice(body);
    out
}

// The argument list mirrors the wire fields one-to-one, so the count is
// inherent to the record layout rather than an API-design smell.
#[allow(clippy::too_many_arguments)]
/// IODReadReq wrapped in NRD and framed by the RPC request header. An explicit
/// and an implicit read differ only in the AR UUID and the opnum, so both
/// public builders come through here.
fn read_request(
    object_uuid: &[u8; 16],
    iface_uuid: &[u8; 16],
    activity_uuid: &[u8; 16],
    ar_uuid: &[u8; 16],
    opnum: u16,
    seq: u32,
    api: u32,
    slot: u16,
    subslot: u16,
    index: u16,
    length: u32,
) -> Vec<u8> {
    let body = nrd(&crate::blocks::iod_read_request(
        ar_uuid, api, slot, subslot, index, length,
    ));
    rpc_request(object_uuid, iface_uuid, activity_uuid, seq, opnum, &body)
}

// The argument list mirrors the wire fields one-to-one, so the count is
// inherent to the record layout rather than an API-design smell.
#[allow(clippy::too_many_arguments)]
/// Full READ request frame: IODReadReq record wrapped in NRD, framed by the
/// RPC request header (as `RPCCon.read` composes it).
pub fn read_record_request(
    object_uuid: &[u8; 16],
    iface_uuid: &[u8; 16],
    activity_uuid: &[u8; 16],
    ar_uuid: &[u8; 16],
    seq: u32,
    api: u32,
    slot: u16,
    subslot: u16,
    index: u16,
    length: u32,
) -> Vec<u8> {
    read_request(
        object_uuid,
        iface_uuid,
        activity_uuid,
        ar_uuid,
        READ,
        seq,
        api,
        slot,
        subslot,
        index,
        length,
    )
}

// The argument list mirrors the wire fields one-to-one, so the count is
// inherent to the record layout rather than an API-design smell.
#[allow(clippy::too_many_arguments)]
/// Full Read Implicit request frame: an IODReadReq carrying an all-zero AR
/// UUID, sent with the IMPLICIT_READ opnum (as `RPCCon.read_implicit`
/// composes it). The service addresses the device by IP alone, so it answers
/// on stacks that reject the Device Access AR. Read-only — a write always
/// needs an established AR.
pub fn read_record_implicit_request(
    object_uuid: &[u8; 16],
    iface_uuid: &[u8; 16],
    activity_uuid: &[u8; 16],
    seq: u32,
    api: u32,
    slot: u16,
    subslot: u16,
    index: u16,
    length: u32,
) -> Vec<u8> {
    read_request(
        object_uuid,
        iface_uuid,
        activity_uuid,
        &[0u8; 16],
        IMPLICIT_READ,
        seq,
        api,
        slot,
        subslot,
        index,
        length,
    )
}

// The argument list mirrors the wire fields one-to-one, so the count is
// inherent to the record layout rather than an API-design smell.
#[allow(clippy::too_many_arguments)]
/// Full WRITE request frame: IODWriteReq record wrapped in NRD, framed by the
/// RPC request header (as `RPCCon.write` composes it).
pub fn write_record_request(
    object_uuid: &[u8; 16],
    iface_uuid: &[u8; 16],
    activity_uuid: &[u8; 16],
    ar_uuid: &[u8; 16],
    seq: u32,
    api: u32,
    slot: u16,
    subslot: u16,
    index: u16,
    payload: &[u8],
) -> Vec<u8> {
    let body = nrd(&crate::blocks::iod_write_request(
        ar_uuid, api, slot, subslot, index, payload,
    ));
    rpc_request(object_uuid, iface_uuid, activity_uuid, seq, WRITE, &body)
}

/// Full WRITE request frame for IODWriteMultipleReq 0xE040 as
/// `RPCCon.write_multiple` composes it: the builder payload wrapped in a
/// wildcard IODWriteReq record (api 0xFFFFFFFF, slot/subslot 0xFFFF), NRD
/// and the RPC request header.
pub fn write_multiple_request(
    object_uuid: &[u8; 16],
    iface_uuid: &[u8; 16],
    activity_uuid: &[u8; 16],
    ar_uuid: &[u8; 16],
    seq: u32,
    writes: &[crate::blocks::MultiWrite],
) -> Vec<u8> {
    let payload = crate::blocks::iod_write_multiple_payload(ar_uuid, 0, writes);
    let body = nrd(&crate::blocks::iod_write_request(
        ar_uuid,
        0xFFFF_FFFF,
        0xFFFF,
        0xFFFF,
        crate::blocks::IOD_WRITE_MULTIPLE_INDEX,
        &payload,
    ));
    rpc_request(object_uuid, iface_uuid, activity_uuid, seq, WRITE, &body)
}
