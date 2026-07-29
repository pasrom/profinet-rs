//! RPC transport: `RpcConn` over UDP, ported from `profinet-py/profinet/rpc.py`
//! (`RPCCon.__init__`, `_send_receive`, `_parse_rpc_header`, `connect`,
//! `_send_control`/`prm_end`, `application_ready`, `read`, `write`,
//! `_parse_iocr_response`).
//!
//! The socket methods are kept thin; all response parsing lives in pure
//! functions (`parse_rpc_header`, `parse_nrd`, `parse_iod_header`,
//! `parse_iocr_block_res`, `parse_ccontrol_request`, `ccontrol_response`) so
//! the error-prone byte handling is unit-testable without a device. Header
//! parsing is DREP-aware: DCE/RPC multi-byte fields follow the byte order in
//! the DREP byte at offset 4 (high nibble 0x1x = little-endian), and some
//! devices answer little-endian. PROFINET block payloads (NRD
//! args, IOD records, control blocks) stay big-endian, exactly as the
//! reference parses them.

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::connect::IocrSetup;
use crate::diagnosis;
use crate::errors::PnioError;
use crate::im;
use crate::rawudp::RawUdp;
use crate::rpc;

/// PROFINET IO RPC port (IEC 61158-6-10).
pub const RPC_PORT: u16 = 0x8894; // 34964

/// Default requested record length for reads (rpc.py `read()` length=4096).
pub const READ_LENGTH: u32 = 4096;

/// PNRPCHeader packet types.
pub const PACKET_TYPE_REQUEST: u8 = 0x00;
pub const PACKET_TYPE_RESPONSE: u8 = 0x02;
pub const PACKET_TYPE_FAULT: u8 = 0x03;
pub const PACKET_TYPE_REJECT: u8 = 0x06;

/// IODControl block types and control commands (indices.py).
pub const BLOCK_IOD_CONTROL_PRM_END_REQ: u16 = 0x0110;
pub const BLOCK_IOD_CONTROL_APP_READY_REQ: u16 = 0x0112;
pub const BLOCK_IOD_CONTROL_APP_READY_RES: u16 = 0x8112;
pub const BLOCK_IOD_RELEASE_REQ: u16 = 0x0114;
pub const BLOCK_PRM_BEGIN_REQ: u16 = 0x0118;
pub const CONTROL_CMD_PRM_END: u16 = 0x0001;
pub const CONTROL_CMD_APPLICATION_READY: u16 = 0x0002;
pub const CONTROL_CMD_RELEASE: u16 = 0x0004;
pub const CONTROL_CMD_DONE: u16 = 0x0008;
pub const CONTROL_CMD_PRM_BEGIN: u16 = 0x0040;

/// IOCRBlockRes block type (PNIOCRBlockRes.BLOCK_TYPE).
pub const IOCR_BLOCK_RES: u16 = 0x8102;

fn rd_u16(data: &[u8], off: usize, le: bool) -> u16 {
    let b = [data[off], data[off + 1]];
    if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    }
}

fn rd_u32(data: &[u8], off: usize, le: bool) -> u32 {
    let b = [data[off], data[off + 1], data[off + 2], data[off + 3]];
    if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

fn wr_u16(out: &mut Vec<u8>, v: u16, le: bool) {
    out.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
}

fn wr_u32(out: &mut Vec<u8>, v: u32, le: bool) {
    out.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
}

/// DCE/RPC header parsed DREP-aware, as `_parse_rpc_header` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRpc {
    pub version: u8,
    pub packet_type: u8,
    pub flags1: u8,
    pub flags2: u8,
    pub drep: [u8; 3],
    pub serial_high: u8,
    pub object_uuid: [u8; 16],
    pub interface_uuid: [u8; 16],
    pub activity_uuid: [u8; 16],
    pub server_boot_time: u32,
    pub interface_version: u32,
    pub sequence_number: u32,
    pub operation_number: u16,
    pub interface_hint: u16,
    pub activity_hint: u16,
    pub length_of_body: u16,
    pub fragment_number: u16,
    pub auth_protocol: u8,
    pub serial_low: u8,
    pub is_little_endian: bool,
    pub payload: Vec<u8>,
}

/// Parse an 80-byte DCE/RPC header + body with DREP-aware endianness
/// (`RPCCon._parse_rpc_header`). Single-byte fields and the UUIDs are
/// endian-independent; multi-byte fields follow DREP byte 0 (0x1x = LE).
/// Returns None if the packet is shorter than the header.
pub fn parse_rpc_header(data: &[u8]) -> Option<ParsedRpc> {
    if data.len() < 80 {
        return None;
    }
    let le = data[4] & 0x10 != 0;
    let uuid = |off: usize| -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&data[off..off + 16]);
        out
    };
    Some(ParsedRpc {
        version: data[0],
        packet_type: data[1],
        flags1: data[2],
        flags2: data[3],
        drep: [data[4], data[5], data[6]],
        serial_high: data[7],
        object_uuid: uuid(8),
        interface_uuid: uuid(24),
        activity_uuid: uuid(40),
        server_boot_time: rd_u32(data, 56, le),
        interface_version: rd_u32(data, 60, le),
        sequence_number: rd_u32(data, 64, le),
        operation_number: rd_u16(data, 68, le),
        interface_hint: rd_u16(data, 70, le),
        activity_hint: rd_u16(data, 72, le),
        length_of_body: rd_u16(data, 74, le),
        fragment_number: rd_u16(data, 76, le),
        auth_protocol: data[78],
        serial_low: data[79],
        is_little_endian: le,
        payload: data[80..].to_vec(),
    })
}

/// Classify one received packet as `_send_receive`'s loop does: an echoed
/// REQUEST (our own packet looped back on host networking) yields Ok(None)
/// = skip; FAULT/REJECT/unexpected types are errors; RESPONSE yields the
/// parsed header.
pub fn parse_rpc_response(data: &[u8]) -> Result<Option<ParsedRpc>, String> {
    let hdr = parse_rpc_header(data).ok_or_else(|| {
        format!(
            "Failed to parse RPC response: data too short ({} bytes)",
            data.len()
        )
    })?;
    match hdr.packet_type {
        PACKET_TYPE_REQUEST => Ok(None), // echoed request, skip
        PACKET_TYPE_RESPONSE => Ok(Some(hdr)),
        PACKET_TYPE_FAULT => Err(format!(
            "RPC fault from device (fault code 0x{:04X})",
            hdr.operation_number
        )),
        PACKET_TYPE_REJECT => Err("RPC request rejected by device".to_string()),
        t => Err(format!("Unexpected RPC packet type: 0x{t:02X}")),
    }
}

/// The echoed-request-skip loop of `_send_receive`, driven over an abstract
/// Normalize a DCE activity UUID to a DREP-independent form for comparison.
/// The UUID's first three fields (time_low u32, time_mid u16, time_hi u16) are
/// serialized in the packet's byte order; the trailing 8 bytes (clock_seq +
/// node) are always big-endian. When the packet is little-endian we swap those
/// three fields to big-endian so a request and its response (which may carry
/// opposite DREPs, as some devices do) canonicalize to the same value.
fn drep_normalized_uuid(uuid: &[u8; 16], little_endian: bool) -> [u8; 16] {
    if !little_endian {
        return *uuid;
    }
    let mut out = *uuid;
    out[0..4].reverse(); // time_low
    out[4..6].reverse(); // time_mid
    out[6..8].reverse(); // time_hi_and_version
    out
}

/// receive function so it is testable without a socket: keep receiving until
/// a non-REQUEST packet arrives, then validate it. `recv` errors (timeout,
/// socket failure) propagate. `expected_uuid` must be the DREP-normalized
/// activity UUID (see [`drep_normalized_uuid`]).
pub fn next_rpc_response<F>(
    mut recv: F,
    expected_uuid: &[u8; 16],
    expected_seq: u32,
) -> Result<ParsedRpc, String>
where
    F: FnMut() -> Result<Vec<u8>, String>,
{
    loop {
        if let Some(resp) = parse_rpc_response(&recv()?)? {
            // Only the response matching our activity UUID + sequence number is
            // ours. Skip a late answer to a previous request, another
            // controller's traffic, or a spoofed datagram -- any of which would
            // otherwise be returned as this call's result (silent corruption).
            // Compare the activity UUID in DREP-normalized form: a device may
            // answer with little-endian DREP even when our request used
            // big-endian, which byte-swaps the UUID's time_low/mid/hi fields on
            // the wire (the trailing clock_seq+node are endian-invariant). A raw
            // 16-byte compare would reject our own device's valid response.
            let resp_uuid = drep_normalized_uuid(&resp.activity_uuid, resp.is_little_endian);
            if &resp_uuid == expected_uuid && resp.sequence_number == expected_seq {
                return Ok(resp);
            }
        }
    }
}

/// PNNRDData: args status + array counts + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNrd {
    /// args_maximum_status: args_maximum on requests, PNIO status on
    /// responses (non-zero = PNIO error).
    pub args_status: u32,
    pub args_length: u32,
    pub maximum_count: u32,
    pub offset: u32,
    pub actual_count: u32,
    pub payload: Vec<u8>,
}

/// Parse a 20-byte NRD header + payload. Responses received via
/// `_send_receive` are parsed big-endian (PNNRDData); the device-initiated
/// CControl request in `application_ready` is parsed with the request's DREP
/// byte order, so the endianness is a parameter.
pub fn parse_nrd(data: &[u8], little_endian: bool) -> Result<ParsedNrd, String> {
    if data.len() < 20 {
        return Err(format!("NRD header too short ({} bytes)", data.len()));
    }
    Ok(ParsedNrd {
        args_status: rd_u32(data, 0, little_endian),
        args_length: rd_u32(data, 4, little_endian),
        maximum_count: rd_u32(data, 8, little_endian),
        offset: rd_u32(data, 12, little_endian),
        actual_count: rd_u32(data, 16, little_endian),
        payload: data[20..].to_vec(),
    })
}

/// PNIODHeader response record (64 fixed bytes + payload), always big-endian.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedIod {
    pub block_type: u16,
    pub block_length: u16,
    pub sequence_number: u16,
    pub ar_uuid: [u8; 16],
    pub api: u32,
    pub slot: u16,
    pub subslot: u16,
    pub index: u16,
    pub length: u32,
    pub payload: Vec<u8>,
}

/// Parse a PNIODHeader (read/write response record) from an NRD payload.
pub fn parse_iod_header(data: &[u8]) -> Result<ParsedIod, String> {
    if data.len() < 64 {
        return Err(format!("IOD header too short ({} bytes)", data.len()));
    }
    let mut ar_uuid = [0u8; 16];
    ar_uuid.copy_from_slice(&data[8..24]);
    Ok(ParsedIod {
        block_type: rd_u16(data, 0, false),
        block_length: rd_u16(data, 2, false),
        sequence_number: rd_u16(data, 6, false),
        ar_uuid,
        api: rd_u32(data, 24, false),
        slot: rd_u16(data, 28, false),
        subslot: rd_u16(data, 30, false),
        index: rd_u16(data, 34, false),
        length: rd_u32(data, 36, false),
        payload: data[64..].to_vec(),
    })
}

/// Walk the connect-response blocks for an IOCRBlockRes (0x8102) of the given
/// type (1=input, 2=output) and return its assigned frame ID, or 0 if not
/// found (`_parse_iocr_response`). The scan advances by 4 + block_length.
pub fn parse_iocr_block_res(response_data: &[u8], iocr_type: u16) -> u16 {
    let mut offset = 0usize;
    while offset + 6 <= response_data.len() {
        let block_type = rd_u16(response_data, offset, false);
        let block_length = rd_u16(response_data, offset + 2, false);
        if block_type == IOCR_BLOCK_RES && offset + 12 <= response_data.len() {
            // block_header(6) ++ iocr_type ++ iocr_reference ++ frame_id
            let res_type = rd_u16(response_data, offset + 6, false);
            if res_type == iocr_type {
                return rd_u16(response_data, offset + 10, false);
            }
        }
        offset += 4 + block_length as usize;
    }
    0
}

/// Result from AR CONNECT (ConnectResult).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectResult {
    /// Frame ID for input IOCR (device -> controller). 0 = not established.
    pub input_frame_id: u16,
    /// Frame ID for output IOCR (controller -> device). 0 = not established.
    pub output_frame_id: u16,
    /// True if cyclic IO was established.
    pub has_cyclic: bool,
}

/// Format a non-zero NRD args_status as `0x........ (<decoded>)`, keeping the
/// raw hex (callers match contract statuses like `DE80C200` as substrings) and
/// appending the decoded PNIO message. Responses are read big-endian, so the
/// status bytes are already `[ErrorCode, ErrorDecode, ErrorCode1, ErrorCode2]`
/// -- `from_bytes`, not `from_args_status` (which byte-swaps for LE wire data).
fn pnio_status_str(args_status: u32) -> String {
    format!(
        "0x{:08X} ({})",
        args_status,
        PnioError::from_bytes(&args_status.to_be_bytes())
    )
}

/// Parse a connect-response RPC body: NRD status check, then extract the
/// frame IDs assigned in the IOCRBlockRes blocks (`connect()`).
pub fn parse_connect_response(
    rpc_payload: &[u8],
    little_endian: bool,
) -> Result<ConnectResult, String> {
    let nrd = parse_nrd(rpc_payload, little_endian)?;
    if nrd.args_status != 0 {
        return Err(format!(
            "Connect rejected by device: PNIO status {}",
            pnio_status_str(nrd.args_status)
        ));
    }
    let input_frame_id = parse_iocr_block_res(&nrd.payload, 1);
    let output_frame_id = parse_iocr_block_res(&nrd.payload, 2);
    Ok(ConnectResult {
        input_frame_id,
        output_frame_id,
        has_cyclic: input_frame_id != 0 || output_frame_id != 0,
    })
}

/// Parse a read-response RPC body: NRD status check (non-zero args_status =
/// PNIO error), then the IOD record; returns the record payload (`read()`).
pub fn parse_read_response(rpc_payload: &[u8], little_endian: bool) -> Result<Vec<u8>, String> {
    let nrd = parse_nrd(rpc_payload, little_endian)?;
    if nrd.args_status != 0 {
        return Err(format!(
            "PNIO error status {}",
            pnio_status_str(nrd.args_status)
        ));
    }
    Ok(parse_iod_header(&nrd.payload)?.payload)
}

/// Parse a write/control-response RPC body: NRD status check only, returning
/// the NRD payload (`write()` / `_send_control`).
pub fn parse_status_response(rpc_payload: &[u8], little_endian: bool) -> Result<Vec<u8>, String> {
    let nrd = parse_nrd(rpc_payload, little_endian)?;
    if nrd.args_status != 0 {
        return Err(format!(
            "PNIO error status {}",
            pnio_status_str(nrd.args_status)
        ));
    }
    Ok(nrd.payload)
}

/// IODControlReq/Res block (PNIODReleaseBlock layout, 32 bytes) as
/// `_send_control` builds it: header ++ padding ++ ar_uuid ++ session_key ++
/// padding ++ control_command ++ control_block_properties.
pub fn iod_control_block(
    block_type: u16,
    ar_uuid: &[u8; 16],
    session_key: u16,
    control_command: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&crate::blocks::block_header(block_type, 28, 1, 0));
    out.extend_from_slice(&0u16.to_be_bytes()); // padding1
    out.extend_from_slice(ar_uuid);
    out.extend_from_slice(&session_key.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // padding2
    out.extend_from_slice(&control_command.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // control_block_properties
    out
}

/// Full RELEASE request frame as `disconnect()` composes it: ReleaseBlockReq
/// (0x0114, control command 0x0004 = terminate AR) wrapped in NRD and the
/// RPC request header with opnum RELEASE.
pub fn release_request(
    object_uuid: &[u8; 16],
    iface_uuid: &[u8; 16],
    activity_uuid: &[u8; 16],
    ar_uuid: &[u8; 16],
    session_key: u16,
    seq: u32,
) -> Vec<u8> {
    let block = iod_control_block(
        BLOCK_IOD_RELEASE_REQ,
        ar_uuid,
        session_key,
        CONTROL_CMD_RELEASE,
    );
    rpc::rpc_request(
        object_uuid,
        iface_uuid,
        activity_uuid,
        seq,
        rpc::RELEASE,
        &rpc::nrd(&block),
    )
}

/// A device-initiated CControl request, as `application_ready` extracts it
/// from the RPC packet received on the 34964 listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CControlRequest {
    pub block_type: u16,
    pub control_command: u16,
    /// The NRD body (control block + sub-blocks), returned to the caller.
    pub nrd_body: Vec<u8>,
}

/// Validate and extract the CControl request from a parsed RPC packet: must
/// be a REQUEST with opnum CONTROL; the NRD is parsed with the request's
/// DREP byte order, while the control block itself is big-endian
/// (control_command sits at offset 28: header 6 + pad 2 + ar_uuid 16 +
/// session_key 2 + pad 2). Errors correspond to the packets
/// `application_ready` skips.
pub fn parse_ccontrol_request(hdr: &ParsedRpc) -> Result<CControlRequest, String> {
    if hdr.packet_type != PACKET_TYPE_REQUEST {
        return Err(format!("Not a REQUEST (type=0x{:02X})", hdr.packet_type));
    }
    if hdr.operation_number != rpc::CONTROL {
        return Err(format!("Not CONTROL opnum (op={})", hdr.operation_number));
    }
    let nrd = parse_nrd(&hdr.payload, hdr.is_little_endian)?;
    if nrd.payload.len() < 32 {
        return Err(format!(
            "CControl payload too short: {} bytes",
            nrd.payload.len()
        ));
    }
    Ok(CControlRequest {
        block_type: rd_u16(&nrd.payload, 0, false),
        control_command: rd_u16(&nrd.payload, 28, false),
        nrd_body: nrd.payload,
    })
}

/// Build the CControl response `application_ready` sends back for the
/// device's ApplicationReady: control block 0x8112 with command DONE, NRD
/// with PNIO status 0 in the request's byte order, and an RPC RESPONSE
/// header echoing the device's DREP, UUIDs, sequence number and serials.
pub fn ccontrol_response(req: &ParsedRpc, ar_uuid: &[u8; 16], session_key: u16) -> Vec<u8> {
    let le = req.is_little_endian;
    let control = iod_control_block(
        BLOCK_IOD_CONTROL_APP_READY_RES,
        ar_uuid,
        session_key,
        CONTROL_CMD_DONE,
    );

    // Response NRD: pnio_status(0) ++ args_length ++ maximum_count ++
    // offset(0) ++ actual_count ++ control block, in the request byte order.
    let len = control.len() as u32;
    let mut nrd = Vec::with_capacity(20 + control.len());
    wr_u32(&mut nrd, 0, le); // pnio_status = OK
    wr_u32(&mut nrd, len, le); // args_length
    wr_u32(&mut nrd, len, le); // maximum_count
    wr_u32(&mut nrd, 0, le); // offset
    wr_u32(&mut nrd, len, le); // actual_count
    nrd.extend_from_slice(&control);

    let mut out = Vec::with_capacity(80 + nrd.len());
    out.push(req.version);
    out.push(PACKET_TYPE_RESPONSE);
    out.push(0x00); // flags1
    out.push(0x00); // flags2
    out.extend_from_slice(&req.drep);
    out.push(req.serial_high);
    out.extend_from_slice(&req.object_uuid);
    out.extend_from_slice(&req.interface_uuid);
    out.extend_from_slice(&req.activity_uuid);
    wr_u32(&mut out, 0, le); // server_boot_time
    wr_u32(&mut out, req.interface_version, le);
    wr_u32(&mut out, req.sequence_number, le);
    wr_u16(&mut out, req.operation_number, le);
    wr_u16(&mut out, 0xFFFF, le); // interface_hint
    wr_u16(&mut out, 0xFFFF, le); // activity_hint
    wr_u16(&mut out, nrd.len() as u16, le); // length_of_body
    wr_u16(&mut out, 0, le); // fragment_number
    out.push(0x00); // auth_protocol
    out.push(req.serial_low);
    out.extend_from_slice(&nrd);
    out
}

/// Parse one received datagram as a device-initiated CControl
/// ApplicationReady (REQUEST + CONTROL opnum + block type 0x0112); None for
/// anything else, which `application_ready` skips like the reference does.
fn extract_app_ready(data: &[u8]) -> Option<(ParsedRpc, CControlRequest)> {
    let hdr = parse_rpc_header(data)?;
    let cc = parse_ccontrol_request(&hdr).ok()?;
    if cc.block_type != BLOCK_IOD_CONTROL_APP_READY_REQ {
        return None;
    }
    Some((hdr, cc))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| format!("getrandom failed: {e}"))?;
    Ok(buf)
}

/// Bind the CControl listener to 0.0.0.0:34964 with SO_REUSEADDR, as
/// `RPCCon.__init__` does for the device-initiated ApplicationReady.
fn bind_ccontrol_socket() -> Result<UdpSocket, String> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| format!("CControl socket create failed: {e}"))?;
    sock.set_reuse_address(true)
        .map_err(|e| format!("CControl SO_REUSEADDR failed: {e}"))?;
    let addr = SocketAddr::from(([0, 0, 0, 0], RPC_PORT));
    sock.bind(&addr.into())
        .map_err(|e| format!("Cannot bind CControl socket to port {RPC_PORT}: {e}"))?;
    Ok(sock.into())
}

/// The datagram transport under `RpcConn`, factored out as a port so the
/// byte-level orchestration (`send_receive`, `application_ready`, `release`)
/// is testable without a device: the reference's `std::net` UDP socket pair
/// ([`UdpTransport`]), a UDP-over-raw-L2 endpoint ([`RawL2Transport`]; macOS
/// Local Network privacy drops inbound LAN UDP through the IP stack, so the
/// bench uses raw L2 like DCP), or a test double. The request/response and the
/// device-initiated CControl are separate channels because the UDP path
/// listens for them on two different sockets.
///
/// The CControl reply route (where the confirmation goes back to) is transport
/// -private: each impl remembers the source of its last received CControl and
/// `reply_ccontrol` addresses that, so a caller can never route a reply to the
/// wrong transport.
///
/// `Send` is required so `RpcConn` keeps the `Send` auto-trait the pre-refactor
/// `Endpoint` enum had (both real transports are `Send`); losing it would
/// silently forbid moving a connection into a worker thread.
trait RpcTransport: std::fmt::Debug + Send {
    /// Send a request datagram to the device's RPC port (34964).
    fn send_request(&mut self, data: &[u8]) -> Result<(), String>;
    /// Receive one datagram on the request/response channel; None on timeout.
    fn recv_response(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String>;
    /// Receive one datagram on the CControl channel, remembering its source
    /// for [`Self::reply_ccontrol`]; None on timeout.
    fn recv_ccontrol(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String>;
    /// Send a CControl confirmation from port 34964 back to the source of the
    /// last datagram [`Self::recv_ccontrol`] returned.
    fn reply_ccontrol(&mut self, data: &[u8]) -> Result<(), String>;
    /// Human-readable peer description for error messages.
    fn peer(&self) -> String;
}

/// The reference's `RPCCon.__init__` socket layout: a request/response socket
/// on an ephemeral local port, plus a lazily-bound listener on 0.0.0.0:34964
/// for the device-initiated CControl (ApplicationReady).
#[derive(Debug)]
struct UdpTransport {
    socket: UdpSocket,
    ccontrol_socket: Option<UdpSocket>,
    /// Source of the last CControl datagram, for the confirmation route.
    ccontrol_src: Option<SocketAddr>,
    peer: SocketAddr,
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

impl RpcTransport for UdpTransport {
    fn send_request(&mut self, data: &[u8]) -> Result<(), String> {
        self.socket
            .send_to(data, self.peer)
            .map(|_| ())
            .map_err(|e| format!("Socket error: {e}"))
    }

    fn recv_response(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| format!("Socket error: {e}"))?;
        // Full 64 KiB: a 4096-byte buffer silently truncated any response larger
        // than the default READ_LENGTH (RPC+NRD+IOD headers push a 4096-byte
        // record over 4 KiB), returning short data as Ok.
        let mut buf = [0u8; 65535];
        match self.socket.recv_from(&mut buf) {
            Ok((n, _)) => Ok(Some(buf[..n].to_vec())),
            Err(e) if is_timeout(&e) => Ok(None),
            Err(e) => Err(format!("Socket error: {e}")),
        }
    }

    fn recv_ccontrol(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        if self.ccontrol_socket.is_none() {
            self.ccontrol_socket = Some(bind_ccontrol_socket()?);
        }
        let sock = self
            .ccontrol_socket
            .as_ref()
            .expect("ccontrol socket bound above");
        sock.set_read_timeout(Some(timeout))
            .map_err(|e| format!("Socket error: {e}"))?;
        // Full 64 KiB: a 4096-byte buffer silently truncated any response larger
        // than the default READ_LENGTH (RPC+NRD+IOD headers push a 4096-byte
        // record over 4 KiB), returning short data as Ok.
        let mut buf = [0u8; 65535];
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                self.ccontrol_src = Some(addr);
                Ok(Some(buf[..n].to_vec()))
            }
            Err(e) if is_timeout(&e) => Ok(None),
            Err(e) => Err(format!("Socket error: {e}")),
        }
    }

    fn reply_ccontrol(&mut self, data: &[u8]) -> Result<(), String> {
        let addr = self
            .ccontrol_src
            .ok_or("No CControl received to reply to")?;
        self.ccontrol_socket
            .as_ref()
            .ok_or("CControl socket not bound")?
            .send_to(data, addr)
            .map(|_| ())
            .map_err(|e| format!("Socket error: {e}"))
    }

    fn peer(&self) -> String {
        self.peer.to_string()
    }
}

/// The raw-L2 RPC transport: a single [`RawUdp`] capture carrying both flows,
/// plus the source UDP port of the last CControl datagram so the confirmation
/// can leave from 34964 back to it.
#[derive(Debug)]
struct RawL2Transport {
    raw: RawUdp,
    ccontrol_src: Option<u16>,
}

impl RpcTransport for RawL2Transport {
    fn send_request(&mut self, data: &[u8]) -> Result<(), String> {
        self.raw.send_to(data, RPC_PORT)
    }

    fn recv_response(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        // The response comes from a dynamic device port, so any UDP source
        // port is accepted; parse_rpc_response still filters by packet type.
        Ok(self.raw.recv_from(timeout)?.map(|(payload, _src)| payload))
    }

    fn recv_ccontrol(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        match self.raw.recv_from(timeout)? {
            Some((payload, src_port)) => {
                self.ccontrol_src = Some(src_port);
                Ok(Some(payload))
            }
            None => Ok(None),
        }
    }

    fn reply_ccontrol(&mut self, data: &[u8]) -> Result<(), String> {
        let src_port = self
            .ccontrol_src
            .ok_or("No CControl received to reply to")?;
        // The device addressed our well-known port 34964, so the DONE
        // confirmation must leave from 34964 too, back to the device port
        // that sent the CControl.
        self.raw.send_to_from(data, RPC_PORT, src_port)
    }

    fn peer(&self) -> String {
        crate::util::s2ip(&self.raw.dst_ip()).unwrap_or_else(|_| "device".to_string())
    }
}

/// PROFINET DCE/RPC connection to an IO-Device (RPCCon): UDP transport
/// composing the byte builders in `crate::rpc` / `crate::connect` with the
/// pure response parsers above.
#[derive(Debug)]
pub struct RpcConn {
    transport: Box<dyn RpcTransport>,
    pub object_uuid: [u8; 16],
    pub activity_uuid: [u8; 16],
    pub ar_uuid: [u8; 16],
    pub session_key: u16,
    sequence_number: u32,
    timeout: Duration,
    /// Frame IDs assigned by the device in the connect response.
    pub input_frame_id: u16,
    pub output_frame_id: u16,
    connected: bool,
}

impl RpcConn {
    /// Set up a connection to `device_ip:34964` as `RPCCon.__init__`: remote
    /// object UUID from the device/vendor IDs (DCP discovery), random
    /// ar_uuid/activity_uuid and a random non-zero session key per
    /// IEC 61158, plus the pre-bound CControl listener.
    pub fn new(
        device_ip: &str,
        device_id: u16,
        vendor_id: u16,
        timeout: Duration,
    ) -> Result<Self, String> {
        let peer: SocketAddr = format!("{device_ip}:{RPC_PORT}")
            .parse()
            .map_err(|e| format!("Invalid device IP {device_ip}: {e}"))?;
        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("UDP socket bind failed: {e}"))?;
        let transport = UdpTransport {
            socket,
            // Best-effort at init, exactly like the reference; retried in
            // application_ready() if the port was busy here.
            ccontrol_socket: bind_ccontrol_socket().ok(),
            ccontrol_src: None,
            peer,
        };
        Self::with_transport(Box::new(transport), device_id, vendor_id, timeout)
    }

    /// Set up a connection over raw L2 (`RawUdp`) instead of `std::net` UDP
    /// sockets: same UUID/session-key setup, but the DCE/RPC datagrams are
    /// sent and captured as hand-built Ethernet+IPv4+UDP frames on `iface`,
    /// bypassing the macOS IP stack (Local Network privacy drops inbound
    /// LAN UDP to the sockets otherwise). The local UDP port is a random
    /// ephemeral one, like the reference's 0.0.0.0:0 bind.
    #[allow(clippy::too_many_arguments)]
    pub fn new_raw(
        iface: &str,
        src_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_mac: [u8; 6],
        dst_ip: [u8; 4],
        device_id: u16,
        vendor_id: u16,
        timeout: Duration,
    ) -> Result<Self, String> {
        let local_port = 49152 + u16::from_be_bytes(random_bytes::<2>()?) % 16384;
        let raw = RawUdp::open(iface, src_mac, src_ip, dst_mac, dst_ip, local_port)?;
        let transport = RawL2Transport {
            raw,
            ccontrol_src: None,
        };
        Self::with_transport(Box::new(transport), device_id, vendor_id, timeout)
    }

    fn with_transport(
        transport: Box<dyn RpcTransport>,
        device_id: u16,
        vendor_id: u16,
        timeout: Duration,
    ) -> Result<Self, String> {
        let [dev_high, dev_low] = device_id.to_be_bytes();
        let [ven_high, ven_low] = vendor_id.to_be_bytes();
        let session_key = match u16::from_be_bytes(random_bytes::<2>()?) {
            0 => 1, // random, non-zero
            k => k,
        };
        Ok(RpcConn {
            transport,
            object_uuid: rpc::object_uuid(dev_high, dev_low, ven_high, ven_low),
            activity_uuid: random_bytes()?,
            ar_uuid: random_bytes()?,
            session_key,
            sequence_number: 0,
            timeout,
            input_frame_id: 0,
            output_frame_id: 0,
            connected: false,
        })
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.sequence_number;
        self.sequence_number += 1;
        seq
    }

    /// Send an RPC request and receive the matching response
    /// (`_send_receive`): recv loop under a wall-clock deadline, skipping
    /// echoed REQUEST packets, DREP-aware header parse, error on
    /// FAULT/REJECT/timeout.
    fn send_receive(&mut self, rpc_bytes: &[u8]) -> Result<ParsedRpc, String> {
        let deadline = Instant::now() + self.timeout;
        // Match the response to THIS request by activity UUID + sequence number.
        // Both are read with each packet's own DREP, so the numeric compare is
        // byte-order independent.
        let req = parse_rpc_header(rpc_bytes)
            .ok_or_else(|| "outgoing RPC request too short to parse header".to_string())?;
        self.transport.send_request(rpc_bytes)?;
        let peer = self.transport.peer();
        let transport = self.transport.as_mut();
        next_rpc_response(
            || {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|r| !r.is_zero())
                    .ok_or_else(|| format!("No response from {peer}"))?;
                transport
                    .recv_response(remaining)?
                    .ok_or_else(|| format!("No response from {peer}"))
            },
            &drep_normalized_uuid(&req.activity_uuid, req.is_little_endian),
            req.sequence_number,
        )
    }

    /// Establish the AR with cyclic IO (`connect()` with an IOCRSetup):
    /// ARBlockReq + IOCRs + AlarmCR + ExpectedSubmodule, then parse the
    /// response blocks for the assigned frame IDs.
    pub fn connect(
        &mut self,
        cm_mac: &[u8; 6],
        cm_station_name: &[u8],
        setup: &IocrSetup,
    ) -> Result<ConnectResult, String> {
        let seq = self.next_seq();
        let req = crate::connect::build_connect_request(
            &self.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &self.activity_uuid,
            &self.ar_uuid,
            self.session_key,
            cm_mac,
            cm_station_name,
            setup,
            seq,
        );
        let resp = self.send_receive(&req)?;
        let result = parse_connect_response(&resp.payload, resp.is_little_endian)
            .map_err(|e| format!("Failed to connect: {e}"))?;
        self.input_frame_id = result.input_frame_id;
        self.output_frame_id = result.output_frame_id;
        self.connected = true;
        Ok(result)
    }

    /// Establish a Device-Access AR for acyclic read/write only (`connect()`
    /// without an IOCRSetup): a lone ARBlockReq with AR type IOSAR and the
    /// DeviceAccess ARProperties, no cyclic IOCRs, so no frame IDs are
    /// assigned in the response.
    pub fn connect_device_access(
        &mut self,
        cm_mac: &[u8; 6],
        cm_station_name: &[u8],
    ) -> Result<(), String> {
        let seq = self.next_seq();
        let req = crate::connect::build_device_access_connect_request(
            &self.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &self.activity_uuid,
            &self.ar_uuid,
            self.session_key,
            cm_mac,
            cm_station_name,
            seq,
        );
        let resp = self.send_receive(&req)?;
        parse_status_response(&resp.payload, resp.is_little_endian)
            .map_err(|e| format!("Failed to connect: {e}"))?;
        self.connected = true;
        Ok(())
    }

    /// Send a CONTROL operation request (`_send_control`): the IODControlReq
    /// block for `block_type`/`control_command` plus optional sub-blocks
    /// appended after it, returning the response NRD payload.
    pub fn send_control(
        &mut self,
        block_type: u16,
        control_command: u16,
        sub_blocks: &[u8],
    ) -> Result<Vec<u8>, String> {
        if !self.connected {
            return Err("Not connected".to_string());
        }
        let mut payload =
            iod_control_block(block_type, &self.ar_uuid, self.session_key, control_command);
        payload.extend_from_slice(sub_blocks);
        let seq = self.next_seq();
        let req = rpc::rpc_request(
            &self.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &self.activity_uuid,
            seq,
            rpc::CONTROL,
            &rpc::nrd(&payload),
        );
        let resp = self.send_receive(&req)?;
        parse_status_response(&resp.payload, resp.is_little_endian)
    }

    /// Send the PrmEnd control command ending the parameter phase
    /// (`prm_end` via `_send_control`), returning the response NRD payload.
    pub fn prm_end(&mut self) -> Result<Vec<u8>, String> {
        self.send_control(BLOCK_IOD_CONTROL_PRM_END_REQ, CONTROL_CMD_PRM_END, &[])
            .map_err(|e| format!("PrmEnd failed: {e}"))
    }

    /// Send the PrmBegin control command starting (re-)parameterization
    /// (`prm_begin` via `_send_control`), returning the response NRD payload.
    pub fn prm_begin(&mut self) -> Result<Vec<u8>, String> {
        self.send_control(BLOCK_PRM_BEGIN_REQ, CONTROL_CMD_PRM_BEGIN, &[])
            .map_err(|e| format!("PrmBegin failed: {e}"))
    }

    /// Wait for the device's CControl ApplicationReady on the 34964 listener
    /// and confirm it with DONE (`application_ready`), returning the NRD
    /// body of the device's request.
    pub fn application_ready(&mut self, timeout: Duration) -> Result<Vec<u8>, String> {
        if !self.connected {
            return Err("Not connected".to_string());
        }
        let deadline = Instant::now() + timeout;
        let ar_uuid = self.ar_uuid;
        let session_key = self.session_key;
        let peer = self.transport.peer();
        let timeout_err = || {
            format!(
                "No ApplicationReady from {peer} within {:.0}s",
                timeout.as_secs_f64()
            )
        };
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|r| !r.is_zero())
                .ok_or_else(timeout_err)?;
            let Some(payload) = self.transport.recv_ccontrol(remaining)? else {
                return Err(timeout_err());
            };
            // Ignore anything that is not a CControl ApplicationReady, like
            // the reference does.
            let Some((hdr, cc)) = extract_app_ready(&payload) else {
                continue;
            };
            // control_command other than APPLICATION_READY only warns in the
            // reference; the confirmation is sent regardless, back to the
            // source the transport recorded.
            let resp = ccontrol_response(&hdr, &ar_uuid, session_key);
            self.transport.reply_ccontrol(&resp)?;
            return Ok(cc.nrd_body);
        }
    }

    /// Read a data record via slot/subslot/index (`read()` with api=0),
    /// returning the raw record payload.
    pub fn read_raw(
        &mut self,
        idx: u16,
        slot: u16,
        subslot: u16,
        length: u32,
    ) -> Result<Vec<u8>, String> {
        let seq = self.next_seq();
        let req = rpc::read_record_request(
            &self.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &self.activity_uuid,
            &self.ar_uuid,
            seq,
            0,
            slot,
            subslot,
            idx,
            length,
        );
        let resp = self.send_receive(&req)?;
        parse_read_response(&resp.payload, resp.is_little_endian)
    }

    /// Read I&M0 identification data (`read_im0`; reference defaults
    /// slot=0, subslot=1).
    pub fn read_im0(&mut self, slot: u16, subslot: u16) -> Result<im::InM0, String> {
        let payload = self.read_raw(im::InM0::IDX, slot, subslot, READ_LENGTH)?;
        im::parse_im0(&payload)
    }

    /// Read I&M1 tag function/location data (`read_im1`).
    pub fn read_im1(&mut self, slot: u16, subslot: u16) -> Result<im::InM1, String> {
        let payload = self.read_raw(im::InM1::IDX, slot, subslot, READ_LENGTH)?;
        im::parse_im1(&payload)
    }

    /// Read I&M2 installation date data (`read_im2`).
    pub fn read_im2(&mut self, slot: u16, subslot: u16) -> Result<im::InM2, String> {
        let payload = self.read_raw(im::InM2::IDX, slot, subslot, READ_LENGTH)?;
        im::parse_im2(&payload)
    }

    /// Read I&M3 descriptor data (`read_im3`).
    pub fn read_im3(&mut self, slot: u16, subslot: u16) -> Result<im::InM3, String> {
        let payload = self.read_raw(im::InM3::IDX, slot, subslot, READ_LENGTH)?;
        im::parse_im3(&payload)
    }

    /// Read and parse PDRealData 0xF841 (`read_pd_real_data`; the reference
    /// reads at slot=0, subslot=1).
    pub fn read_pd_real_data(&mut self) -> Result<im::PdRealData, String> {
        let payload = self.read_raw(im::PD_REAL_DATA, 0, 1, READ_LENGTH)?;
        Ok(im::parse_pd_real_data(&payload))
    }

    /// Read and parse RealIdentificationData 0xF000
    /// (`read_real_identification_data`; slot=0, subslot=1).
    pub fn read_real_identification_data(&mut self) -> Result<im::RealIdentificationData, String> {
        let payload = self.read_raw(im::REAL_ID_API, 0, 1, READ_LENGTH)?;
        Ok(im::parse_real_identification_data(&payload))
    }

    /// Discover all slots/subslots from RealIdentificationData
    /// (`discover_slots`), as the slot type consumed by
    /// [`crate::gsdml::GsdmlDevice::build_io_slots_from_device`].
    pub fn discover_slots(&mut self) -> Result<Vec<crate::gsdml::DeviceSlot>, String> {
        let real_id = self.read_real_identification_data()?;
        Ok(real_id
            .slots
            .iter()
            .map(im::SlotInfo::to_device_slot)
            .collect())
    }

    /// Read I&M0FilterData 0xF840, the module/submodule topology
    /// (`read_inm0filter`; the reference reads at slot=0, subslot=0).
    pub fn read_inm0_filter(&mut self) -> Result<im::InM0FilterData, String> {
        let payload = self.read_raw(im::IM0_FILTER_DATA, 0, 0, READ_LENGTH)?;
        im::parse_inm0_filter(&payload)
    }

    /// Read and parse diagnosis data (`read_diagnosis`; the reference
    /// defaults slot=0, subslot=0, index=0xF000 for all diagnosis; other
    /// indices: 0x800A/0x800B/0x800C slot/subslot level, 0xF00A/0xF00B API
    /// level). Read errors yield an empty [`diagnosis::DiagnosisData`], like
    /// the reference's RPCError swallow.
    pub fn read_diagnosis(
        &mut self,
        slot: u16,
        subslot: u16,
        index: u16,
    ) -> diagnosis::DiagnosisData {
        match self.read_raw(index, slot, subslot, READ_LENGTH) {
            Ok(data) if data.len() > 6 => {
                // Try full parsing first; fall back to the simpler format
                // when no entries were found.
                let result = diagnosis::parse_diagnosis_block(&data, 0, slot, subslot);
                if result.entries.is_empty() {
                    diagnosis::parse_diagnosis_simple(&data, 0, slot, subslot)
                } else {
                    result
                }
            }
            Ok(data) => diagnosis::DiagnosisData {
                slot,
                subslot,
                raw_data: data,
                ..diagnosis::DiagnosisData::default()
            },
            Err(_) => diagnosis::DiagnosisData {
                slot,
                subslot,
                ..diagnosis::DiagnosisData::default()
            },
        }
    }

    /// Read diagnosis from all standard indices (`read_all_diagnosis`),
    /// keeping only the ones with entries.
    pub fn read_all_diagnosis(&mut self) -> BTreeMap<u16, diagnosis::DiagnosisData> {
        const DIAGNOSIS_INDICES: [(u16, u16, u16); 6] = [
            (0x800A, 0, 0), // Channel diagnosis for slot 0.
            (0x800B, 0, 0), // All diagnosis for slot 0.
            (0x800C, 0, 1), // Channel diagnosis for subslot 1.
            (0xF000, 0, 0), // All diagnosis data (device level).
            (0xF00A, 0, 0), // Channel diagnosis (API level).
            (0xF00B, 0, 0), // All diagnosis (API level).
        ];
        let mut results = BTreeMap::new();
        for (idx, slot, subslot) in DIAGNOSIS_INDICES {
            let diag = self.read_diagnosis(slot, subslot, idx);
            if !diag.entries.is_empty() {
                results.insert(idx, diag);
            }
        }
        results
    }

    /// Write a data record via slot/subslot/index (`write()` with api=0).
    pub fn write(&mut self, idx: u16, slot: u16, subslot: u16, data: &[u8]) -> Result<(), String> {
        let seq = self.next_seq();
        let req = rpc::write_record_request(
            &self.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &self.activity_uuid,
            &self.ar_uuid,
            seq,
            0,
            slot,
            subslot,
            idx,
            data,
        );
        let resp = self.send_receive(&req)?;
        parse_status_response(&resp.payload, resp.is_little_endian).map(|_| ())
    }

    /// Write multiple records atomically via IODWriteMultipleReq 0xE040
    /// (`write_multiple`). Entries are (idx, slot, subslot, data) with api=0,
    /// mirroring [`RpcConn::write`]'s argument order; one result per write.
    pub fn write_multiple(
        &mut self,
        writes: &[(u16, u16, u16, &[u8])],
    ) -> Result<Vec<crate::blocks::WriteMultipleResult>, String> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }
        let entries: Vec<crate::blocks::MultiWrite> = writes
            .iter()
            .map(|&(idx, slot, subslot, data)| (0u32, slot, subslot, idx, data))
            .collect();
        let seq = self.next_seq();
        let req = rpc::write_multiple_request(
            &self.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &self.activity_uuid,
            &self.ar_uuid,
            seq,
            &entries,
        );
        let resp = self.send_receive(&req)?;
        let nrd_payload = parse_status_response(&resp.payload, resp.is_little_endian)?;
        Ok(crate::blocks::parse_write_multiple_response(&nrd_payload))
    }

    /// Send the Release request terminating the AR (`disconnect()`):
    /// fire-and-forget best effort like the reference — a send failure only
    /// ends the local AR state; no response is awaited.
    pub fn release(&mut self) {
        if !self.connected {
            return;
        }
        let seq = self.next_seq();
        let req = release_request(
            &self.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &self.activity_uuid,
            &self.ar_uuid,
            self.session_key,
            seq,
        );
        // Fire-and-forget best effort, like the reference: a send failure
        // only ends the local AR state; no response is awaited.
        let _ = self.transport.send_request(&req);
        self.connected = false;
    }
}

/// Release the AR on every exit path (early return via `?`, panic unwind,
/// scope exit), so a crashed CLI never leaves the device holding a dead AR.
/// `release` is idempotent via the `connected` flag, so an explicit release
/// beforehand makes this a no-op.
impl Drop for RpcConn {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    //! Orchestration tests for `RpcConn` driven through the `RpcTransport`
    //! port. A `ScriptedTransport` records the exact request datagrams the
    //! connection emits and replays real device-format response bytes (built
    //! with the same wire builders/parsers the code uses), so every
    //! send/parse/error path is covered deterministically without a NIC. A
    //! separate loopback test exercises the real `UdpTransport` socket adapter
    //! over 127.0.0.1.

    use super::*;
    use crate::connect::IocrSetup;
    use crate::gsdml::IoSlot;
    use std::collections::VecDeque;
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};

    const DEVICE_ID: u16 = 0x0007;
    const VENDOR_ID: u16 = 0x0abc;

    // --- device-format datagram builders (real wire bytes) -------------------

    /// An 80-byte big-endian DCE/RPC datagram with the given packet type,
    /// operation number and body.
    fn rpc_datagram(packet_type: u8, opnum: u16, body: &[u8]) -> Vec<u8> {
        let mut d = vec![0x04, packet_type, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        d.extend_from_slice(&[0u8; 48]); // object/interface/activity UUIDs
        d.extend_from_slice(&0u32.to_be_bytes()); // server_boot_time
        d.extend_from_slice(&1u32.to_be_bytes()); // interface_version
        d.extend_from_slice(&0u32.to_be_bytes()); // sequence_number
        d.extend_from_slice(&opnum.to_be_bytes()); // operation_number
        d.extend_from_slice(&0xFFFFu16.to_be_bytes()); // interface_hint
        d.extend_from_slice(&0xFFFFu16.to_be_bytes()); // activity_hint
        d.extend_from_slice(&(body.len() as u16).to_be_bytes()); // length_of_body
        d.extend_from_slice(&0u16.to_be_bytes()); // fragment_number
        d.push(0); // auth_protocol
        d.push(0); // serial_low
        d.extend_from_slice(body);
        d
    }

    fn rpc_response(body: &[u8]) -> Vec<u8> {
        rpc_datagram(PACKET_TYPE_RESPONSE, 0, body)
    }

    /// A 20-byte big-endian NRD header (args_status = PNIO status on responses)
    /// followed by the argument body.
    fn nrd_be(args_status: u32, body: &[u8]) -> Vec<u8> {
        let len = body.len() as u32;
        let mut n = Vec::new();
        n.extend_from_slice(&args_status.to_be_bytes());
        n.extend_from_slice(&len.to_be_bytes()); // args_length
        n.extend_from_slice(&len.to_be_bytes()); // maximum_count
        n.extend_from_slice(&0u32.to_be_bytes()); // offset
        n.extend_from_slice(&len.to_be_bytes()); // actual_count
        n.extend_from_slice(body);
        n
    }

    fn iocr_block_res(iocr_type: u16, frame_id: u16) -> Vec<u8> {
        let mut b = crate::blocks::block_header(IOCR_BLOCK_RES, 8, 1, 0);
        b.extend_from_slice(&iocr_type.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes()); // iocr_reference
        b.extend_from_slice(&frame_id.to_be_bytes());
        b
    }

    /// A 64-byte IOD response record header (fields irrelevant to the parser)
    /// carrying `record` as its payload.
    fn iod_record(record: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[36..40].copy_from_slice(&(record.len() as u32).to_be_bytes()); // length
        d.extend_from_slice(record);
        d
    }

    /// A device-initiated CControl ApplicationReady REQUEST datagram.
    fn app_ready_request(ar_uuid: &[u8; 16], session_key: u16) -> Vec<u8> {
        let block = iod_control_block(
            BLOCK_IOD_CONTROL_APP_READY_REQ,
            ar_uuid,
            session_key,
            CONTROL_CMD_APPLICATION_READY,
        );
        rpc_datagram(PACKET_TYPE_REQUEST, rpc::CONTROL, &nrd_be(0, &block))
    }

    // --- scripted transport double -------------------------------------------

    #[derive(Debug, Default)]
    struct ScriptState {
        sent: Vec<Vec<u8>>,
        responses: VecDeque<Vec<u8>>,
        ccontrol: VecDeque<Vec<u8>>,
        ccontrol_replies: Vec<Vec<u8>>,
    }

    #[derive(Debug, Default)]
    struct ScriptedTransport {
        state: Arc<Mutex<ScriptState>>,
    }

    impl RpcTransport for ScriptedTransport {
        fn send_request(&mut self, data: &[u8]) -> Result<(), String> {
            self.state.lock().unwrap().sent.push(data.to_vec());
            Ok(())
        }
        fn recv_response(&mut self, _timeout: Duration) -> Result<Option<Vec<u8>>, String> {
            let mut st = self.state.lock().unwrap();
            let Some(mut resp) = st.responses.pop_front() else {
                return Ok(None);
            };
            // A real device echoes the request's activity UUID (offset 40) and
            // sequence number (offset 64); patch the canned response to the last
            // request so send_receive's response-matching accepts it (the conn's
            // UUID is random per run, so a static response can't match otherwise).
            if let Some(req) = st.sent.last() {
                if resp.len() >= 68 && req.len() >= 68 {
                    resp[40..56].copy_from_slice(&req[40..56]);
                    resp[64..68].copy_from_slice(&req[64..68]);
                }
            }
            Ok(Some(resp))
        }
        fn recv_ccontrol(&mut self, _timeout: Duration) -> Result<Option<Vec<u8>>, String> {
            Ok(self.state.lock().unwrap().ccontrol.pop_front())
        }
        fn reply_ccontrol(&mut self, data: &[u8]) -> Result<(), String> {
            self.state
                .lock()
                .unwrap()
                .ccontrol_replies
                .push(data.to_vec());
            Ok(())
        }
        fn peer(&self) -> String {
            "scripted-device".to_string()
        }
    }

    #[test]
    fn next_rpc_response_skips_foreign_and_stale_responses() {
        // A valid RESPONSE datagram with a patched activity UUID (offset 40) +
        // sequence number (offset 64).
        let with = |uuid: [u8; 16], seq: u32| {
            let mut d = rpc_response(&nrd_be(0, &[0xAA; 4]));
            d[40..56].copy_from_slice(&uuid);
            d[64..68].copy_from_slice(&seq.to_be_bytes()); // rpc_datagram DREP is big-endian
            d
        };
        let expected = [0xABu8; 16];
        let foreign = with([0xCD; 16], 42); // another controller / spoof
        let stale = with(expected, 41); // our uuid, previous request's seq
        let ours = with(expected, 42);
        let mut q = std::collections::VecDeque::from([foreign, stale, ours]);
        let resp = next_rpc_response(
            || q.pop_front().ok_or_else(|| "empty".to_string()),
            &expected,
            42,
        )
        .expect("should skip the two non-matching and return ours");
        assert_eq!(resp.activity_uuid, expected);
        assert_eq!(resp.sequence_number, 42);
    }

    fn scripted_conn() -> (RpcConn, Arc<Mutex<ScriptState>>) {
        let transport = ScriptedTransport::default();
        let state = Arc::clone(&transport.state);
        let conn = RpcConn::with_transport(
            Box::new(transport),
            DEVICE_ID,
            VENDOR_ID,
            Duration::from_millis(50),
        )
        .expect("scripted conn");
        (conn, state)
    }

    /// Queue a raw response datagram for the next `recv_response`.
    fn queue(state: &Arc<Mutex<ScriptState>>, datagram: Vec<u8>) {
        state.lock().unwrap().responses.push_back(datagram);
    }

    /// Queue an RPC response wrapping an NRD with the given PNIO status + body.
    fn queue_status(state: &Arc<Mutex<ScriptState>>, status: u32, body: &[u8]) {
        queue(state, rpc_response(&nrd_be(status, body)));
    }

    /// Queue a successful RPC response wrapping `body` (PNIO status 0).
    fn queue_ok(state: &Arc<Mutex<ScriptState>>, body: &[u8]) {
        queue_status(state, 0, body);
    }

    /// Queue a device-initiated CControl datagram for the next `recv_ccontrol`.
    fn queue_ccontrol(state: &Arc<Mutex<ScriptState>>, datagram: Vec<u8>) {
        state.lock().unwrap().ccontrol.push_back(datagram);
    }

    fn sample_setup() -> IocrSetup {
        IocrSetup {
            io_slots: vec![IoSlot {
                slot: 1,
                subslot: 1,
                module_ident: 0x0000_0002,
                submodule_ident: 0x0000_0001,
                input_length: 40,
                output_length: 1,
            }],
            send_clock_factor: 32,
            reduction_ratio: 128,
            watchdog_factor: 6,
            data_hold_factor: 6,
        }
    }

    /// `RpcConn` must keep the `Send` auto-trait the pre-`RpcTransport`
    /// `Endpoint` enum had, so a connection can move into a worker thread. This
    /// fails to compile if the `RpcTransport: Send` bound is ever dropped.
    #[test]
    fn rpc_conn_stays_send() {
        fn assert_send<T: Send>() {}
        assert_send::<RpcConn>();
    }

    // --- connect -------------------------------------------------------------

    #[test]
    fn connect_builds_exact_request_and_parses_frame_ids() {
        let (mut conn, state) = scripted_conn();
        let body = [iocr_block_res(1, 0xC001), iocr_block_res(2, 0xC000)].concat();
        queue_ok(&state, &body);

        let cm_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let setup = sample_setup();
        let result = conn.connect(&cm_mac, b"tp", &setup).expect("connect");

        assert_eq!(result.input_frame_id, 0xC001);
        assert_eq!(result.output_frame_id, 0xC000);
        assert!(result.has_cyclic);
        assert_eq!(conn.input_frame_id, 0xC001);
        assert!(conn.connected);

        // The emitted request is byte-exact the connect builder's output.
        let expected = crate::connect::build_connect_request(
            &conn.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &conn.activity_uuid,
            &conn.ar_uuid,
            conn.session_key,
            &cm_mac,
            b"tp",
            &setup,
            0,
        );
        assert_eq!(state.lock().unwrap().sent, vec![expected]);
    }

    #[test]
    fn connect_rejected_on_nonzero_pnio_status() {
        let (mut conn, state) = scripted_conn();
        queue_status(&state, 0x00B0_80DE, &[]);
        let err = conn.connect(&[0u8; 6], b"tp", &sample_setup()).unwrap_err();
        assert!(err.contains("Failed to connect"), "got {err}");
        assert!(!conn.connected);
    }

    #[test]
    fn connect_device_access_builds_exact_request() {
        let (mut conn, state) = scripted_conn();
        queue_ok(&state, &[]);
        let cm_mac = [0x0A; 6];
        conn.connect_device_access(&cm_mac, b"tp")
            .expect("da connect");
        assert!(conn.connected);
        let expected = crate::connect::build_device_access_connect_request(
            &conn.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &conn.activity_uuid,
            &conn.ar_uuid,
            conn.session_key,
            &cm_mac,
            b"tp",
            0,
        );
        assert_eq!(state.lock().unwrap().sent, vec![expected]);
    }

    // --- read / write --------------------------------------------------------

    #[test]
    fn read_raw_returns_record_and_builds_exact_request() {
        let (mut conn, state) = scripted_conn();
        let record = vec![0xDE, 0xAD, 0xBE, 0xEF];
        queue_ok(&state, &iod_record(&record));

        let got = conn.read_raw(4660, 1, 1, 4).expect("read");
        assert_eq!(got, record);

        let expected = rpc::read_record_request(
            &conn.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &conn.activity_uuid,
            &conn.ar_uuid,
            0,
            0,
            1,
            1,
            4660,
            4,
        );
        assert_eq!(state.lock().unwrap().sent, vec![expected]);
    }

    #[test]
    fn read_raw_surfaces_pnio_error() {
        let (mut conn, state) = scripted_conn();
        queue_status(&state, 0x00B0_80DE, &[]);
        let err = conn.read_raw(1001, 2, 1, 4).unwrap_err();
        assert!(err.contains("PNIO error status"), "got {err}");
    }

    #[test]
    fn read_raw_error_keeps_hex_and_appends_decode() {
        // On the wire the args_status reads big-endian as ErrorCode-first, e.g.
        // 0xDE80B000 = invalid index (bench-observed contract status). The error
        // string must keep the raw hex (classify_pnio/BUSY-retry match it as a
        // substring) AND append the decoded message for humans.
        let (mut conn, state) = scripted_conn();
        queue_status(&state, 0xDE80_B000, &[]);
        let err = conn.read_raw(2001, 2, 1, 4).unwrap_err();
        assert!(err.contains("DE80B000"), "raw hex lost: {err}");
        assert!(err.contains("Index not supported"), "decode missing: {err}");
    }

    // The little-endian answer case: a big-endian request and a little-endian
    // response carry the SAME activity UUID, but the
    // time_low/mid/hi fields are byte-swapped by the opposite DREP. A raw compare
    // rejected the valid response ("No response from device"); the normalized
    // compare must accept it.
    const REQ_UUID_BE: [u8; 16] = [
        0x11, 0xb8, 0xbe, 0xab, 0xc8, 0x57, 0xca, 0xbb, 0x64, 0xf5, 0x01, 0xde, 0xdc, 0x33, 0x5b,
        0x4e,
    ];
    const RESP_UUID_LE: [u8; 16] = [
        0xab, 0xbe, 0xb8, 0x11, 0x57, 0xc8, 0xbb, 0xca, 0x64, 0xf5, 0x01, 0xde, 0xdc, 0x33, 0x5b,
        0x4e,
    ];

    #[test]
    fn drep_normalized_uuid_canonicalizes_opposite_dreps() {
        // Both DREPs normalize to the same canonical (big-endian) UUID.
        assert_eq!(drep_normalized_uuid(&REQ_UUID_BE, false), REQ_UUID_BE);
        assert_eq!(drep_normalized_uuid(&RESP_UUID_LE, true), REQ_UUID_BE);
        // The trailing clock_seq+node bytes are never swapped.
        assert_eq!(
            drep_normalized_uuid(&RESP_UUID_LE, true)[8..],
            RESP_UUID_LE[8..]
        );
    }

    #[test]
    fn next_rpc_response_accepts_opposite_drep_uuid() {
        // Build an LE-DREP response frame carrying the device's byte-swapped
        // UUID; the expected UUID is the normalized (BE) form of our request.
        let mut resp = rpc_datagram(PACKET_TYPE_RESPONSE, 0, &[]);
        resp[4] = 0x10; // little-endian DREP, as some devices answer
        resp[40..56].copy_from_slice(&RESP_UUID_LE);
        let mut packets = std::collections::VecDeque::from([resp]);
        let got = next_rpc_response(
            || packets.pop_front().ok_or_else(|| "timeout".to_string()),
            &REQ_UUID_BE,
            0,
        )
        .expect("device response accepted despite opposite DREP");
        assert_eq!(got.packet_type, PACKET_TYPE_RESPONSE);
    }

    #[test]
    fn write_ok_and_builds_exact_request() {
        let (mut conn, state) = scripted_conn();
        queue_ok(&state, &[]);
        let data = [0x01, 0x02, 0x03, 0x04];
        conn.write(6001, 2, 1, &data).expect("write");
        let expected = rpc::write_record_request(
            &conn.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &conn.activity_uuid,
            &conn.ar_uuid,
            0,
            0,
            2,
            1,
            6001,
            &data,
        );
        assert_eq!(state.lock().unwrap().sent, vec![expected]);
    }

    #[test]
    fn write_multiple_empty_is_noop() {
        let (mut conn, state) = scripted_conn();
        assert_eq!(conn.write_multiple(&[]).unwrap(), vec![]);
        assert!(state.lock().unwrap().sent.is_empty()); // nothing sent
    }

    #[test]
    fn write_multiple_parses_results() {
        // One IODWriteMultipleRes entry (0x8008, status = success) inside the
        // outer record.
        let mut entry = vec![0u8; 56];
        entry[0..2].copy_from_slice(&0x8008u16.to_be_bytes()); // IODWriteRes header
        entry[2..4].copy_from_slice(&52u16.to_be_bytes()); // block_length -> size 56
        entry[44..48].copy_from_slice(&0u32.to_be_bytes()); // status = OK
        let record = iod_record(&entry);

        let (mut conn, state) = scripted_conn();
        queue_ok(&state, &record);
        let data = [0xAA];
        let results = conn
            .write_multiple(&[(6001, 2, 1, &data)])
            .expect("write_multiple");
        assert_eq!(results.len(), 1);
        assert!(results[0].success());
    }

    #[test]
    fn read_all_diagnosis_collects_nonempty() {
        // A single ChannelDiagnosis block answered for the first index; the
        // other indices time out and are swallowed (empty), so only one entry
        // survives.
        let diag = b"\x00\x10\x00\x08\x01\x00\x00\x01\x00\x00\x80\x00\x00\x01";
        let (mut conn, state) = scripted_conn();
        queue_ok(&state, &iod_record(diag));
        let all = conn.read_all_diagnosis();
        assert_eq!(all.len(), 1);
        assert!(all.contains_key(&0x800A));
    }

    #[test]
    fn read_diagnosis_swallows_read_error() {
        // No queued response -> read_raw times out -> empty DiagnosisData.
        let (mut conn, _state) = scripted_conn();
        let diag = conn.read_diagnosis(0, 0, 0x800A);
        assert!(diag.entries.is_empty());
        assert_eq!(diag.slot, 0);
    }

    // --- control / prm_end ---------------------------------------------------

    #[test]
    fn send_control_requires_connection() {
        let (mut conn, _state) = scripted_conn();
        let err = conn.send_control(BLOCK_IOD_CONTROL_PRM_END_REQ, CONTROL_CMD_PRM_END, &[]);
        assert!(err.unwrap_err().contains("Not connected"));
        assert!(conn.prm_end().unwrap_err().contains("PrmEnd failed"));
    }

    #[test]
    fn prm_end_after_connect_succeeds() {
        let (mut conn, state) = scripted_conn();
        let body = [iocr_block_res(1, 0xC001), iocr_block_res(2, 0xC000)].concat();
        queue_ok(&state, &body);
        conn.connect(&[0u8; 6], b"tp", &sample_setup()).unwrap();
        queue_ok(&state, &[]);
        conn.prm_end().expect("prm_end");

        // Two datagrams sent: connect, then a byte-exact PrmEnd CONTROL request
        // (seq 1, opnum CONTROL, an IODControlReq 0x0110 / command PrmEnd 0x0001
        // wrapped in the request NRD).
        let sent = state.lock().unwrap().sent.clone();
        assert_eq!(sent.len(), 2);
        let expected = rpc::rpc_request(
            &conn.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &conn.activity_uuid,
            1,
            rpc::CONTROL,
            &rpc::nrd(&iod_control_block(
                BLOCK_IOD_CONTROL_PRM_END_REQ,
                &conn.ar_uuid,
                conn.session_key,
                CONTROL_CMD_PRM_END,
            )),
        );
        assert_eq!(sent[1], expected);
    }

    // --- send_receive loop: skip / fault / reject / timeout ------------------

    #[test]
    fn send_receive_skips_echoed_request() {
        let (mut conn, state) = scripted_conn();
        // An echoed REQUEST is skipped; the following RESPONSE is used.
        queue(&state, rpc_datagram(PACKET_TYPE_REQUEST, 0, &[]));
        let record = vec![0xAA, 0xBB];
        queue_ok(&state, &iod_record(&record));
        assert_eq!(conn.read_raw(1, 0, 1, 2).unwrap(), record);
    }

    #[test]
    fn send_receive_fault_is_error() {
        let (mut conn, state) = scripted_conn();
        queue(&state, rpc_datagram(PACKET_TYPE_FAULT, 0x1234, &[]));
        assert!(conn.read_raw(1, 0, 1, 2).unwrap_err().contains("RPC fault"));
    }

    #[test]
    fn send_receive_reject_is_error() {
        let (mut conn, state) = scripted_conn();
        queue(&state, rpc_datagram(PACKET_TYPE_REJECT, 0, &[]));
        assert!(conn.read_raw(1, 0, 1, 2).unwrap_err().contains("rejected"));
    }

    #[test]
    fn send_receive_timeout_is_error() {
        let (mut conn, _state) = scripted_conn();
        assert!(conn
            .read_raw(1, 0, 1, 2)
            .unwrap_err()
            .contains("No response"));
    }

    // --- application_ready ---------------------------------------------------

    fn connect_ok(conn: &mut RpcConn, state: &Arc<Mutex<ScriptState>>) {
        let body = [iocr_block_res(1, 0xC001), iocr_block_res(2, 0xC000)].concat();
        queue_ok(state, &body);
        conn.connect(&[0u8; 6], b"tp", &sample_setup()).unwrap();
    }

    #[test]
    fn application_ready_confirms_with_exact_response() {
        let (mut conn, state) = scripted_conn();
        connect_ok(&mut conn, &state);
        let req = app_ready_request(&conn.ar_uuid, conn.session_key);
        queue_ccontrol(&state, req.clone());

        let nrd_body = conn
            .application_ready(Duration::from_millis(50))
            .expect("app ready");
        assert!(!nrd_body.is_empty());

        // The confirmation is byte-exact ccontrol_response for the request.
        let hdr = parse_rpc_header(&req).unwrap();
        let expected = ccontrol_response(&hdr, &conn.ar_uuid, conn.session_key);
        assert_eq!(state.lock().unwrap().ccontrol_replies, vec![expected]);
    }

    #[test]
    fn application_ready_skips_non_appready_datagram() {
        let (mut conn, state) = scripted_conn();
        connect_ok(&mut conn, &state);
        // A stray RESPONSE on the CControl channel is ignored, then the real
        // ApplicationReady is confirmed.
        queue_ccontrol(&state, rpc_response(&nrd_be(0, &[])));
        queue_ccontrol(&state, app_ready_request(&conn.ar_uuid, conn.session_key));
        conn.application_ready(Duration::from_millis(50))
            .expect("app ready");
        assert_eq!(state.lock().unwrap().ccontrol_replies.len(), 1);
    }

    #[test]
    fn application_ready_requires_connection() {
        let (mut conn, _state) = scripted_conn();
        assert!(conn
            .application_ready(Duration::from_millis(10))
            .unwrap_err()
            .contains("Not connected"));
    }

    #[test]
    fn application_ready_times_out() {
        let (mut conn, state) = scripted_conn();
        connect_ok(&mut conn, &state);
        assert!(conn
            .application_ready(Duration::from_millis(10))
            .unwrap_err()
            .contains("No ApplicationReady"));
    }

    // --- release -------------------------------------------------------------

    #[test]
    fn release_sends_exact_frame_and_clears_state() {
        let (mut conn, state) = scripted_conn();
        connect_ok(&mut conn, &state);
        conn.release();
        assert!(!conn.connected);
        // The last datagram sent is a byte-exact release request (seq 1).
        let expected = release_request(
            &conn.object_uuid,
            &rpc::IFACE_UUID_DEVICE,
            &conn.activity_uuid,
            &conn.ar_uuid,
            conn.session_key,
            1,
        );
        assert_eq!(state.lock().unwrap().sent.last().unwrap(), &expected);
    }

    #[test]
    fn release_before_connect_is_noop() {
        let (mut conn, state) = scripted_conn();
        conn.release();
        assert!(state.lock().unwrap().sent.is_empty());
    }

    // --- pure CControl-parse error branches ----------------------------------

    #[test]
    fn parse_ccontrol_request_rejects_non_request_and_short() {
        // A RESPONSE packet is not a CControl request.
        let resp = parse_rpc_header(&rpc_response(&nrd_be(0, &[]))).unwrap();
        assert!(parse_ccontrol_request(&resp)
            .unwrap_err()
            .contains("Not a REQUEST"));

        // A REQUEST with a non-CONTROL opnum is rejected.
        let wrong_op = parse_rpc_header(&rpc_datagram(PACKET_TYPE_REQUEST, 0x00, &[])).unwrap();
        assert!(parse_ccontrol_request(&wrong_op)
            .unwrap_err()
            .contains("Not CONTROL"));

        // A CONTROL request with a < 32-byte NRD payload is too short.
        let short = parse_rpc_header(&rpc_datagram(
            PACKET_TYPE_REQUEST,
            rpc::CONTROL,
            &nrd_be(0, &[1, 2]),
        ))
        .unwrap();
        assert!(parse_ccontrol_request(&short)
            .unwrap_err()
            .contains("too short"));
    }

    #[test]
    fn nrd_and_iod_headers_reject_short_buffers() {
        assert!(parse_nrd(&[0u8; 19], false)
            .unwrap_err()
            .contains("too short"));
        assert!(parse_iod_header(&[0u8; 63])
            .unwrap_err()
            .contains("too short"));
    }

    #[test]
    fn extract_app_ready_ignores_wrong_block_and_response() {
        // A RESPONSE datagram yields no ApplicationReady.
        assert!(extract_app_ready(&rpc_response(&nrd_be(0, &[]))).is_none());
        // A CONTROL request whose block is not 0x0112 is ignored.
        let block = iod_control_block(
            BLOCK_IOD_CONTROL_PRM_END_REQ,
            &[0u8; 16],
            1,
            CONTROL_CMD_DONE,
        );
        let wrong = rpc_datagram(PACKET_TYPE_REQUEST, rpc::CONTROL, &nrd_be(0, &block));
        assert!(extract_app_ready(&wrong).is_none());
    }

    // --- real UdpTransport adapter over loopback -----------------------------

    #[test]
    fn udp_transport_loopback_roundtrip_and_timeout() {
        let device = UdpSocket::bind("127.0.0.1:0").expect("device bind");
        let device_addr = device.local_addr().unwrap();
        let mut transport = UdpTransport {
            socket: UdpSocket::bind("127.0.0.1:0").expect("client bind"),
            ccontrol_socket: None,
            ccontrol_src: None,
            peer: device_addr,
        };

        transport.send_request(b"ping").expect("send");
        let mut buf = [0u8; 16];
        device
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let (n, from) = device.recv_from(&mut buf).expect("device recv");
        assert_eq!(&buf[..n], b"ping");
        device.send_to(b"pong", from).expect("device reply");

        let got = transport
            .recv_response(Duration::from_millis(500))
            .expect("recv");
        assert_eq!(got.as_deref(), Some(&b"pong"[..]));

        // No further data: the timeout maps to None, not an error.
        assert!(transport
            .recv_response(Duration::from_millis(50))
            .unwrap()
            .is_none());
        assert!(transport.peer().contains("127.0.0.1"));
    }
}
