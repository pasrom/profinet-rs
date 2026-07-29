//! Endpoint Mapper (EPM) lookup over UDP 34964 (ncadg_ip_udp), ported from
//! `profinet-py/profinet/rpc.py` (`epm_lookup`, `_parse_epm_tower`,
//! `_uuid_bytes_to_string`, `_string_to_uuid_bytes`, `EPMEndpoint`).
//!
//! Request building and response/tower parsing are pure functions verified
//! against golden vectors. The I/O runs over [`RawUdp`] by default so it
//! works headless on macOS (Local Network privacy silently drops inbound LAN
//! UDP through the IP stack, like the rest of this stack works around); a
//! plain `UdpSocket` variant exists for hosts where LAN UDP is permitted.

use std::net::UdpSocket;
use std::time::Duration;

use crate::rawudp::RawUdp;

/// PROFINET IO RPC port; the EPM answers on it on PROFINET devices.
pub const RPC_PORT: u16 = 0x8894; // 34964

/// RPC UUIDs (DCE/RPC standard / PROFINET), as canonical strings.
pub const UUID_EPM_V4: &str = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";
pub const UUID_PNIO_DEVICE: &str = "dea00001-6c97-11d1-8271-00a02442df7d";
pub const UUID_PNIO_CONTROLLER: &str = "dea00002-6c97-11d1-8271-00a02442df7d";
pub const UUID_PNIO_SUPERVISOR: &str = "dea00003-6c97-11d1-8271-00a02442df7d";
pub const UUID_PNIO_PARAMSERVER: &str = "dea00004-6c97-11d1-8271-00a02442df7d";

/// ept_lookup operation number.
pub const EPM_LOOKUP: u16 = 0x02;
/// Inquiry types: return all entries / filter by interface UUID.
pub const EPM_INQUIRY_ALL: u32 = 0x00;
pub const EPM_INQUIRY_INTERFACE: u32 = 0x01;

fn le16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn le32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// Convert a 16-byte DCE/RPC UUID to string form (`_uuid_bytes_to_string`).
/// DCE/RPC UUIDs are mixed-endian: the first three fields little-endian, the
/// clock_seq and node big-endian. Returns "" if not exactly 16 bytes.
pub fn uuid_bytes_to_string(data: &[u8]) -> String {
    if data.len() != 16 {
        return String::new();
    }
    let node: String = data[10..16].iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{node}",
        le32(data, 0),
        le16(data, 4),
        le16(data, 6),
        u16::from_be_bytes([data[8], data[9]]),
    )
}

/// Convert a UUID string to its 16-byte DCE/RPC mixed-endian form
/// (`_string_to_uuid_bytes`).
pub fn string_to_uuid_bytes(uuid_str: &str) -> Result<[u8; 16], String> {
    let parts: String = uuid_str.chars().filter(|c| *c != '-').collect();
    if parts.len() != 32 {
        return Err(format!("Invalid UUID string: {uuid_str}"));
    }
    let field = |range: std::ops::Range<usize>| -> Result<u64, String> {
        u64::from_str_radix(&parts[range], 16)
            .map_err(|_| format!("Invalid UUID string: {uuid_str}"))
    };
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&(field(0..8)? as u32).to_le_bytes());
    out[4..6].copy_from_slice(&(field(8..12)? as u16).to_le_bytes());
    out[6..8].copy_from_slice(&(field(12..16)? as u16).to_le_bytes());
    out[8..10].copy_from_slice(&(field(16..20)? as u16).to_be_bytes());
    for i in 0..6 {
        out[10 + i] = field(20 + 2 * i..22 + 2 * i)? as u8;
    }
    Ok(out)
}

/// Parsed EPM endpoint entry (EPMEndpoint).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EpmEndpoint {
    pub interface_uuid: String,
    pub interface_version_major: u16,
    pub interface_version_minor: u16,
    pub object_uuid: String,
    pub protocol: String,
    pub port: u16,
    pub address: String,
    /// Device model/article number from the EPM response.
    pub annotation: String,
}

impl EpmEndpoint {
    /// Human-readable interface name (`EPMEndpoint.interface_name`).
    pub fn interface_name(&self) -> String {
        match self.interface_uuid.to_lowercase().as_str() {
            UUID_PNIO_DEVICE => "PNIO-Device".to_string(),
            UUID_PNIO_CONTROLLER => "PNIO-Controller".to_string(),
            UUID_PNIO_SUPERVISOR => "PNIO-Supervisor".to_string(),
            UUID_PNIO_PARAMSERVER => "PNIO-ParameterServer".to_string(),
            UUID_EPM_V4 => "EPM".to_string(),
            _ => format!("Unknown({})", self.interface_uuid),
        }
    }
}

/// Build the EPM lookup request datagram exactly as `epm_lookup` sends it:
/// an 80-byte DCE/RPC v4 header (drep 0x10 = little-endian, interface
/// version 3, opnum ept_lookup, NULL object UUID, EPM interface UUID)
/// followed by the 52-byte lookup body (inquiry type, NULL object UUID,
/// optional interface filter, max_ents 100).
pub fn epm_lookup_request(
    activity_uuid: &[u8; 16],
    interface_filter: Option<&str>,
) -> Result<Vec<u8>, String> {
    let (inquiry_type, iface_uuid, iface_version) = match interface_filter {
        Some(filter) => (
            EPM_INQUIRY_INTERFACE,
            string_to_uuid_bytes(filter)?,
            [1u16, 0u16],
        ),
        None => (EPM_INQUIRY_ALL, [0u8; 16], [0u16, 0u16]),
    };

    let mut body = Vec::with_capacity(52);
    body.extend_from_slice(&inquiry_type.to_le_bytes());
    body.extend_from_slice(&[0u8; 16]); // object UUID (NULL)
    body.extend_from_slice(&iface_uuid);
    body.extend_from_slice(&iface_version[0].to_le_bytes()); // major
    body.extend_from_slice(&iface_version[1].to_le_bytes()); // minor
    body.extend_from_slice(&0u32.to_le_bytes()); // vers_option
    body.extend_from_slice(&0u32.to_le_bytes()); // entry_handle
    body.extend_from_slice(&100u32.to_le_bytes()); // max_ents

    let epm_iface = string_to_uuid_bytes(UUID_EPM_V4)?;
    let mut out = Vec::with_capacity(80 + body.len());
    out.push(0x04); // version
    out.push(0x00); // packet_type = REQUEST
    out.push(0x20); // flags1
    out.push(0x00); // flags2
    out.extend_from_slice(&[0x10, 0x00, 0x00]); // drep: little-endian
    out.push(0x00); // serial_high
    out.extend_from_slice(&[0u8; 16]); // object UUID (NULL)
    out.extend_from_slice(&epm_iface);
    out.extend_from_slice(activity_uuid);
    out.extend_from_slice(&0u32.to_le_bytes()); // server_boot_time
    out.extend_from_slice(&3u32.to_le_bytes()); // interface_version
    out.extend_from_slice(&0u32.to_le_bytes()); // sequence_number
    out.extend_from_slice(&EPM_LOOKUP.to_le_bytes()); // operation_number
    out.extend_from_slice(&0xFFFFu16.to_le_bytes()); // interface_hint
    out.extend_from_slice(&0xFFFFu16.to_le_bytes()); // activity_hint
    out.extend_from_slice(&(body.len() as u16).to_le_bytes()); // length_of_body
    out.extend_from_slice(&0u16.to_le_bytes()); // fragment_number
    out.push(0x00); // authentication_protocol
    out.push(0x00); // serial_low
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse an EPM tower structure to extract endpoint info
/// (`_parse_epm_tower`): floor count, then per floor an LHS (protocol
/// identifier) and RHS (address data), both with u16-LE length prefixes.
/// Recognized floors: 0x0D UUID (first one = interface), 0x0A RPC
/// connectionless, 0x08 UDP port (big-endian), 0x09 IPv4 address. None if
/// no interface UUID was found.
pub fn parse_epm_tower(tower: &[u8]) -> Option<EpmEndpoint> {
    if tower.len() < 4 {
        return None;
    }
    let floor_count = le16(tower, 0);
    let mut offset = 2usize;
    let mut endpoint = EpmEndpoint::default();

    for floor_idx in 0..floor_count {
        if offset + 4 > tower.len() {
            break;
        }
        let lhs_len = le16(tower, offset) as usize;
        offset += 2;
        if offset + lhs_len > tower.len() {
            break;
        }
        let lhs = &tower[offset..offset + lhs_len];
        offset += lhs_len;

        if offset + 2 > tower.len() {
            break;
        }
        let rhs_len = le16(tower, offset) as usize;
        offset += 2;
        if offset + rhs_len > tower.len() {
            break;
        }
        let rhs = &tower[offset..offset + rhs_len];
        offset += rhs_len;

        if lhs_len >= 1 {
            match lhs[0] {
                0x0D if lhs_len >= 19 => {
                    // UUID floor (interface or transfer syntax); only the
                    // first one is the interface.
                    if floor_idx == 0 {
                        endpoint.interface_uuid = uuid_bytes_to_string(&lhs[1..17]);
                        endpoint.interface_version_major = le16(lhs, 17);
                        if rhs_len >= 2 {
                            endpoint.interface_version_minor = le16(rhs, 0);
                        }
                    }
                }
                0x0A => endpoint.protocol = "ncadg_ip_udp".to_string(),
                0x08 if rhs_len >= 2 => endpoint.port = u16::from_be_bytes([rhs[0], rhs[1]]),
                0x09 if rhs_len >= 4 => {
                    endpoint.address = format!("{}.{}.{}.{}", rhs[0], rhs[1], rhs[2], rhs[3]);
                }
                _ => {}
            }
        }
    }

    if endpoint.interface_uuid.is_empty() {
        None
    } else {
        Some(endpoint)
    }
}

/// Parse an EPM lookup response datagram into endpoints, mirroring the
/// response handling inline in `epm_lookup`: short packets, FAULT and other
/// non-RESPONSE types yield an empty list; the body length is read
/// little-endian at offset 74; entries carry object UUID, annotation and the
/// tower, each 4-byte aligned.
pub fn parse_epm_response(data: &[u8]) -> Vec<EpmEndpoint> {
    if data.len() < 80 {
        return Vec::new();
    }
    if data[1] != 0x02 {
        // FAULT (0x03) or unexpected packet type.
        return Vec::new();
    }
    let body_len = le16(data, 74) as usize;
    let body = &data[80..(80 + body_len).min(data.len())];
    if body.len() < 12 {
        return Vec::new();
    }

    let mut offset = 4usize; // entry_handle (continuation context)
    let num_ents = le32(body, offset);
    offset += 4;
    offset += 12; // array metadata (max_count, offset, actual_count)

    let mut endpoints = Vec::new();
    for _ in 0..num_ents {
        if offset + 4 > body.len() || offset + 16 > body.len() {
            break;
        }
        let object_uuid = uuid_bytes_to_string(&body[offset..offset + 16]);
        offset += 16;

        if offset + 4 > body.len() {
            break;
        }
        offset += 4; // tower pointer (reference ID)

        if offset + 4 > body.len() {
            break;
        }
        let annotation_len = le32(body, offset) as usize;
        offset += 4;

        // Annotation string (device model/article number), trailing NULs
        // stripped; the offset advances even if the length overruns.
        let mut annotation = String::new();
        if annotation_len > 0 && offset + annotation_len <= body.len() {
            let mut raw = &body[offset..offset + annotation_len];
            while let [rest @ .., 0] = raw {
                raw = rest;
            }
            annotation = String::from_utf8_lossy(raw).into_owned();
        }
        offset += annotation_len;
        offset = (offset + 3) & !3;

        if offset + 4 > body.len() {
            break;
        }
        let tower_len = le32(body, offset) as usize;
        offset += 4;
        if offset + tower_len > body.len() {
            break;
        }
        let tower = &body[offset..offset + tower_len];
        offset += tower_len;
        offset = (offset + 3) & !3;

        if let Some(mut endpoint) = parse_epm_tower(tower) {
            endpoint.object_uuid = object_uuid;
            endpoint.annotation = annotation;
            endpoints.push(endpoint);
        }
    }
    endpoints
}

/// EPM lookup over raw L2 (`epm_lookup`, transplanted onto [`RawUdp`] so it
/// works headless on macOS): opens a capture on `iface` with a random
/// ephemeral source port, sends one lookup request to `dst_ip`:34964 and
/// parses the response datagram. A timeout yields an empty list, like the
/// reference.
// The argument list mirrors the raw-L2 endpoint tuple one-to-one, like
// RpcConn::new_raw.
#[allow(clippy::too_many_arguments)]
pub fn epm_lookup(
    iface: &str,
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    timeout: Duration,
    interface_filter: Option<&str>,
) -> Result<Vec<EpmEndpoint>, String> {
    let mut rnd = [0u8; 18];
    getrandom::fill(&mut rnd).map_err(|e| format!("getrandom failed: {e}"))?;
    let mut activity_uuid = [0u8; 16];
    activity_uuid.copy_from_slice(&rnd[..16]);
    let local_port = 49152 + u16::from_be_bytes([rnd[16], rnd[17]]) % 16384;

    let req = epm_lookup_request(&activity_uuid, interface_filter)?;
    let mut raw = RawUdp::open(iface, src_mac, src_ip, dst_mac, dst_ip, local_port)?;
    raw.send_to(&req, RPC_PORT)?;
    match raw.recv_from(timeout)? {
        Some((payload, _src_port)) => Ok(parse_epm_response(&payload)),
        None => Ok(Vec::new()), // lookup timeout: no endpoints
    }
}

/// EPM lookup over a plain `UdpSocket`, matching the reference's socket I/O
/// one-to-one. Only works where the OS delivers inbound LAN UDP to sockets —
/// macOS Local Network privacy silently drops it for unapproved processes,
/// so prefer [`epm_lookup`] over raw L2 there.
pub fn epm_lookup_udp(
    ip: &str,
    port: u16,
    timeout: Duration,
    interface_filter: Option<&str>,
) -> Result<Vec<EpmEndpoint>, String> {
    let mut activity_uuid = [0u8; 16];
    getrandom::fill(&mut activity_uuid).map_err(|e| format!("getrandom failed: {e}"))?;
    let req = epm_lookup_request(&activity_uuid, interface_filter)?;

    let peer: std::net::SocketAddr = format!("{ip}:{port}")
        .parse()
        .map_err(|e| format!("Invalid device IP {ip}: {e}"))?;
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("UDP socket bind failed: {e}"))?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("Socket error: {e}"))?;
    sock.send_to(&req, peer)
        .map_err(|e| format!("Socket error: {e}"))?;

    let mut buf = [0u8; 4096];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => Ok(parse_epm_response(&buf[..n])),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Ok(Vec::new()) // lookup timeout: no endpoints
        }
        Err(e) => Err(format!("Socket error: {e}")),
    }
}
