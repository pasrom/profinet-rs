//! UDP-over-raw-L2 endpoint: sends and receives DCE/RPC UDP datagrams as
//! hand-built Ethernet + IPv4 + UDP frames over the pcap backend
//! ([`crate::pcap::RawSocket`]).
//!
//! Rationale: macOS Local Network privacy silently drops inbound LAN UDP
//! delivered through the IP stack to a fresh binary, which breaks the
//! `std::net::UdpSocket` RPC transport. DCP already works because it talks
//! raw L2 via pcap/BPF; this module gives the RPC layer the same path. The
//! RPC request/response bytes are unchanged — only the socket I/O moves down
//! to L2.
//!
//! The frame builder/parser and both Internet checksums are pure functions,
//! unit-tested below; [`RawUdp`] just wires them to a live capture.

use crate::util::skip_vlan_tags;

use std::time::{Duration, Instant};

use crate::pcap::RawSocket;

/// EtherType for IPv4, the BPF filter installed on the capture.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTO_UDP: u8 = 17;

/// One's-complement sum of `data` as big-endian 16-bit words (RFC 1071);
/// a trailing odd byte is padded with a zero low byte.
fn sum_be_words(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    sum
}

/// Fold the carries back into 16 bits and complement (RFC 1071).
fn fold_checksum(mut sum: u32) -> u16 {
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 header checksum over the (IHL-long) header with its checksum field
/// zeroed. Applied to a header carrying a correct checksum it returns 0.
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    fold_checksum(sum_be_words(header))
}

/// UDP checksum over the IPv4 pseudo-header (src, dst, zero, proto 17, UDP
/// length) plus the UDP header (checksum field zeroed) and payload in `udp`.
/// A computed 0x0000 is transmitted as 0xFFFF (RFC 768: 0 means "no
/// checksum").
pub fn udp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], udp: &[u8]) -> u16 {
    let sum = sum_be_words(src_ip)
        + sum_be_words(dst_ip)
        + u32::from(IP_PROTO_UDP)
        + udp.len() as u32
        + sum_be_words(udp);
    match fold_checksum(sum) {
        0 => 0xFFFF,
        c => c,
    }
}

/// Build a complete Ethernet + IPv4 + UDP frame around `payload`:
/// Ethernet(dst, src, 0x0800), IPv4 with IHL 5 / DF / TTL 64 / proto 17 and
/// a computed header checksum, UDP with a computed pseudo-header checksum.
#[allow(clippy::too_many_arguments)]
pub fn build_udp_frame(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
    ip_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut ip = Vec::with_capacity(20);
    ip.push(0x45); // version 4, IHL 5
    ip.push(0x00); // TOS
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&ip_id.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // DF, fragment offset 0
    ip.push(64); // TTL
    ip.push(IP_PROTO_UDP);
    ip.extend_from_slice(&[0, 0]); // checksum, computed below
    ip.extend_from_slice(src_ip);
    ip.extend_from_slice(dst_ip);
    let ip_cksum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum, computed below
    udp.extend_from_slice(payload);
    let udp_cksum = udp_checksum(src_ip, dst_ip, &udp);
    udp[6..8].copy_from_slice(&udp_cksum.to_be_bytes());

    let mut frame = Vec::with_capacity(14 + total_len);
    frame.extend_from_slice(dst_mac);
    frame.extend_from_slice(src_mac);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    frame
}

/// Extract `(udp_payload, udp_src_port)` from a captured Ethernet frame if it
/// is an unfragmented IPv4/UDP datagram from `want_src_ip` to `want_dst_ip`;
/// None for anything else (our own outgoing frames, other traffic, runts).
/// Any number of 802.1Q tags is skipped, the IP header is walked by its IHL (options
/// tolerated), and the payload is cut to the UDP length field so Ethernet
/// minimum-frame padding is not returned.
pub fn parse_udp_frame(
    frame: &[u8],
    want_src_ip: &[u8; 4],
    want_dst_ip: &[u8; 4],
) -> Option<(Vec<u8>, u16)> {
    if frame.len() < 14 {
        return None;
    }
    // Any number of VLAN tags may sit before the EtherType, the same as on the
    // PROFINET paths.
    let off = skip_vlan_tags(frame);
    if frame.len() < off + 2 {
        return None;
    }
    if u16::from_be_bytes([frame[off], frame[off + 1]]) != ETHERTYPE_IPV4 {
        return None;
    }

    let ip = off + 2;
    if frame.len() < ip + 20 || frame[ip] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(frame[ip] & 0x0F) * 4;
    if ihl < 20 || frame.len() < ip + ihl + 8 {
        return None;
    }
    // Non-first fragments carry no UDP header.
    if u16::from_be_bytes([frame[ip + 6], frame[ip + 7]]) & 0x1FFF != 0 {
        return None;
    }
    if frame[ip + 9] != IP_PROTO_UDP
        || frame[ip + 12..ip + 16] != want_src_ip[..]
        || frame[ip + 16..ip + 20] != want_dst_ip[..]
    {
        return None;
    }

    let udp = ip + ihl;
    let src_port = u16::from_be_bytes([frame[udp], frame[udp + 1]]);
    let udp_len = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
    if udp_len < 8 || frame.len() < udp + udp_len {
        return None;
    }
    Some((frame[udp + 8..udp + udp_len].to_vec(), src_port))
}

/// A point-to-point UDP endpoint over raw L2: one pcap capture on the
/// interface with the VLAN-aware IPv4 BPF filter, sending hand-built frames
/// to `dst_mac`/`dst_ip` and receiving only IPv4/UDP frames coming back from
/// `dst_ip` to `src_ip`.
#[derive(Debug)]
pub struct RawUdp {
    sock: RawSocket,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    local_port: u16,
    ip_id: u16,
}

impl RawUdp {
    /// Open the IPv4-filtered capture on `iface`; `local_port` is the UDP
    /// source port used by [`RawUdp::send_to`].
    pub fn open(
        iface: &str,
        src_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_mac: [u8; 6],
        dst_ip: [u8; 4],
        local_port: u16,
    ) -> Result<Self, String> {
        Ok(RawUdp {
            sock: RawSocket::open(iface, Some(ETHERTYPE_IPV4))?,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            local_port,
            ip_id: 0,
        })
    }

    /// The UDP source port of [`RawUdp::send_to`].
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// The peer IPv4 address (for error messages).
    pub fn dst_ip(&self) -> [u8; 4] {
        self.dst_ip
    }

    /// Send `payload` as a UDP datagram from `local_port` to `dst_port`.
    pub fn send_to(&mut self, payload: &[u8], dst_port: u16) -> Result<(), String> {
        self.send_to_from(payload, self.local_port, dst_port)
    }

    /// Send with an explicit UDP source port: the CControl confirmation must
    /// leave from the well-known RPC port 34964, not from `local_port`.
    pub fn send_to_from(
        &mut self,
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
    ) -> Result<(), String> {
        let id = self.ip_id;
        self.ip_id = self.ip_id.wrapping_add(1);
        let frame = build_udp_frame(
            &self.src_mac,
            &self.dst_mac,
            &self.src_ip,
            &self.dst_ip,
            src_port,
            dst_port,
            id,
            payload,
        );
        self.sock.send(&frame)
    }

    /// Receive the next UDP datagram from the peer within `timeout`
    /// wall-clock time, returning `(payload, udp_src_port)` — the source
    /// port lets the caller tell a connect response (dynamic device port)
    /// from a device-initiated CControl. Non-matching frames are skipped;
    /// `Ok(None)` on timeout.
    pub fn recv_from(&mut self, timeout: Duration) -> Result<Option<(Vec<u8>, u16)>, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            match self.sock.recv(deadline - now)? {
                Some(frame) => {
                    if let Some(hit) = parse_udp_frame(&frame, &self.dst_ip, &self.src_ip) {
                        return Ok(Some(hit));
                    }
                }
                None => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const DST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const SRC_IP: [u8; 4] = [192, 168, 0, 1];
    const DST_IP: [u8; 4] = [192, 168, 0, 199];

    /// The IPv4 header checksum example from RFC 1071 practice (the
    /// well-known Wikipedia vector): checksum 0xB861 for this header.
    #[test]
    fn ipv4_checksum_known_vector() {
        let mut header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7,
        ];
        assert_eq!(ipv4_checksum(&header), 0xB861);
        // A header carrying its correct checksum verifies to zero.
        header[10..12].copy_from_slice(&0xB861u16.to_be_bytes());
        assert_eq!(ipv4_checksum(&header), 0);
    }

    /// Hand-computed vector: src 192.168.0.1, dst 192.168.0.199, ports
    /// 34964 -> 34964, payload "test". Pseudo-header + UDP words sum to
    /// 0x37B42, folds to 0x7B45, complements to 0x84BA.
    #[test]
    fn udp_checksum_known_vector() {
        let mut udp = Vec::new();
        udp.extend_from_slice(&34964u16.to_be_bytes());
        udp.extend_from_slice(&34964u16.to_be_bytes());
        udp.extend_from_slice(&12u16.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(b"test");
        assert_eq!(udp_checksum(&SRC_IP, &DST_IP, &udp), 0x84BA);
    }

    #[test]
    fn built_frame_layout_and_checksums() {
        let payload = b"\x04\x00\x20\x00hello rpc";
        let frame = build_udp_frame(
            &SRC_MAC, &DST_MAC, &SRC_IP, &DST_IP, 50123, 34964, 7, payload,
        );

        // Ethernet: dst ++ src ++ 0x0800.
        assert_eq!(&frame[0..6], &DST_MAC);
        assert_eq!(&frame[6..12], &SRC_MAC);
        assert_eq!(&frame[12..14], &[0x08, 0x00]);

        // IPv4 header fields.
        let ip = &frame[14..34];
        assert_eq!(ip[0], 0x45);
        let total_len = u16::from_be_bytes([ip[2], ip[3]]);
        assert_eq!(total_len as usize, 20 + 8 + payload.len());
        assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 7); // id
        assert_eq!(u16::from_be_bytes([ip[6], ip[7]]), 0x4000); // DF
        assert_eq!(ip[8], 64); // TTL
        assert_eq!(ip[9], 17); // UDP
        assert_eq!(&ip[12..16], &SRC_IP);
        assert_eq!(&ip[16..20], &DST_IP);
        // Header checksum verifies: sum over the full header (checksum
        // included) folds to 0xFFFF, i.e. ipv4_checksum returns 0.
        assert_eq!(ipv4_checksum(ip), 0);
        assert_ne!(u16::from_be_bytes([ip[10], ip[11]]), 0);

        // UDP header fields.
        let udp = &frame[34..];
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 50123);
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 34964);
        assert_eq!(
            u16::from_be_bytes([udp[4], udp[5]]) as usize,
            8 + payload.len()
        );
        assert_ne!(u16::from_be_bytes([udp[6], udp[7]]), 0);
        // UDP checksum verifies over pseudo-header + full datagram
        // (checksum included): the one's-complement sum folds to 0xFFFF.
        let verify = sum_be_words(&SRC_IP)
            + sum_be_words(&DST_IP)
            + u32::from(IP_PROTO_UDP)
            + udp.len() as u32
            + sum_be_words(udp);
        assert_eq!(fold_checksum(verify), 0);
        assert_eq!(&udp[8..], payload);
    }

    /// A frame built for the incoming direction parses back to the same
    /// payload and source port.
    #[test]
    fn round_trip_build_then_parse() {
        let payload = b"rpc response bytes";
        let frame = build_udp_frame(
            &DST_MAC, &SRC_MAC, &DST_IP, &SRC_IP, 49152, 50123, 3, payload,
        );
        let (got, src_port) = parse_udp_frame(&frame, &DST_IP, &SRC_IP).expect("frame must parse");
        assert_eq!(got, payload);
        assert_eq!(src_port, 49152);
    }

    /// 802.1Q-tagged and Ethernet-padded frames still parse, and the padding
    /// is cut off at the UDP length.
    #[test]
    fn parse_vlan_tagged_and_padded_frame() {
        let payload = b"ok";
        let mut frame = build_udp_frame(
            &DST_MAC, &SRC_MAC, &DST_IP, &SRC_IP, 34964, 34964, 0, payload,
        );
        // Insert an 802.1Q tag (TPID 0x8100, VID 5) after the MACs.
        frame.splice(12..12, [0x81, 0x00, 0x00, 0x05]);
        // Pad to the 60-byte Ethernet minimum.
        while frame.len() < 60 {
            frame.push(0);
        }
        let (got, src_port) = parse_udp_frame(&frame, &DST_IP, &SRC_IP).expect("frame must parse");
        assert_eq!(got, payload);
        assert_eq!(src_port, 34964);
    }

    /// Frames that are not the peer's UDP traffic are ignored — notably our
    /// own outgoing frames, which the capture also sees.
    #[test]
    fn parse_rejects_non_matching_frames() {
        let own = build_udp_frame(&SRC_MAC, &DST_MAC, &SRC_IP, &DST_IP, 50123, 34964, 0, b"x");
        assert_eq!(parse_udp_frame(&own, &DST_IP, &SRC_IP), None);

        let other_ip = build_udp_frame(
            &DST_MAC,
            &SRC_MAC,
            &[10, 0, 0, 1],
            &SRC_IP,
            34964,
            34964,
            0,
            b"x",
        );
        assert_eq!(parse_udp_frame(&other_ip, &DST_IP, &SRC_IP), None);

        // Wrong ethertype (ARP) and runt frames.
        let mut arp = build_udp_frame(&DST_MAC, &SRC_MAC, &DST_IP, &SRC_IP, 1, 2, 0, b"x");
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(parse_udp_frame(&arp, &DST_IP, &SRC_IP), None);
        assert_eq!(parse_udp_frame(&[0u8; 13], &DST_IP, &SRC_IP), None);
    }
}
