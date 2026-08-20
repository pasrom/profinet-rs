//! Address conversion utilities, ported from `profinet-py/profinet/util.py`
//! (s2mac / mac2s / ip2s / s2ip).
//!
//! Naming follows the reference: `ip2s` parses a dotted-decimal string into
//! bytes and `s2ip` formats bytes into a string, mirroring the Python API.

/// Parse a MAC address string ("aa:bb:cc:dd:ee:ff") into 6 bytes.
pub fn s2mac(s: &str) -> Result<[u8; 6], String> {
    if s.is_empty() {
        return Err("MAC address cannot be empty".to_string());
    }

    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!(
            "Invalid MAC address format: {s:?}. Expected format: aa:bb:cc:dd:ee:ff"
        ));
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "Invalid MAC address format: {s:?}. Expected format: aa:bb:cc:dd:ee:ff"
            ));
        }
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| format!("Invalid MAC address: {s:?}"))?;
    }
    Ok(mac)
}

/// Format a 6-byte MAC address as a lowercase colon-separated string.
pub fn mac2s(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse a dotted-decimal IPv4 string ("192.168.0.2") into 4 bytes.
pub fn ip2s(s: &str) -> Result<[u8; 4], String> {
    if s.is_empty() {
        return Err("IP address cannot be empty".to_string());
    }

    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("Invalid IP address: {s:?}"));
    }

    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("Invalid IP address: {s:?}"));
        }
        // Reject leading zeros as ipaddress.IPv4Address does ("010" is invalid).
        if part.len() > 1 && part.starts_with('0') {
            return Err(format!("Invalid IP address: {s:?}"));
        }
        ip[i] = part
            .parse::<u8>()
            .map_err(|_| format!("Invalid IP address: {s:?}"))?;
    }
    Ok(ip)
}

/// Format the first 4 bytes of an IP address as a dotted-decimal string.
pub fn s2ip(ip: &[u8]) -> Result<String, String> {
    if ip.len() < 4 {
        return Err(format!(
            "IP address must be at least 4 bytes, got {}",
            ip.len()
        ));
    }
    Ok(ip[..4]
        .iter()
        .map(|o| o.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

/// TPIDs that introduce an 802.1Q / 802.1ad tag.
pub const VLAN_TPIDS: [u16; 2] = [0x8100, 0x88A8];

/// Byte offset of the real EtherType in an Ethernet frame (`skip_vlan_tags`).
///
/// PROFINET devices commonly send RT and alarm frames 802.1Q priority-tagged
/// (TPID 0x8100, VID 0). Whether the tag still reaches a raw socket depends on
/// NIC and driver VLAN offload — Linux AF_PACKET usually strips it, libpcap and
/// BPF deliver it in-band — so a receiver has to skip any number of tags rather
/// than read the EtherType at a fixed offset.
///
/// Returns 12 for an untagged frame, plus 4 per tag.
pub fn skip_vlan_tags(frame: &[u8]) -> usize {
    let mut offset = 12;
    while frame.len() >= offset + 4
        && VLAN_TPIDS.contains(&u16::from_be_bytes([frame[offset], frame[offset + 1]]))
    {
        offset += 4;
    }
    offset
}

/// Strip the Ethernet header and return the payload, requiring the EtherType
/// to be `want`. Any number of VLAN tags is skipped, so a tagged and an
/// untagged frame are handled identically — the alternative is every protocol
/// module carrying its own single-tag check, which is how they drifted apart.
pub fn strip_eth(frame: &[u8], want: u16) -> Result<&[u8], String> {
    if frame.len() < 14 {
        return Err(format!(
            "frame too short for Ethernet header: {} bytes",
            frame.len()
        ));
    }
    let at = skip_vlan_tags(frame);
    if frame.len() < at + 2 {
        return Err("VLAN frame too short".to_string());
    }
    let ethertype = u16::from_be_bytes([frame[at], frame[at + 1]]);
    if ethertype != want {
        // "inner" when a tag was skipped, so the message says which field
        // disagreed.
        return Err(if at > 12 {
            format!("unexpected inner EtherType: 0x{ethertype:04X}")
        } else {
            format!("unexpected EtherType: 0x{ethertype:04X}")
        });
    }
    Ok(&frame[at + 2..])
}
