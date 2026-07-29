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
