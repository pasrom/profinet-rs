//! Byte-exact DCP (Discovery and Configuration Protocol) frame building and
//! parsing, ported from `profinet-py/profinet/dcp.py` (send_discover,
//! set_param, set_ip, read_response) and `protocol.py` (EthernetHeader,
//! PNDCPHeader, PNDCPBlockRequest, PNDCPBlock).
//!
//! This module is pure functions over bytes; the raw-L2 socket transport
//! lives in a later module.

pub const PROFINET_ETHERTYPE: u16 = 0x8892;
pub const VLAN_ETHERTYPE: u16 = 0x8100;

/// DCP multicast addresses per IEC 61158-6-10.
pub const DCP_MULTICAST_MAC: [u8; 6] = [0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00];
pub const DCP_HELLO_MULTICAST_MAC: [u8; 6] = [0x01, 0x0E, 0xCF, 0x00, 0x00, 0x01];

/// DCP frame IDs.
pub const DCP_IDENTIFY_REQUEST_FRAME_ID: u16 = 0xFEFE;
pub const DCP_IDENTIFY_RESPONSE_FRAME_ID: u16 = 0xFEFF;
pub const DCP_GET_SET_FRAME_ID: u16 = 0xFEFD;
pub const DCP_HELLO_FRAME_ID: u16 = 0xFEFC;

/// DCP service IDs.
pub const DCP_SERVICE_ID_GET: u8 = 0x03;
pub const DCP_SERVICE_ID_SET: u8 = 0x04;
pub const DCP_SERVICE_ID_IDENTIFY: u8 = 0x05;
pub const DCP_SERVICE_ID_HELLO: u8 = 0x06;

/// DCP service types.
pub const DCP_SERVICE_TYPE_REQUEST: u8 = 0x00;
pub const DCP_SERVICE_TYPE_RESPONSE_SUCCESS: u8 = 0x01;
pub const DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED: u8 = 0x05;

/// DCP options.
pub const DCP_OPTION_IP: u8 = 0x01;
pub const DCP_OPTION_DEVICE: u8 = 0x02;
pub const DCP_OPTION_DHCP: u8 = 0x03;
pub const DCP_OPTION_CONTROL: u8 = 0x05;
pub const DCP_OPTION_DEVICE_INITIATIVE: u8 = 0x06;
pub const DCP_OPTION_ALL: u8 = 0xFF;

/// DCP suboptions for IP (option 0x01).
pub const DCP_SUBOPTION_IP_MAC: u8 = 0x01;
pub const DCP_SUBOPTION_IP_PARAMETER: u8 = 0x02;
pub const DCP_SUBOPTION_IP_FULL_SUITE: u8 = 0x03;

/// DCP suboptions for Device (option 0x02).
pub const DCP_SUBOPTION_DEVICE_TYPE: u8 = 0x01;
pub const DCP_SUBOPTION_DEVICE_NAME: u8 = 0x02;
pub const DCP_SUBOPTION_DEVICE_ID: u8 = 0x03;
pub const DCP_SUBOPTION_DEVICE_ROLE: u8 = 0x04;
pub const DCP_SUBOPTION_DEVICE_OPTIONS: u8 = 0x05;
pub const DCP_SUBOPTION_DEVICE_ALIAS: u8 = 0x06;
pub const DCP_SUBOPTION_DEVICE_INSTANCE: u8 = 0x07;

/// DCP suboptions for Control (option 0x05).
pub const DCP_SUBOPTION_CONTROL_START: u8 = 0x01;
pub const DCP_SUBOPTION_CONTROL_STOP: u8 = 0x02;
pub const DCP_SUBOPTION_CONTROL_SIGNAL: u8 = 0x03;
pub const DCP_SUBOPTION_CONTROL_RESPONSE: u8 = 0x04;
pub const DCP_SUBOPTION_CONTROL_RESET_FACTORY: u8 = 0x05;
pub const DCP_SUBOPTION_CONTROL_RESET_TO_FACTORY: u8 = 0x06;

/// Reset-to-factory mode bitmasks (dcp.py RESET_MODE_*).
pub const RESET_MODE_COMMUNICATION: u16 = 0x0002;
pub const RESET_MODE_APPLICATION: u16 = 0x0004;
pub const RESET_MODE_ENGINEERING: u16 = 0x0008;
pub const RESET_MODE_ALL_DATA: u16 = 0x0010;
pub const RESET_MODE_DEVICE: u16 = 0x0020;
pub const RESET_MODE_FACTORY: u16 = 0x0040;

/// DCP SET response block error codes (dcp.py DCP_BLOCK_ERROR_*).
pub const DCP_BLOCK_ERROR_OK: u8 = 0x00;
pub const DCP_BLOCK_ERROR_OPTION_UNSUPPORTED: u8 = 0x01;
pub const DCP_BLOCK_ERROR_SUBOPTION_UNSUPPORTED: u8 = 0x02;
pub const DCP_BLOCK_ERROR_SUBOPTION_NOT_SET: u8 = 0x03;
pub const DCP_BLOCK_ERROR_RESOURCE: u8 = 0x04;
pub const DCP_BLOCK_ERROR_SET_NOT_POSSIBLE: u8 = 0x05;
pub const DCP_BLOCK_ERROR_IN_OPERATION: u8 = 0x06;

/// Human-readable block error name (dcp.py DCP_BLOCK_ERROR_NAMES).
pub fn block_error_name(code: u8) -> String {
    match code {
        0x00 => "OK".to_string(),
        0x01 => "Option not supported".to_string(),
        0x02 => "Suboption not supported or no dataset available".to_string(),
        0x03 => "Suboption not set".to_string(),
        0x04 => "Resource error".to_string(),
        0x05 => "SET not possible by local reasons".to_string(),
        0x06 => "In operation, SET not possible".to_string(),
        _ => format!("Unknown error (0x{code:02X})"),
    }
}

/// DCP maximum Name-of-Station length (IEC 61158-6-10).
pub const DCP_MAX_NAME_LENGTH: usize = 240;

/// Default Identify response delay in 10 ms units (dcp.py send_discover).
pub const DCP_RESPONSE_DELAY: u16 = 0x0080;

/// EthernetHeader: dst ++ src ++ ethertype (14 bytes) followed by the payload.
fn eth_frame(dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + payload.len());
    out.extend_from_slice(dst);
    out.extend_from_slice(src);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// PNDCPHeader: frame_id ++ service_id ++ service_type ++ xid ++ resp ++
/// length (12 bytes) followed by the payload.
fn dcp_header(
    frame_id: u16,
    service_id: u8,
    service_type: u8,
    xid: u32,
    resp: u16,
    length: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + payload.len());
    out.extend_from_slice(&frame_id.to_be_bytes());
    out.push(service_id);
    out.push(service_type);
    out.extend_from_slice(&xid.to_be_bytes());
    out.extend_from_slice(&resp.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// PNDCPBlockRequest: option ++ suboption ++ length (4 bytes) followed by the
/// payload. `length` is caller-supplied because set_param/set_ip count a
/// leading 2-byte qualifier that is part of the payload.
fn block_request(option: u8, suboption: u8, length: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.push(option);
    out.push(suboption);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Identify-All multicast request as built by dcp.py send_discover: dst
/// 01:0e:cf:00:00:00, response delay 0x0080, one All/All block with empty
/// payload. 30 bytes total (no minimum-frame padding, matching the reference).
pub fn identify_all_request(src_mac: &[u8; 6], xid: u32) -> Vec<u8> {
    let block = block_request(DCP_OPTION_ALL, DCP_OPTION_ALL, 0, &[]);
    let dcp = dcp_header(
        DCP_IDENTIFY_REQUEST_FRAME_ID,
        DCP_SERVICE_ID_IDENTIFY,
        DCP_SERVICE_TYPE_REQUEST,
        xid,
        DCP_RESPONSE_DELAY,
        block.len() as u16,
        &block,
    );
    eth_frame(&DCP_MULTICAST_MAC, src_mac, PROFINET_ETHERTYPE, &dcp)
}

/// Set request frame as built by dcp.py set_param/set_ip: one block whose
/// payload is a 2-byte qualifier followed by the value.
///
/// Reference quirk preserved as-is: for odd-length values the DCP header
/// length field counts a pad byte that is never actually appended.
fn set_request(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    xid: u32,
    option: u8,
    suboption: u8,
    qualifier: u16,
    value: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + value.len());
    payload.extend_from_slice(&qualifier.to_be_bytes());
    payload.extend_from_slice(value);

    let block = block_request(option, suboption, (value.len() + 2) as u16, &payload);
    let padding = value.len() % 2;
    let dcp = dcp_header(
        DCP_GET_SET_FRAME_ID,
        DCP_SERVICE_ID_SET,
        DCP_SERVICE_TYPE_REQUEST,
        xid,
        0,
        (value.len() + 6 + padding) as u16,
        &block,
    );
    eth_frame(dst_mac, src_mac, PROFINET_ETHERTYPE, &dcp)
}

/// Set Name-of-Station request as built by dcp.py set_param("name", ...):
/// Device/Name block, temporary qualifier 0x0000, ASCII name.
pub fn set_name_request(src_mac: &[u8; 6], dst_mac: &[u8; 6], xid: u32, name: &str) -> Vec<u8> {
    set_request(
        src_mac,
        dst_mac,
        xid,
        DCP_OPTION_DEVICE,
        DCP_SUBOPTION_DEVICE_NAME,
        0x0000,
        name.as_bytes(),
    )
}

/// Set IP-parameter request as built by dcp.py set_ip (temporary qualifier
/// 0x0000, matching its `permanent=False` default): IP/Parameter block with
/// address ++ netmask ++ gateway.
pub fn set_ip_request(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    xid: u32,
    ip: &[u8; 4],
    netmask: &[u8; 4],
    gateway: &[u8; 4],
) -> Vec<u8> {
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(ip);
    value.extend_from_slice(netmask);
    value.extend_from_slice(gateway);
    set_request(
        src_mac,
        dst_mac,
        xid,
        DCP_OPTION_IP,
        DCP_SUBOPTION_IP_PARAMETER,
        0x0000,
        &value,
    )
}

/// Get-parameter request frame as built by dcp.py get_param: a single
/// option/suboption block with empty payload.
///
/// Reference quirk preserved as-is: the DCP header length field is 2 even
/// though the serialized block (option ++ suboption ++ length) is 4 bytes.
pub fn get_request(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    xid: u32,
    option: u8,
    suboption: u8,
) -> Vec<u8> {
    let block = block_request(option, suboption, 0, &[]);
    let dcp = dcp_header(
        DCP_GET_SET_FRAME_ID,
        DCP_SERVICE_ID_GET,
        DCP_SERVICE_TYPE_REQUEST,
        xid,
        0,
        2,
        &block,
    );
    eth_frame(dst_mac, src_mac, PROFINET_ETHERTYPE, &dcp)
}

/// Generic set-parameter request as built by dcp.py set_param: temporary
/// qualifier 0x0000 followed by the raw value bytes (the reference sends the
/// ASCII value string for every parameter, including "ip").
pub fn set_param_request(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    xid: u32,
    option: u8,
    suboption: u8,
    value: &[u8],
) -> Vec<u8> {
    set_request(src_mac, dst_mac, xid, option, suboption, 0x0000, value)
}

/// Set IP-parameter request with an explicit permanence qualifier (dcp.py
/// set_ip with `permanent=True/False`); [`set_ip_request`] is the
/// temporary-qualifier shorthand.
pub fn set_ip_request_qualified(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    xid: u32,
    ip: &[u8; 4],
    netmask: &[u8; 4],
    gateway: &[u8; 4],
    permanent: bool,
) -> Vec<u8> {
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(ip);
    value.extend_from_slice(netmask);
    value.extend_from_slice(gateway);
    let qualifier = if permanent { 0x0001 } else { 0x0000 };
    set_request(
        src_mac,
        dst_mac,
        xid,
        DCP_OPTION_IP,
        DCP_SUBOPTION_IP_PARAMETER,
        qualifier,
        &value,
    )
}

/// Control/Signal request to flash the device LEDs (dcp.py signal_device):
/// BlockInfo 0x0001 (temporary signal) followed by the duration in 100 ms
/// units — the same qualifier ++ value layout as a SET block.
pub fn signal_request(src_mac: &[u8; 6], dst_mac: &[u8; 6], xid: u32, duration_ms: u32) -> Vec<u8> {
    let duration_units = (duration_ms / 100).max(1) as u16;
    set_request(
        src_mac,
        dst_mac,
        xid,
        DCP_OPTION_CONTROL,
        DCP_SUBOPTION_CONTROL_SIGNAL,
        0x0001,
        &duration_units.to_be_bytes(),
    )
}

/// Control/ResetToFactory request (dcp.py reset_to_factory): the reset mode
/// bitmask as the block qualifier, no value bytes.
pub fn reset_request(src_mac: &[u8; 6], dst_mac: &[u8; 6], xid: u32, mode: u16) -> Vec<u8> {
    set_request(
        src_mac,
        dst_mac,
        xid,
        DCP_OPTION_CONTROL,
        DCP_SUBOPTION_CONTROL_RESET_TO_FACTORY,
        mode,
        &[],
    )
}

/// Strip the Ethernet (and optional 802.1Q) header of a PROFINET frame,
/// returning the DCP payload. Mirrors the VLAN handling shared by dcp.py
/// read_response and _parse_set_response.
fn dcp_payload(frame: &[u8]) -> Result<&[u8], String> {
    if frame.len() < 14 {
        return Err(format!(
            "frame too short for Ethernet header: {} bytes",
            frame.len()
        ));
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let payload = &frame[14..];
    if ethertype == VLAN_ETHERTYPE {
        if payload.len() < 4 {
            return Err("VLAN frame too short".to_string());
        }
        let inner_type = u16::from_be_bytes([payload[2], payload[3]]);
        if inner_type != PROFINET_ETHERTYPE {
            return Err(format!("unexpected inner EtherType: 0x{inner_type:04X}"));
        }
        Ok(&payload[4..])
    } else if ethertype != PROFINET_ETHERTYPE {
        Err(format!("unexpected EtherType: 0x{ethertype:04X}"))
    } else {
        Ok(payload)
    }
}

/// Extract the DCP transaction id (xid) from a frame, for matching a response
/// to its request. Works for any DCP frame (GET/SET or Identify), VLAN or not.
/// `None` if the frame is too short or not a DCP frame.
pub fn parse_dcp_xid(frame: &[u8]) -> Option<u32> {
    let payload = dcp_payload(frame).ok()?;
    (payload.len() >= 8)
        .then(|| u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]))
}

/// Parse a DCP SET response and extract the block error code (0x00 =
/// success), the port of dcp.py _parse_set_response: find the
/// Control/Response block and read its BlockError byte; a response without
/// one counts as success (some devices omit it).
///
/// `expected_xid` gates ownership: only a GET/SET-frame response carrying our
/// transaction id is ours. Any other frame (our echoed request, a foreign
/// device's traffic, a stale xid, an RTA alarm whose byte at the service_type
/// offset happens to be 0x01) returns `Ok(None)` so the caller skips it and
/// keeps waiting. Only an UNSUPPORTED response to our xid is an `Err`.
pub fn parse_set_response(frame: &[u8], expected_xid: u32) -> Result<Option<u8>, String> {
    let payload = dcp_payload(frame)?;
    if payload.len() < 12 {
        return Ok(None); // too short to be a DCP GET/SET response header
    }
    let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
    let service_id = payload[2];
    let service_type = payload[3];
    let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    // Only a GET/SET-frame response to OUR xid is ours. Skip anything else --
    // our echoed request, an RTA alarm (whose payload[3] happens to be 0x01), a
    // foreign device's frame, or a stale xid -- instead of reporting a bogus
    // SET success.
    if frame_id != DCP_GET_SET_FRAME_ID || service_id != DCP_SERVICE_ID_SET || xid != expected_xid {
        return Ok(None);
    }
    if service_type == DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED {
        return Err("DCP SET: service not supported by device".to_string());
    }
    if service_type != DCP_SERVICE_TYPE_RESPONSE_SUCCESS {
        // Matches our xid but is not a SET response (e.g. our own echoed
        // request, service_type 0x00). Skip and keep waiting rather than
        // aborting the roundtrip on a stray frame.
        return Ok(None);
    }

    let mut remaining = i32::from(u16::from_be_bytes([payload[10], payload[11]]));
    let mut blocks = &payload[12..];

    while remaining > 4 {
        if blocks.len() < 4 {
            break;
        }
        let option = blocks[0];
        let suboption = blocks[1];
        let block_length = usize::from(u16::from_be_bytes([blocks[2], blocks[3]]));
        let block_payload = &blocks[4..(4 + block_length).min(blocks.len())];

        if option == DCP_OPTION_CONTROL && suboption == DCP_SUBOPTION_CONTROL_RESPONSE {
            // Payload: OptionForResponse(1) + SubOptionForResponse(1) +
            // BlockError(1); short blocks fall back like the reference.
            return Ok(Some(match block_payload.len() {
                0 => DCP_BLOCK_ERROR_OK,
                1 | 2 => block_payload[0],
                _ => block_payload[2],
            }));
        }

        // Blocks are 2-byte aligned.
        let mut block_len = 4 + block_length;
        if block_length % 2 == 1 {
            block_len += 1;
        }
        blocks = &blocks[block_len.min(blocks.len())..];
        remaining -= block_len as i32;
    }

    Ok(Some(DCP_BLOCK_ERROR_OK))
}

/// Extract one block's payload from a DCP GET response (dcp.py get_param via
/// read_response with `once=True`): walk the response blocks like
/// [`parse_identify_response`] and return the payload of the requested
/// option/suboption block (BlockInfo word stripped), or `None` when absent.
pub fn parse_get_response(
    frame: &[u8],
    option: u8,
    suboption: u8,
) -> Result<Option<Vec<u8>>, String> {
    let payload = dcp_payload(frame)?;
    if payload.len() < 12 {
        return Err(format!(
            "payload too short for DCP header: {} bytes",
            payload.len()
        ));
    }
    let service_type = payload[3];
    if service_type != DCP_SERVICE_TYPE_RESPONSE_SUCCESS {
        return Err(format!(
            "not a DCP response: service_type 0x{service_type:02X}"
        ));
    }
    let mut length = i32::from(u16::from_be_bytes([payload[10], payload[11]]));
    let mut blocks = &payload[12..];

    while length > 6 {
        if blocks.len() < 6 {
            break;
        }
        let block_option = blocks[0];
        let block_suboption = blocks[1];
        let block_length = usize::from(u16::from_be_bytes([blocks[2], blocks[3]]));
        // The block length counts the 2-byte BlockInfo/status word at 4..6.
        let payload_len = block_length.saturating_sub(2);
        let block_payload = &blocks[6..(6 + payload_len).min(blocks.len())];

        if block_option == option && block_suboption == suboption {
            return Ok(Some(block_payload.to_vec()));
        }

        let mut block_len = block_length;
        if block_len % 2 == 1 {
            block_len += 1;
        }
        blocks = &blocks[(4 + block_len).min(blocks.len())..];
        length -= (4 + block_len) as i32;
    }

    Ok(None)
}

/// Parsed PROFINET device information from a DCP Identify response, the
/// subset of dcp.py DCPDeviceDescription carried by the standard blocks.
/// Fields for blocks absent from the response keep their zero/empty defaults,
/// matching the reference (which only warns on missing name/IP).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DcpDevice {
    pub mac: [u8; 6],
    pub name: String,
    pub device_type: String,
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub vendor_id: u16,
    pub device_id: u16,
    pub role: u8,
}

/// Parse a DCP Identify response Ethernet frame into a [`DcpDevice`],
/// mirroring the per-frame logic of dcp.py read_response: skip an optional
/// 802.1Q tag, require the PROFINET EtherType and a RESPONSE service type,
/// then walk the 2-byte-aligned response blocks (6-byte header including the
/// BlockInfo/status word, which the reference strips from the payload).
pub fn parse_identify_response(frame: &[u8]) -> Result<DcpDevice, String> {
    if frame.len() < 14 {
        return Err(format!(
            "frame too short for Ethernet header: {} bytes",
            frame.len()
        ));
    }
    let src: [u8; 6] = frame[6..12].try_into().expect("6-byte slice");
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut payload = &frame[14..];

    if ethertype == VLAN_ETHERTYPE {
        // VLAN header: 2 bytes TCI + 2 bytes inner ethertype.
        if payload.len() < 4 {
            return Err("VLAN frame too short".to_string());
        }
        let inner_type = u16::from_be_bytes([payload[2], payload[3]]);
        if inner_type != PROFINET_ETHERTYPE {
            return Err(format!("unexpected inner EtherType: 0x{inner_type:04X}"));
        }
        payload = &payload[4..];
    } else if ethertype != PROFINET_ETHERTYPE {
        return Err(format!("unexpected EtherType: 0x{ethertype:04X}"));
    }

    if payload.len() < 12 {
        return Err(format!(
            "payload too short for DCP header: {} bytes",
            payload.len()
        ));
    }
    let service_type = payload[3];
    if service_type != DCP_SERVICE_TYPE_RESPONSE_SUCCESS {
        return Err(format!(
            "not a DCP response: service_type 0x{service_type:02X}"
        ));
    }
    let mut length = i32::from(u16::from_be_bytes([payload[10], payload[11]]));
    let mut blocks = &payload[12..];

    let mut device = DcpDevice {
        mac: src,
        ..DcpDevice::default()
    };

    while length > 6 {
        if blocks.len() < 6 {
            break;
        }
        let option = blocks[0];
        let suboption = blocks[1];
        let block_length = usize::from(u16::from_be_bytes([blocks[2], blocks[3]]));
        // The block length counts the 2-byte BlockInfo/status word at offset
        // 4..6; the payload follows it (truncated if the frame is short,
        // matching the reference's silent slicing).
        let payload_len = block_length.saturating_sub(2);
        let block_payload = &blocks[6..(6 + payload_len).min(blocks.len())];

        match (option, suboption) {
            (DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_TYPE) => {
                let trimmed = block_payload
                    .iter()
                    .rposition(|&b| b != 0)
                    .map_or(&[][..], |i| &block_payload[..=i]);
                device.device_type = String::from_utf8_lossy(trimmed).into_owned();
            }
            (DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_NAME) => {
                device.name = String::from_utf8_lossy(block_payload).into_owned();
            }
            (DCP_OPTION_IP, DCP_SUBOPTION_IP_PARAMETER) if block_payload.len() >= 12 => {
                device.ip = block_payload[0..4].try_into().expect("4-byte slice");
                device.netmask = block_payload[4..8].try_into().expect("4-byte slice");
                device.gateway = block_payload[8..12].try_into().expect("4-byte slice");
            }
            (DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_ID) if block_payload.len() >= 4 => {
                device.vendor_id = u16::from_be_bytes([block_payload[0], block_payload[1]]);
                device.device_id = u16::from_be_bytes([block_payload[2], block_payload[3]]);
            }
            (DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_ROLE) if !block_payload.is_empty() => {
                device.role = block_payload[0];
            }
            _ => {}
        }

        // Blocks are 2-byte aligned; advance past header + payload + padding.
        let mut block_len = block_length;
        if block_len % 2 == 1 {
            block_len += 1;
        }
        blocks = &blocks[(4 + block_len).min(blocks.len())..];
        length -= (4 + block_len) as i32;
    }

    Ok(device)
}
