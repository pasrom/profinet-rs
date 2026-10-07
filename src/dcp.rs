//! Byte-exact DCP (Discovery and Configuration Protocol) frame building and
//! parsing, ported from `profinet-py/profinet/dcp.py` (send_discover,
//! set_param, set_ip, read_response) and `protocol.py` (EthernetHeader,
//! PNDCPHeader, PNDCPBlockRequest, PNDCPBlock).
//!
//! This module is pure functions over bytes; the raw-L2 socket transport
//! lives in a later module.

use crate::util::strip_eth;

pub const PROFINET_ETHERTYPE: u16 = 0x8892;

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

/// Legacy reset mode constants (dcp.py RESET_MODE_*, which keeps them "for
/// compatibility"). They are not the spec's encoding: they read as one bit per
/// mode, while the ResetToFactory BlockQualifier carries the mode *number* in
/// bits 1..15. Sent as a qualifier, `RESET_MODE_COMMUNICATION` (0x0002) is mode
/// 1, reset application data, and `RESET_MODE_ALL_DATA` (0x0010) is mode 8,
/// reset to factory values. Use the `RESET_QUALIFIER_*` values below.
#[deprecated(note = "not the spec encoding; use the RESET_QUALIFIER_* values")]
pub const RESET_MODE_COMMUNICATION: u16 = 0x0002;
#[deprecated(note = "not the spec encoding; use the RESET_QUALIFIER_* values")]
pub const RESET_MODE_APPLICATION: u16 = 0x0004;
#[deprecated(note = "not the spec encoding; use the RESET_QUALIFIER_* values")]
pub const RESET_MODE_ENGINEERING: u16 = 0x0008;
#[deprecated(note = "not the spec encoding; use the RESET_QUALIFIER_* values")]
pub const RESET_MODE_ALL_DATA: u16 = 0x0010;
#[deprecated(note = "not the spec encoding; use the RESET_QUALIFIER_* values")]
pub const RESET_MODE_DEVICE: u16 = 0x0020;
#[deprecated(note = "not the spec encoding; use the RESET_QUALIFIER_* values")]
pub const RESET_MODE_FACTORY: u16 = 0x0040;

/// ResetToFactory BlockQualifier values (IEC 61158-6-10; dcp.py
/// ResetQualifier). The mode number sits in bits 1..15, so the qualifier is
/// `mode << 1`; each mode also has an `_ALT` value with bit 0 set.
pub const RESET_QUALIFIER_APPLICATION_DATA: u16 = 0x0002; // mode 1
pub const RESET_QUALIFIER_APPLICATION_DATA_ALT: u16 = 0x0003;
pub const RESET_QUALIFIER_COMMUNICATION_PARAM: u16 = 0x0004; // mode 2
pub const RESET_QUALIFIER_COMMUNICATION_PARAM_ALT: u16 = 0x0005;
pub const RESET_QUALIFIER_ENGINEERING_PARAM: u16 = 0x0006; // mode 3
pub const RESET_QUALIFIER_ENGINEERING_PARAM_ALT: u16 = 0x0007;
pub const RESET_QUALIFIER_ALL_STORED_DATA: u16 = 0x0008; // mode 4
pub const RESET_QUALIFIER_ALL_STORED_DATA_ALT: u16 = 0x0009;
pub const RESET_QUALIFIER_ENGINEERING_PARAM_2: u16 = 0x000A; // mode 5
pub const RESET_QUALIFIER_ENGINEERING_PARAM_2_ALT: u16 = 0x000B;
pub const RESET_QUALIFIER_TO_FACTORY: u16 = 0x0010; // mode 8
pub const RESET_QUALIFIER_TO_FACTORY_ALT: u16 = 0x0011;
pub const RESET_QUALIFIER_AND_RESTORE: u16 = 0x0012; // mode 9
pub const RESET_QUALIFIER_AND_RESTORE_ALT: u16 = 0x0013;

/// Human-readable name of a ResetToFactory qualifier (dcp.py
/// ResetQualifier.get_name).
pub fn reset_qualifier_name(qualifier: u16) -> String {
    let name = match qualifier {
        RESET_QUALIFIER_APPLICATION_DATA | RESET_QUALIFIER_APPLICATION_DATA_ALT => {
            "Reset application data"
        }
        RESET_QUALIFIER_COMMUNICATION_PARAM | RESET_QUALIFIER_COMMUNICATION_PARAM_ALT => {
            "Reset communication parameter"
        }
        RESET_QUALIFIER_ENGINEERING_PARAM
        | RESET_QUALIFIER_ENGINEERING_PARAM_ALT
        | RESET_QUALIFIER_ENGINEERING_PARAM_2
        | RESET_QUALIFIER_ENGINEERING_PARAM_2_ALT => "Reset engineering parameter",
        RESET_QUALIFIER_ALL_STORED_DATA | RESET_QUALIFIER_ALL_STORED_DATA_ALT => {
            "Reset all stored data"
        }
        RESET_QUALIFIER_TO_FACTORY | RESET_QUALIFIER_TO_FACTORY_ALT => "Reset to factory values",
        RESET_QUALIFIER_AND_RESTORE | RESET_QUALIFIER_AND_RESTORE_ALT => "Reset and restore data",
        _ => return format!("Unknown (0x{qualifier:04X})"),
    };
    name.to_string()
}

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
/// payload is a 2-byte qualifier followed by the value. An odd-length value is
/// followed by a pad byte, which DCPDataLength counts.
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

    let mut block = block_request(option, suboption, (value.len() + 2) as u16, &payload);
    // An odd-length value is followed by a pad byte, and DCPDataLength counts
    // it. Declaring the pad without appending it leaves the frame one byte
    // shorter than announced, which a device is right to reject.
    if value.len() % 2 == 1 {
        block.push(0x00);
    }
    let dcp = dcp_header(
        DCP_GET_SET_FRAME_ID,
        DCP_SERVICE_ID_SET,
        DCP_SERVICE_TYPE_REQUEST,
        xid,
        0,
        block.len() as u16,
        &block,
    );
    eth_frame(dst_mac, src_mac, PROFINET_ETHERTYPE, &dcp)
}

/// Set Name-of-Station request as built by dcp.py set_param("name", ...):
/// Device/Name block, temporary qualifier 0x0000, ASCII name.
pub fn set_name_request(src_mac: &[u8; 6], dst_mac: &[u8; 6], xid: u32, name: &str) -> Vec<u8> {
    set_name_request_qualified(src_mac, dst_mac, xid, name, false)
}

/// Set Name-of-Station with an explicit permanence qualifier (dcp.py
/// `set_param(..., permanent=)`): bit 0 of the BlockQualifier asks the device
/// to store the name across a power cycle. [`set_name_request`] is the
/// temporary shorthand.
pub fn set_name_request_qualified(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    xid: u32,
    name: &str,
    permanent: bool,
) -> Vec<u8> {
    set_request(
        src_mac,
        dst_mac,
        xid,
        DCP_OPTION_DEVICE,
        DCP_SUBOPTION_DEVICE_NAME,
        if permanent { 0x0001 } else { 0x0000 },
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

/// Control/ResetToFactory request (dcp.py reset_to_factory): `qualifier` as
/// the block qualifier, no value bytes. Pass a `RESET_QUALIFIER_*` value.
pub fn reset_request(src_mac: &[u8; 6], dst_mac: &[u8; 6], xid: u32, qualifier: u16) -> Vec<u8> {
    set_request(
        src_mac,
        dst_mac,
        xid,
        DCP_OPTION_CONTROL,
        DCP_SUBOPTION_CONTROL_RESET_TO_FACTORY,
        qualifier,
        &[],
    )
}

/// Control/FactoryReset request (suboption 0x05), the reset that preceded
/// ResetToFactory (suboption 0x06). It stays available beside the mode-based
/// reset for a device that refuses the mode it would need. The service predates the
/// reset modes and carries none, so the block qualifier is 0; no value bytes.
pub fn factory_reset_request(src_mac: &[u8; 6], dst_mac: &[u8; 6], xid: u32) -> Vec<u8> {
    set_request(
        src_mac,
        dst_mac,
        xid,
        DCP_OPTION_CONTROL,
        DCP_SUBOPTION_CONTROL_RESET_FACTORY,
        0x0000,
        &[],
    )
}

/// Strip the Ethernet (and optional 802.1Q) header of a PROFINET frame,
/// returning the DCP payload. Mirrors the VLAN handling shared by dcp.py
/// read_response and _parse_set_response.
fn dcp_payload(frame: &[u8]) -> Result<&[u8], String> {
    strip_eth(frame, PROFINET_ETHERTYPE)
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
///
/// `expected_xid` gates ownership exactly as in [`parse_set_response`]: only a
/// GET/SET-frame response carrying our transaction id is ours, and anything
/// else — a foreign device's DCP traffic, a stale reply to an earlier request,
/// a cyclic RT or RTA frame from the same EtherType — yields `Ok(None)` so the
/// caller skips it and keeps waiting for its own answer.
pub fn parse_get_response(
    frame: &[u8],
    option: u8,
    suboption: u8,
    expected_xid: u32,
) -> Result<Option<Vec<u8>>, String> {
    let payload = dcp_payload(frame)?;
    if payload.len() < 12 {
        return Err(format!(
            "payload too short for DCP header: {} bytes",
            payload.len()
        ));
    }
    let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
    let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if frame_id != DCP_GET_SET_FRAME_ID || xid != expected_xid {
        return Ok(None);
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

/// IP BlockInfo values: the status word of an Identify response's IP
/// parameter block (IEC 61158-6-10; dcp.py IPBlockInfo). Bit 7 flags an
/// address conflict on top of the base state.
pub const IP_BLOCK_INFO_NOT_SET: u16 = 0x0000;
pub const IP_BLOCK_INFO_SET: u16 = 0x0001;
pub const IP_BLOCK_INFO_SET_BY_DHCP: u16 = 0x0002;
pub const IP_BLOCK_INFO_NOT_SET_CONFLICT: u16 = 0x0080;
pub const IP_BLOCK_INFO_SET_CONFLICT: u16 = 0x0081;
pub const IP_BLOCK_INFO_SET_BY_DHCP_CONFLICT: u16 = 0x0082;

/// Human-readable name of an IP BlockInfo value (dcp.py IPBlockInfo.get_name).
pub fn ip_block_info_name(info: u16) -> String {
    let name = match info {
        IP_BLOCK_INFO_NOT_SET => "IP not set",
        IP_BLOCK_INFO_SET => "IP set",
        IP_BLOCK_INFO_SET_BY_DHCP => "IP set by DHCP",
        IP_BLOCK_INFO_NOT_SET_CONFLICT => "IP not set (address conflict detected)",
        IP_BLOCK_INFO_SET_CONFLICT => "IP set (address conflict detected)",
        IP_BLOCK_INFO_SET_BY_DHCP_CONFLICT => "IP set by DHCP (address conflict detected)",
        _ => return format!("Unknown (0x{info:04X})"),
    };
    name.to_string()
}

/// Whether an IP BlockInfo value reports an address conflict (dcp.py
/// IPBlockInfo.has_conflict).
pub fn ip_block_info_has_conflict(info: u16) -> bool {
    info & 0x0080 != 0
}

/// Whether an IP BlockInfo value reports a DHCP-assigned address (dcp.py
/// IPBlockInfo.is_dhcp).
pub fn ip_block_info_is_dhcp(info: u16) -> bool {
    info & 0x0002 != 0
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
    /// Status word of the IP parameter block (`IP_BLOCK_INFO_*`): whether the
    /// address is set, set by DHCP, and in conflict. `None` when the response
    /// carried no IP block, which is not the same as the device reporting
    /// "IP not set" (0).
    pub ip_block_info: Option<u16>,
}

/// Parse a DCP Identify response Ethernet frame into a [`DcpDevice`],
/// mirroring the per-frame logic of dcp.py read_response: skip an optional
/// 802.1Q tag, require the PROFINET EtherType, the Identify-response frame ID
/// and a RESPONSE service type, then walk the 2-byte-aligned response blocks
/// (6-byte header including the BlockInfo/status word, which the reference
/// strips from the payload).
///
/// The frame ID is what separates DCP from everything else sharing EtherType
/// 0x8892: cyclic RT and RTA alarm frames land in the same capture, and
/// nothing further down the parse would recognise them as foreign — their
/// bytes at the service-type and xid offsets are process data.
///
/// Unlike [`parse_get_response`] and [`parse_set_response`], this does not
/// check the transaction id, because an Identify request is a multicast that
/// many devices answer and the answers are collected rather than matched one
/// to one. The xid gate belongs to whoever runs that collection:
/// `pcap::aggregate_responses` applies it, via [`parse_dcp_xid`], to every
/// frame before it gets here. A caller that parses an Identify response
/// outside that loop has to apply it itself, or it will accept a response to
/// somebody else's discovery.
pub fn parse_identify_response(frame: &[u8]) -> Result<DcpDevice, String> {
    if frame.len() < 14 {
        return Err(format!(
            "frame too short for Ethernet header: {} bytes",
            frame.len()
        ));
    }
    let src: [u8; 6] = frame[6..12].try_into().expect("6-byte slice");
    let payload = dcp_payload(frame)?;

    if payload.len() < 12 {
        return Err(format!(
            "payload too short for DCP header: {} bytes",
            payload.len()
        ));
    }
    let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
    if frame_id != DCP_IDENTIFY_RESPONSE_FRAME_ID {
        return Err(format!(
            "not a DCP Identify response: frame_id 0x{frame_id:04X}"
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
                device.ip_block_info = Some(u16::from_be_bytes([blocks[4], blocks[5]]));
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
