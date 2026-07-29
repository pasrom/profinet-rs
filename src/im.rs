//! I&M (Identification & Maintenance) and identification records: record
//! index constants from `indices.py`, the PNInM0..PNInM3 response structs
//! from `protocol.py`, and the PDRealData / RealIdentificationData /
//! I&M0FilterData response parsers from `blocks.py` / `rpc.py`. All wire
//! fields are big-endian; parsing tolerance (break on truncation, skip
//! malformed nested blocks) mirrors the reference exactly.

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Record indices (indices.py)
// ---------------------------------------------------------------------------

/// I&M0 (mandatory): VendorID, OrderID, SerialNumber, HW/SW revision.
pub const IM0: u16 = 0xAFF0;
/// I&M1: Tag_Function + Tag_Location.
pub const IM1: u16 = 0xAFF1;
/// I&M2: Installation_Date.
pub const IM2: u16 = 0xAFF2;
/// I&M3: Descriptor.
pub const IM3: u16 = 0xAFF3;
/// I&M4: Safety signature (PROFIsafe).
pub const IM4: u16 = 0xAFF4;
/// I&M5: Annotation string.
pub const IM5: u16 = 0xAFF5;
pub const IM6: u16 = 0xAFF6;
pub const IM7: u16 = 0xAFF7;
pub const IM8: u16 = 0xAFF8;
pub const IM9: u16 = 0xAFF9;
pub const IM10: u16 = 0xAFFA;
pub const IM11: u16 = 0xAFFB;
pub const IM12: u16 = 0xAFFC;
pub const IM13: u16 = 0xAFFD;
pub const IM14: u16 = 0xAFFE;
pub const IM15: u16 = 0xAFFF;
/// I&M0FilterData: lists all submodules with I&M data.
pub const IM0_FILTER_DATA: u16 = 0xF840;

// Configuration/identification indices.
pub const EXPECTED_ID_SUBSLOT: u16 = 0x8000;
pub const REAL_ID_SUBSLOT: u16 = 0x8001;
pub const EXPECTED_ID_AR: u16 = 0xE000;
pub const REAL_ID_AR: u16 = 0xE001;
pub const MODULE_DIFF_BLOCK: u16 = 0xE002;
/// RealIdentificationData for one API (API level).
pub const REAL_ID_API: u16 = 0xF000;

// Device-level indices.
pub const AR_DATA: u16 = 0xF820;
pub const API_DATA: u16 = 0xF821;
pub const LOG_DATA: u16 = 0xF830;
pub const PDEV_DATA: u16 = 0xF831;
pub const PD_REAL_DATA: u16 = 0xF841;
pub const PD_EXPECTED_DATA: u16 = 0xF842;
pub const AUTO_CONFIG: u16 = 0xF850;
pub const DIAG_DEVICE: u16 = 0xF80C;

// ---------------------------------------------------------------------------
// Block types (indices.py, from the Wireshark pn_io dissector)
// ---------------------------------------------------------------------------

pub const BLOCK_DIAGNOSIS_DATA: u16 = 0x0010;
pub const BLOCK_EXPECTED_IDENTIFICATION_DATA: u16 = 0x0012;
pub const BLOCK_REAL_IDENTIFICATION_DATA: u16 = 0x0013;
pub const BLOCK_IM0: u16 = 0x0020;
pub const BLOCK_IM1: u16 = 0x0021;
pub const BLOCK_IM2: u16 = 0x0022;
pub const BLOCK_IM3: u16 = 0x0023;
pub const BLOCK_PD_PORT_DATA_REAL: u16 = 0x020F;
pub const BLOCK_PD_INTERFACE_DATA_REAL: u16 = 0x0240;
pub const BLOCK_PD_PORT_STATISTIC: u16 = 0x0251;
pub const BLOCK_MULTIPLE_HEADER: u16 = 0x0400;
pub const BLOCK_CO_CONTAINER_CONTENT: u16 = 0x0401;
pub const BLOCK_AR_SERVER_BLOCK: u16 = 0xF820;
pub const BLOCK_PD_REAL_DATA: u16 = 0xF841;
pub const BLOCK_PD_EXPECTED_DATA: u16 = 0xF842;
pub const BLOCK_REAL_IDENTIFICATION_DATA_API: u16 = 0xF000;

/// Human-readable block type name (get_block_type_name / BLOCK_TYPE_NAMES).
pub fn block_type_name(block_type: u16) -> String {
    let name = match block_type {
        0x0001 => "AlarmNotificationHigh",
        0x8001 => "AlarmAckHigh",
        0x0002 => "AlarmNotificationLow",
        0x8002 => "AlarmAckLow",
        0x0008 => "IODWriteReqHeader",
        0x8008 => "IODWriteResHeader",
        0x0009 => "IODReadReqHeader",
        0x8009 => "IODReadResHeader",
        0x0010 => "DiagnosisData",
        0x0012 => "ExpectedIdentificationData",
        0x0013 => "RealIdentificationData",
        0x0020 => "I&M0",
        0x0021 => "I&M1",
        0x0022 => "I&M2",
        0x0023 => "I&M3",
        0x0024 => "I&M4",
        0x0025 => "I&M5",
        0x0026 => "I&M6",
        0x0027 => "I&M7",
        0x0028 => "I&M8",
        0x0029 => "I&M9",
        0x002A => "I&M10",
        0x002B => "I&M11",
        0x002C => "I&M12",
        0x002D => "I&M13",
        0x002E => "I&M14",
        0x002F => "I&M15",
        0x0101 => "ARBlockReq",
        0x8101 => "ARBlockRes",
        0x0102 => "IOCRBlockReq",
        0x8102 => "IOCRBlockRes",
        0x0103 => "AlarmCRBlockReq",
        0x8103 => "AlarmCRBlockRes",
        0x0104 => "ExpectedSubmoduleBlockReq",
        0x8104 => "ModuleDiffBlock",
        0x0110 => "IODControlReqPrmEnd",
        0x8110 => "IODControlResPrmEnd",
        0x0112 => "IODControlReqAppReady",
        0x8112 => "IODControlResAppReady",
        0x0114 => "IODReleaseReq",
        0x8114 => "IODReleaseRes",
        0x0117 => "IODControlReqRTClass3",
        0x8117 => "IODControlResRTClass3",
        0x0118 => "PrmBeginReq",
        0x8118 => "PrmBeginRes",
        0x0119 => "SubmoduleListBlock",
        0x0018 => "ARData",
        0x0019 => "LogData",
        0x001A => "APIData",
        0x001B => "SRLData",
        0x0200 => "PDPortDataCheck",
        0x0202 => "PDPortDataAdjust",
        0x020F => "PDPortDataReal",
        0x0211 => "PDInterfaceMrpDataAdjust",
        0x0212 => "PDInterfaceMrpDataReal",
        0x0215 => "PDPortMrpDataReal",
        0x0219 => "MrpRingStateData",
        0x0220 => "PDPortFODataReal",
        0x0221 => "PDPortFODataCheck",
        0x0222 => "PDPortFODataAdjust",
        0x022C => "PDPortDataRealExtended",
        0x0240 => "PDInterfaceDataReal",
        0x0251 => "PDPortStatistic",
        0x0400 => "MultipleBlockHeader",
        0x0401 => "COContainerContent",
        0xF820 => "ARServerBlock",
        0xF841 => "PDRealData",
        0xF842 => "PDExpectedData",
        0xF000 => "RealIdentificationDataAPI",
        _ => return format!("Unknown(0x{block_type:04X})"),
    };
    name.to_string()
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

/// Decode bytes to string, stripping trailing null terminators
/// (util.decode_bytes: rstrip(b"\x00") + utf-8 with errors="replace").
pub fn decode_bytes(data: &[u8]) -> String {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// Latin-1 decode as used for chassis/port ID strings in blocks.py
/// (every byte maps 1:1 to the same code point, so it cannot fail).
fn decode_latin1(data: &[u8]) -> String {
    data.iter().map(|&b| b as char).collect()
}

fn be16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn be32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Align offset to 4-byte boundary (align4).
pub fn align4(offset: usize) -> usize {
    (offset + 3) & !3
}

// ---------------------------------------------------------------------------
// Block header
// ---------------------------------------------------------------------------

/// PROFINET block header, 6 bytes (BlockHeader).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub block_type: u16,
    /// Includes the two version bytes; body = length - 2.
    pub block_length: u16,
    pub version_high: u8,
    pub version_low: u8,
}

impl BlockHeader {
    /// Length of the block body excluding the version bytes (body_length).
    pub fn body_length(&self) -> usize {
        if self.block_length >= 2 {
            usize::from(self.block_length) - 2
        } else {
            0
        }
    }

    /// Human-readable block type name (type_name).
    pub fn type_name(&self) -> String {
        block_type_name(self.block_type)
    }
}

/// Parse a 6-byte block header at `offset`, returning the header and the
/// offset just past it (parse_block_header).
pub fn parse_block_header(data: &[u8], offset: usize) -> Result<(BlockHeader, usize), String> {
    if data.len() < offset + 6 {
        return Err(format!(
            "Block header requires 6 bytes, got {}",
            data.len().saturating_sub(offset)
        ));
    }
    let header = BlockHeader {
        block_type: be16(data, offset),
        block_length: be16(data, offset + 2),
        version_high: data[offset + 4],
        version_low: data[offset + 5],
    };
    Ok((header, offset + 6))
}

/// Parse a MultipleBlockHeader (0x0400) body: 2 bytes padding, API (u32),
/// SlotNr (u16), SubslotNr (u16); returns (api, slot, subslot, offset where
/// the nested blocks start) (parse_multiple_block_header).
pub fn parse_multiple_block_header(
    data: &[u8],
    offset: usize,
) -> Result<(u32, u16, u16, usize), String> {
    if data.len() < offset + 10 {
        return Err("MultipleBlockHeader body requires 8 bytes after padding".to_string());
    }
    let api = be32(data, offset + 2);
    let slot = be16(data, offset + 6);
    let subslot = be16(data, offset + 8);
    Ok((api, slot, subslot, offset + 10))
}

// ---------------------------------------------------------------------------
// I&M0..I&M3 response structs (protocol.py PNInM0..PNInM3)
// ---------------------------------------------------------------------------

/// I&M0 identification data (PNInM0), 60 bytes fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InM0 {
    pub block_header: BlockHeader,
    pub vendor_id_high: u8,
    pub vendor_id_low: u8,
    /// Raw 20-byte order ID field; use [`InM0::order_id_str`] for the
    /// null-stripped string view (decode_bytes).
    pub order_id: [u8; 20],
    pub im_serial_number: [u8; 16],
    pub im_hardware_revision: u16,
    pub sw_revision_prefix: u8,
    pub im_sw_revision_functional_enhancement: u8,
    pub im_sw_revision_bug_fix: u8,
    pub im_sw_revision_internal_change: u8,
    pub im_revision_counter: u16,
    pub im_profile_id: u16,
    pub im_profile_specific_type: u16,
    pub im_version: u16,
    pub im_supported: u16,
}

impl InM0 {
    pub const IDX: u16 = IM0;

    /// Combined 16-bit vendor ID (the PNInM0.vendor_id property).
    pub fn vendor_id(&self) -> u16 {
        (u16::from(self.vendor_id_high) << 8) | u16::from(self.vendor_id_low)
    }

    pub fn order_id_str(&self) -> String {
        decode_bytes(&self.order_id)
    }

    pub fn serial_number_str(&self) -> String {
        decode_bytes(&self.im_serial_number)
    }

    /// Software revision as "V1.2.3" (device.py software_revision property:
    /// no prefix character when the prefix byte is 0).
    pub fn software_revision(&self) -> String {
        let prefix = if self.sw_revision_prefix != 0 {
            (self.sw_revision_prefix as char).to_string()
        } else {
            String::new()
        };
        format!(
            "{prefix}{}.{}.{}",
            self.im_sw_revision_functional_enhancement,
            self.im_sw_revision_bug_fix,
            self.im_sw_revision_internal_change
        )
    }
}

/// I&M1 tag function/location (PNInM1), 60 bytes fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InM1 {
    pub block_header: BlockHeader,
    pub im_tag_function: [u8; 32],
    pub im_tag_location: [u8; 22],
}

impl InM1 {
    pub const IDX: u16 = IM1;

    pub fn tag_function_str(&self) -> String {
        decode_bytes(&self.im_tag_function)
    }

    pub fn tag_location_str(&self) -> String {
        decode_bytes(&self.im_tag_location)
    }
}

/// I&M2 installation date (PNInM2), 22 bytes fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InM2 {
    pub block_header: BlockHeader,
    /// "YYYY-MM-DD HH:MM" format.
    pub im_date: [u8; 16],
}

impl InM2 {
    pub const IDX: u16 = IM2;

    pub fn date_str(&self) -> String {
        decode_bytes(&self.im_date)
    }
}

/// I&M3 descriptor (PNInM3), 60 bytes fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InM3 {
    pub block_header: BlockHeader,
    pub im_descriptor: [u8; 54],
}

impl InM3 {
    pub const IDX: u16 = IM3;

    pub fn descriptor_str(&self) -> String {
        decode_bytes(&self.im_descriptor)
    }
}

fn need(name: &str, data: &[u8], size: usize) -> Result<(), String> {
    if data.len() < size {
        Err(format!(
            "{name}: insufficient data, need {size} bytes, got {}",
            data.len()
        ))
    } else {
        Ok(())
    }
}

fn copy<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&data[offset..offset + N]);
    out
}

/// Parse an I&M0 record payload (PNInM0(iod.payload)); extra trailing bytes
/// are ignored like the reference's fixed-size parse.
pub fn parse_im0(data: &[u8]) -> Result<InM0, String> {
    need("PNInM0", data, 60)?;
    let (block_header, _) = parse_block_header(data, 0)?;
    Ok(InM0 {
        block_header,
        vendor_id_high: data[6],
        vendor_id_low: data[7],
        order_id: copy(data, 8),
        im_serial_number: copy(data, 28),
        im_hardware_revision: be16(data, 44),
        sw_revision_prefix: data[46],
        im_sw_revision_functional_enhancement: data[47],
        im_sw_revision_bug_fix: data[48],
        im_sw_revision_internal_change: data[49],
        im_revision_counter: be16(data, 50),
        im_profile_id: be16(data, 52),
        im_profile_specific_type: be16(data, 54),
        im_version: be16(data, 56),
        im_supported: be16(data, 58),
    })
}

/// Parse an I&M1 record payload (PNInM1(iod.payload)).
pub fn parse_im1(data: &[u8]) -> Result<InM1, String> {
    need("PNInM1", data, 60)?;
    let (block_header, _) = parse_block_header(data, 0)?;
    Ok(InM1 {
        block_header,
        im_tag_function: copy(data, 6),
        im_tag_location: copy(data, 38),
    })
}

/// Parse an I&M2 record payload (PNInM2(iod.payload)).
pub fn parse_im2(data: &[u8]) -> Result<InM2, String> {
    need("PNInM2", data, 22)?;
    let (block_header, _) = parse_block_header(data, 0)?;
    Ok(InM2 {
        block_header,
        im_date: copy(data, 6),
    })
}

/// Parse an I&M3 record payload (PNInM3(iod.payload)).
pub fn parse_im3(data: &[u8]) -> Result<InM3, String> {
    need("PNInM3", data, 60)?;
    let (block_header, _) = parse_block_header(data, 0)?;
    Ok(InM3 {
        block_header,
        im_descriptor: copy(data, 6),
    })
}

// ---------------------------------------------------------------------------
// PDRealData / RealIdentificationData structures (blocks.py)
// ---------------------------------------------------------------------------

/// Slot/subslot discovered from a device (SlotInfo).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SlotInfo {
    pub slot: u16,
    pub subslot: u16,
    pub api: u32,
    pub module_ident: u32,
    pub submodule_ident: u32,
    /// Nested block type names seen for this slot (PDRealData only).
    pub blocks: Vec<String>,
}

impl SlotInfo {
    /// View as the slot type consumed by
    /// [`crate::gsdml::GsdmlDevice::build_io_slots_from_device`].
    pub fn to_device_slot(&self) -> crate::gsdml::DeviceSlot {
        crate::gsdml::DeviceSlot {
            slot: self.slot,
            subslot: self.subslot,
            module_ident: self.module_ident,
            submodule_ident: self.submodule_ident,
        }
    }
}

/// LLDP peer information from PDPortDataReal (PeerInfo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub port_id: String,
    pub chassis_id: String,
    pub mac_address: [u8; 6],
}

impl PeerInfo {
    pub fn mac_str(&self) -> String {
        mac_colon_str(&self.mac_address)
    }
}

/// Port information from PDPortDataReal 0x020F (PortInfo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortInfo {
    pub slot: u16,
    pub subslot: u16,
    pub port_id: String,
    pub mau_type: u16,
    pub link_state_port: u8,
    pub link_state_link: u8,
    pub media_type: u32,
    pub peers: Vec<PeerInfo>,
    pub domain_boundary: u32,
    pub multicast_boundary: u32,
}

impl PortInfo {
    /// Human-readable link state (link_state property).
    pub fn link_state(&self) -> String {
        match self.link_state_link {
            0 => "Unknown".to_string(),
            1 => "Up".to_string(),
            2 => "Down".to_string(),
            3 => "Testing".to_string(),
            other => format!("Unknown({other})"),
        }
    }
}

/// Interface information from PDInterfaceDataReal 0x0240 (InterfaceInfo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub chassis_id: String,
    pub mac_address: [u8; 6],
    pub ip_address: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub gateway: [u8; 4],
}

fn mac_colon_str(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn dotted(ip: &[u8; 4]) -> String {
    ip.iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

impl InterfaceInfo {
    pub fn mac_str(&self) -> String {
        mac_colon_str(&self.mac_address)
    }

    pub fn ip_str(&self) -> String {
        dotted(&self.ip_address)
    }

    pub fn subnet_str(&self) -> String {
        dotted(&self.subnet_mask)
    }

    pub fn gateway_str(&self) -> String {
        dotted(&self.gateway)
    }
}

/// Parsed PDRealData 0xF841 (PDRealData).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PdRealData {
    pub slots: Vec<SlotInfo>,
    pub interface: Option<InterfaceInfo>,
    pub ports: Vec<PortInfo>,
    /// (api, slot, subslot, raw block bytes) per MultipleBlockHeader.
    pub raw_blocks: Vec<(u32, u16, u16, Vec<u8>)>,
}

/// Parsed RealIdentificationData 0xF000/0x0013 (RealIdentificationData).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealIdentificationData {
    pub slots: Vec<SlotInfo>,
    pub version: (u8, u8),
}

impl Default for RealIdentificationData {
    fn default() -> Self {
        RealIdentificationData {
            slots: Vec::new(),
            version: (1, 0),
        }
    }
}

// ---------------------------------------------------------------------------
// PDRealData parsers (blocks.py)
// ---------------------------------------------------------------------------

/// Parse a PDInterfaceDataReal (0x0240) block body starting at `offset`;
/// alignment is relative to the block start including the 6-byte header
/// (parse_pd_interface_data_real with the default block_header_size).
pub fn parse_pd_interface_data_real(data: &[u8], offset: usize) -> Result<InterfaceInfo, String> {
    const BLOCK_HEADER_SIZE: usize = 6;
    let start = offset;
    let align_from_block = |body_offset: usize| -> usize {
        let block_offset = BLOCK_HEADER_SIZE + (body_offset - start);
        start + (align4(block_offset) - BLOCK_HEADER_SIZE)
    };

    let mut offset = offset;
    if data.len() <= offset {
        return Err("Truncated chassis ID".to_string());
    }
    let chassis_len = usize::from(data[offset]);
    offset += 1;

    if data.len() < offset + chassis_len {
        return Err("Truncated chassis ID".to_string());
    }
    let chassis_id = decode_latin1(&data[offset..offset + chassis_len]);
    offset += chassis_len;

    offset = align_from_block(offset);

    if data.len() < offset + 6 {
        return Err("Truncated MAC address".to_string());
    }
    let mac_address: [u8; 6] = copy(data, offset);
    offset += 6;

    offset = align_from_block(offset);

    if data.len() < offset + 12 {
        return Err("Truncated IP configuration".to_string());
    }
    Ok(InterfaceInfo {
        chassis_id,
        mac_address,
        ip_address: copy(data, offset),
        subnet_mask: copy(data, offset + 4),
        gateway: copy(data, offset + 8),
    })
}

/// Parse a PDPortDataReal (0x020F) block body starting at `offset`
/// (parse_pd_port_data_real); missing trailing fields default to zero like
/// the reference's length-guarded reads.
pub fn parse_pd_port_data_real(data: &[u8], offset: usize, slot: u16, subslot: u16) -> PortInfo {
    let start = offset;
    // The reference aligns the first field on the absolute offset, then all
    // later paddings relative to the body start; copied verbatim.
    let mut offset = align4(offset);
    let mut slot = slot;
    let mut subslot = subslot;

    if data.len() >= offset + 4 {
        slot = be16(data, offset);
        subslot = be16(data, offset + 2);
        offset += 4;
    }

    if data.len() < offset + 1 {
        return PortInfo {
            slot,
            subslot,
            port_id: String::new(),
            mau_type: 0,
            link_state_port: 0,
            link_state_link: 0,
            media_type: 0,
            peers: Vec::new(),
            domain_boundary: 0,
            multicast_boundary: 0,
        };
    }

    let port_id_len = usize::from(data[offset]);
    offset += 1;

    let port_id = if data.len() < offset + port_id_len {
        String::new()
    } else {
        let s = decode_latin1(&data[offset..offset + port_id_len]);
        offset += port_id_len;
        s
    };

    let mut num_peers = 0usize;
    let mut peers = Vec::new();
    if data.len() > offset {
        num_peers = usize::from(data[offset]);
        offset += 1;
    }

    offset = start + align4(offset - start);

    for _ in 0..num_peers {
        if data.len() < offset + 1 {
            break;
        }

        let peer_port_len = usize::from(data[offset]);
        offset += 1;
        let mut peer_port_id = String::new();
        if data.len() >= offset + peer_port_len {
            peer_port_id = decode_latin1(&data[offset..offset + peer_port_len]);
            offset += peer_port_len;
        }

        if data.len() < offset + 1 {
            break;
        }
        let peer_chassis_len = usize::from(data[offset]);
        offset += 1;
        let mut peer_chassis_id = String::new();
        if data.len() >= offset + peer_chassis_len {
            peer_chassis_id = decode_latin1(&data[offset..offset + peer_chassis_len]);
            offset += peer_chassis_len;
        }

        offset = start + align4(offset - start);

        let mut peer_mac = [0u8; 6];
        if data.len() >= offset + 6 {
            peer_mac = copy(data, offset);
            offset += 6;
        }

        offset = start + align4(offset - start);

        peers.push(PeerInfo {
            port_id: peer_port_id,
            chassis_id: peer_chassis_id,
            mac_address: peer_mac,
        });
    }

    let mut mau_type = 0;
    if data.len() >= offset + 2 {
        mau_type = be16(data, offset);
        offset += 2;
    }

    offset = start + align4(offset - start);

    let mut domain_boundary = 0;
    let mut multicast_boundary = 0;
    if data.len() >= offset + 8 {
        domain_boundary = be32(data, offset);
        multicast_boundary = be32(data, offset + 4);
        offset += 8;
    }

    let mut link_state_port = 0;
    let mut link_state_link = 0;
    if data.len() >= offset + 2 {
        link_state_port = data[offset];
        link_state_link = data[offset + 1];
        offset += 2;
    }

    offset = start + align4(offset - start);

    let mut media_type = 0;
    if data.len() >= offset + 4 {
        media_type = be32(data, offset);
    }

    PortInfo {
        slot,
        subslot,
        port_id,
        mau_type,
        link_state_port,
        link_state_link,
        media_type,
        peers,
        domain_boundary,
        multicast_boundary,
    }
}

/// Parse a complete PDRealData (0xF841) response: a sequence of
/// MultipleBlockHeader blocks with nested PDInterfaceDataReal /
/// PDPortDataReal sub-blocks (parse_pd_real_data). Malformed blocks are
/// skipped, never fatal.
pub fn parse_pd_real_data(data: &[u8]) -> PdRealData {
    let mut result = PdRealData::default();
    let mut offset = 0usize;

    while offset + 6 <= data.len() {
        let Ok((header, new_offset)) = parse_block_header(data, offset) else {
            break;
        };

        let block_end = new_offset + header.body_length();

        if header.block_type == BLOCK_MULTIPLE_HEADER {
            if let Ok((api, slot_nr, subslot_nr, mut nested_offset)) =
                parse_multiple_block_header(data, new_offset)
            {
                let mut slot_info = SlotInfo {
                    api,
                    slot: slot_nr,
                    subslot: subslot_nr,
                    ..SlotInfo::default()
                };

                while nested_offset + 6 <= block_end {
                    let Ok((nested_header, nested_body)) = parse_block_header(data, nested_offset)
                    else {
                        break;
                    };

                    let nested_end = nested_body + nested_header.body_length();
                    slot_info.blocks.push(nested_header.type_name());

                    if nested_header.block_type == BLOCK_PD_INTERFACE_DATA_REAL {
                        if let Ok(interface) = parse_pd_interface_data_real(data, nested_body) {
                            result.interface = Some(interface);
                        }
                    } else if nested_header.block_type == BLOCK_PD_PORT_DATA_REAL {
                        result.ports.push(parse_pd_port_data_real(
                            data,
                            nested_body,
                            slot_nr,
                            subslot_nr,
                        ));
                    }

                    nested_offset = nested_end;
                }

                result.slots.push(slot_info);
                result.raw_blocks.push((
                    api,
                    slot_nr,
                    subslot_nr,
                    data[new_offset..block_end.min(data.len())].to_vec(),
                ));
            }
        }

        offset = block_end;
    }

    result
}

/// Parse a RealIdentificationData (0xF000 or 0x0013) response, both v1.0
/// (no API level) and v1.1 (per-API) layouts
/// (parse_real_identification_data). Truncated data yields the slots parsed
/// so far, never an error.
pub fn parse_real_identification_data(data: &[u8]) -> RealIdentificationData {
    let mut result = RealIdentificationData::default();
    let mut offset = 0usize;

    // Outer block header if present (the reference parses it blindly without
    // checking the block type).
    if data.len() >= 6 {
        if let Ok((header, new_offset)) = parse_block_header(data, 0) {
            result.version = (header.version_high, header.version_low);
            offset = new_offset;
        }
    }

    if data.len() < offset + 2 {
        return result;
    }

    if result.version.0 >= 1 && result.version.1 >= 1 {
        // Version 1.1: NumberOfAPIs first.
        let num_apis = be16(data, offset);
        offset += 2;

        for _ in 0..num_apis {
            if data.len() < offset + 6 {
                break;
            }
            let api = be32(data, offset);
            let num_slots = be16(data, offset + 4);
            offset += 6;

            for _ in 0..num_slots {
                if data.len() < offset + 8 {
                    break;
                }
                let slot_nr = be16(data, offset);
                let module_ident = be32(data, offset + 2);
                let num_subslots = be16(data, offset + 6);
                offset += 8;

                for _ in 0..num_subslots {
                    if data.len() < offset + 6 {
                        break;
                    }
                    result.slots.push(SlotInfo {
                        api,
                        slot: slot_nr,
                        subslot: be16(data, offset),
                        module_ident,
                        submodule_ident: be32(data, offset + 2),
                        blocks: Vec::new(),
                    });
                    offset += 6;
                }
            }
        }
    } else {
        // Version 1.0: no API level.
        let num_slots = be16(data, offset);
        offset += 2;

        for _ in 0..num_slots {
            if data.len() < offset + 8 {
                break;
            }
            let slot_nr = be16(data, offset);
            let module_ident = be32(data, offset + 2);
            let num_subslots = be16(data, offset + 6);
            offset += 8;

            for _ in 0..num_subslots {
                if data.len() < offset + 6 {
                    break;
                }
                result.slots.push(SlotInfo {
                    api: 0,
                    slot: slot_nr,
                    subslot: be16(data, offset),
                    module_ident,
                    submodule_ident: be32(data, offset + 2),
                    blocks: Vec::new(),
                });
                offset += 6;
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// I&M0FilterData (rpc.py read_inm0filter)
// ---------------------------------------------------------------------------

/// Device topology from I&M0FilterData:
/// api -> slot -> (module_ident, subslot -> submodule_ident).
pub type InM0FilterData = BTreeMap<u32, BTreeMap<u16, (u32, BTreeMap<u16, u32>)>>;

/// Parse an I&M0FilterData (0xF840) record payload into nested maps exactly
/// as `read_inm0filter` does; unlike the PDRealData parsers, truncation is an
/// error here (the reference's struct parses raise).
pub fn parse_inm0_filter(data: &[u8]) -> Result<InM0FilterData, String> {
    // Validate the block header, then skip it.
    parse_block_header(data, 0)?;
    let data = &data[6..];
    let mut offset = 0usize;

    let mut result = InM0FilterData::new();

    if data.len() < 2 {
        return Err("InM0FilterData: truncated API count".to_string());
    }
    let num_api = be16(data, offset);
    offset += 2;

    for _ in 0..num_api {
        if data.len() < offset + 6 {
            return Err("InM0FilterData: truncated API header".to_string());
        }
        let api = be32(data, offset);
        let num_modules = be16(data, offset + 4);
        offset += 6;
        // `result[api] = {}` in the reference: a repeated API resets its map.
        result.insert(api, BTreeMap::new());
        let api_entry = result.get_mut(&api).expect("inserted above");

        for _ in 0..num_modules {
            if data.len() < offset + 8 {
                return Err("InM0FilterData: truncated module header".to_string());
            }
            let slot_number = be16(data, offset);
            let module_ident_num = be32(data, offset + 2);
            let num_subslots = be16(data, offset + 6);
            offset += 8;

            let mut subslots = BTreeMap::new();
            for _ in 0..num_subslots {
                if data.len() < offset + 6 {
                    return Err("InM0FilterData: truncated subslot entry".to_string());
                }
                let subslot_number = be16(data, offset);
                let submodule_ident_number = be32(data, offset + 2);
                offset += 6;
                subslots.insert(subslot_number, submodule_ident_number);
            }

            api_entry.insert(slot_number, (module_ident_num, subslots));
        }
    }

    Ok(result)
}
