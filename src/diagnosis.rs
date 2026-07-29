//! PROFINET diagnosis parsing and decoding, ported from `diagnosis.py`:
//! ChannelDiagnosis (USI 0x8000), ExtChannelDiagnosis (USI 0x8002),
//! QualifiedChannelDiagnosis (USI 0x8003) and the channel error-type /
//! channel-properties decoding. All wire fields are big-endian; parsing
//! tolerance (break on truncation, heuristic location-header detection)
//! mirrors the reference exactly.

// ---------------------------------------------------------------------------
// User Structure Identifiers (UserStructureIdentifier IntEnum)
// ---------------------------------------------------------------------------

pub const USI_CHANNEL_DIAGNOSIS: u16 = 0x8000;
pub const USI_MULTIPLE: u16 = 0x8001;
pub const USI_EXT_CHANNEL_DIAGNOSIS: u16 = 0x8002;
pub const USI_QUALIFIED_CHANNEL_DIAGNOSIS: u16 = 0x8003;
pub const USI_MAINTENANCE: u16 = 0x8100;

// ---------------------------------------------------------------------------
// Channel properties bit fields
// ---------------------------------------------------------------------------

/// Channel type from ChannelProperties bits 0-1 (`ChannelType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    Reserved = 0,
    /// Specific channel.
    Specific = 1,
    /// All channels (submodule).
    All = 2,
    /// Whole submodule.
    Submodule = 3,
}

/// Channel direction from ChannelProperties bits 11-12 (`ChannelDirection`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDirection {
    /// Manufacturer-specific.
    Manufacturer = 0,
    Input = 1,
    Output = 2,
    Bidirectional = 3,
}

/// Accumulative info from ChannelProperties bits 2-4 (`ChannelAccumulative`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelAccumulative {
    No = 0,
    /// Main diagnosis (main fault).
    MainFault = 1,
    /// Additional diagnosis.
    AdditionalFault = 2,
    // 3-7: reserved (decoded as No, like the reference's ValueError fallback).
}

/// Specifier from ChannelProperties bits 8-10 (`ChannelSpecifier`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSpecifier {
    /// All diagnosis of submodule disappears.
    AllDisappears = 0,
    /// Diagnosis appears.
    Appears = 1,
    /// Diagnosis disappears.
    Disappears = 2,
    /// Diagnosis disappears, others remain.
    DisappearsOther = 3,
    // 4-7: reserved (decoded as AllDisappears).
}

/// Parsed ChannelProperties bit field, 16 bits (`ChannelProperties`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelProperties {
    pub raw: u16,
    pub channel_type: ChannelType,
    pub accumulative: ChannelAccumulative,
    pub maintenance_required: bool,
    pub maintenance_demanded: bool,
    pub specifier: ChannelSpecifier,
    pub direction: ChannelDirection,
}

impl Default for ChannelProperties {
    fn default() -> ChannelProperties {
        ChannelProperties::from_u16(0)
    }
}

impl ChannelProperties {
    /// Parse ChannelProperties from a 16-bit value
    /// (`ChannelProperties.from_uint16`), with invalid enum values falling
    /// back to the reference defaults.
    pub fn from_u16(value: u16) -> ChannelProperties {
        let channel_type = match value & 0x03 {
            1 => ChannelType::Specific,
            2 => ChannelType::All,
            3 => ChannelType::Submodule,
            _ => ChannelType::Reserved,
        };
        let accumulative = match (value >> 2) & 0x07 {
            1 => ChannelAccumulative::MainFault,
            2 => ChannelAccumulative::AdditionalFault,
            _ => ChannelAccumulative::No,
        };
        let specifier = match (value >> 8) & 0x07 {
            1 => ChannelSpecifier::Appears,
            2 => ChannelSpecifier::Disappears,
            3 => ChannelSpecifier::DisappearsOther,
            _ => ChannelSpecifier::AllDisappears,
        };
        let direction = match (value >> 11) & 0x03 {
            1 => ChannelDirection::Input,
            2 => ChannelDirection::Output,
            3 => ChannelDirection::Bidirectional,
            _ => ChannelDirection::Manufacturer,
        };
        ChannelProperties {
            raw: value,
            channel_type,
            accumulative,
            maintenance_required: (value >> 5) & 0x01 != 0,
            maintenance_demanded: (value >> 6) & 0x01 != 0,
            // Bit 7 reserved.
            specifier,
            direction,
            // Bits 13-15 reserved.
        }
    }
}

// ---------------------------------------------------------------------------
// Diagnosis entries
// ---------------------------------------------------------------------------

/// Which reference dataclass a [`ChannelDiagnosis`] entry corresponds to:
/// the reference models Ext/Qualified as subclasses of ChannelDiagnosis with
/// extra fields; the Rust port flattens them into one struct plus this tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiagnosisKind {
    /// `ChannelDiagnosis` (USI 0x8000, or unknown-USI fallback).
    #[default]
    Channel,
    /// `ExtChannelDiagnosis` (USI 0x8002).
    Ext,
    /// `QualifiedChannelDiagnosis` (USI 0x8003).
    Qualified,
}

/// Channel diagnosis entry (`ChannelDiagnosis` / `ExtChannelDiagnosis` /
/// `QualifiedChannelDiagnosis` flattened; see [`DiagnosisKind`]). The
/// ext/qualifier fields are 0 with empty names for plain channel entries,
/// matching the reference dataclass defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChannelDiagnosis {
    pub kind: DiagnosisKind,
    pub api: u32,
    pub slot: u16,
    pub subslot: u16,
    pub channel_number: u16,
    pub channel_properties: ChannelProperties,
    pub error_type: u16,
    pub error_type_name: String,
    pub ext_error_type: u16,
    pub ext_error_type_name: String,
    pub ext_add_value: u32,
    pub qualifier: u32,
}

impl ChannelDiagnosis {
    /// True if this diagnosis applies to the whole submodule
    /// (channel 0x8000; `is_submodule_level`).
    pub fn is_submodule_level(&self) -> bool {
        self.channel_number == 0x8000
    }
}

/// Complete diagnosis data from a device (`DiagnosisData`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiagnosisData {
    pub api: u32,
    pub slot: u16,
    pub subslot: u16,
    pub entries: Vec<ChannelDiagnosis>,
    pub raw_data: Vec<u8>,
}

impl DiagnosisData {
    /// True if any diagnosis entries exist (`has_errors`).
    pub fn has_errors(&self) -> bool {
        !self.entries.is_empty()
    }

    /// True if any entry has the maintenance_required flag
    /// (`has_maintenance_required`).
    pub fn has_maintenance_required(&self) -> bool {
        self.entries
            .iter()
            .any(|e| e.channel_properties.maintenance_required)
    }

    /// True if any entry has the maintenance_demanded flag
    /// (`has_maintenance_demanded`).
    pub fn has_maintenance_demanded(&self) -> bool {
        self.entries
            .iter()
            .any(|e| e.channel_properties.maintenance_demanded)
    }

    /// All entries for a specific channel (`get_by_channel`).
    pub fn get_by_channel(&self, channel: u16) -> Vec<&ChannelDiagnosis> {
        self.entries
            .iter()
            .filter(|e| e.channel_number == channel)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Decoding functions
// ---------------------------------------------------------------------------

/// Decode ChannelErrorType to a human-readable string
/// (`decode_channel_error_type` / CHANNEL_ERROR_TYPES).
pub fn decode_channel_error_type(error_type: u16) -> String {
    let known = match error_type {
        0x0000 => Some("Reserved"),
        0x0001 => Some("Short circuit"),
        0x0002 => Some("Undervoltage"),
        0x0003 => Some("Overvoltage"),
        0x0004 => Some("Overload"),
        0x0005 => Some("Overtemperature"),
        0x0006 => Some("Line break"),
        0x0007 => Some("Upper limit value exceeded"),
        0x0008 => Some("Lower limit value exceeded"),
        0x0009 => Some("Error"),
        0x000A => Some("Simulation active"),
        0x000B => Some("Reserved (0x000B)"),
        0x000C => Some("Reserved (0x000C)"),
        0x000D => Some("Reserved (0x000D)"),
        0x000E => Some("Reserved (0x000E)"),
        0x000F => Some("Parameter missing"),
        0x0010 => Some("Parameterization fault"),
        0x0011 => Some("Power supply fault"),
        0x0012 => Some("Fuse blown / open"),
        0x0013 => Some("Communication fault"),
        0x0014 => Some("Ground fault"),
        0x0015 => Some("Reference point lost"),
        0x0016 => Some("Process event lost"),
        0x0017 => Some("Threshold warning"),
        0x0018 => Some("Output disabled"),
        0x0019 => Some("Functional safety event"),
        0x001A => Some("External fault"),
        0x001B => Some("Sensor has incorrect configuration"),
        0x001C => Some("Reserved (0x001C)"),
        0x001D => Some("Reserved (0x001D)"),
        0x001E => Some("Reserved (0x001E)"),
        0x001F => Some("Temporary fault"),
        0x8000 => Some("Data transmission impossible"),
        0x8001 => Some("Remote mismatch"),
        0x8002 => Some("Media redundancy mismatch"),
        0x8003 => Some("Sync mismatch"),
        0x8004 => Some("Isochronous mode mismatch"),
        0x8005 => Some("Multicast CR mismatch"),
        0x8006 => Some("Reserved (0x8006)"),
        0x8007 => Some("Fiber optic mismatch"),
        0x8008 => Some("Network component function mismatch"),
        0x8009 => Some("Time mismatch"),
        0x800A => Some("Dynamic frame packing function mismatch"),
        0x800B => Some("Media redundancy with planned duplication mismatch"),
        0x800C => Some("System redundancy mismatch"),
        0x800D => Some("Multiple interface mismatch"),
        0x9500 => Some("IO-Link device event"),
        0x9501 => Some("IO-Link device event (MSB cleared)"),
        0x9502 => Some("IO-Link port event"),
        _ => None,
    };
    if let Some(name) = known {
        return name.to_string();
    }
    match error_type {
        0x0020..=0x00FF => format!("Reserved (0x{error_type:04X})"),
        0x0100..=0x7FFF => format!("Manufacturer-specific (0x{error_type:04X})"),
        0x800E..=0x8FFF => format!("Reserved (0x{error_type:04X})"),
        0x9000..=0x9FFF => format!("Profile-specific (0x{error_type:04X})"),
        0xA000..=0xFFFF => format!("Reserved (0x{error_type:04X})"),
        _ => format!("Unknown (0x{error_type:04X})"),
    }
}

/// Per-ChannelErrorType ExtChannelErrorType lookup
/// (EXT_CHANNEL_ERROR_TYPES_MAP / EXT_CHANNEL_ERROR_TYPES_GENERAL).
fn ext_channel_error_lookup(channel_error_type: u16, ext_error_type: u16) -> Option<&'static str> {
    match channel_error_type {
        // 0x8000: Data transmission impossible.
        0x8000 => match ext_error_type {
            0x0000 => Some("Reserved"),
            0x8000 => Some("Link state mismatch - Loss of link"),
            0x8001 => Some("MAUType mismatch"),
            0x8002 => Some("Line delay mismatch"),
            _ => None,
        },
        // 0x8001: Remote mismatch.
        0x8001 => match ext_error_type {
            0x0000 => Some("Reserved"),
            0x8000 => Some("Peer name of station mismatch"),
            0x8001 => Some("Peer name of port mismatch"),
            0x8002 => Some("Peer RT_CLASS_3 mismatch"),
            0x8003 => Some("Peer MAUType mismatch"),
            0x8004 => Some("Peer MRP domain mismatch"),
            0x8005 => Some("No peer detected"),
            0x8006 => Some("Peer line delay mismatch"),
            0x8007 => Some("Peer PTCP mismatch"),
            0x8008 => Some("Peer Preamble length mismatch"),
            0x8009 => Some("Peer Fragmentation mismatch"),
            _ => None,
        },
        // 0x8002: Media redundancy mismatch.
        0x8002 => match ext_error_type {
            0x0000 => Some("Reserved"),
            0x8000 => Some("Manager role fail"),
            0x8001 => Some("MRP-Loss of redundancy"),
            0x8002 => Some("Reserved (0x8002)"),
            0x8003 => Some("MRP ring open"),
            0x8004 => Some("MRP multiple manager"),
            _ => None,
        },
        // 0x8003: Sync mismatch.
        0x8003 => match ext_error_type {
            0x0000 => Some("Reserved"),
            0x8000 => Some("No sync message received"),
            0x8001 => Some("Jitter out of boundary"),
            0x8002 => Some("Sync message send failure"),
            0x8003 => Some("PTCP timeout"),
            _ => None,
        },
        // 0x8007: Fiber optic mismatch.
        0x8007 => match ext_error_type {
            0x0000 => Some("Reserved"),
            0x8000 => Some("Power budget exceeded"),
            _ => None,
        },
        // 0x8008: Network component function mismatch.
        0x8008 => match ext_error_type {
            0x0000 => Some("Reserved"),
            0x8000 => Some("Frame dropped - no resource"),
            0x8001 => Some("Frame dropped - wrong destination address"),
            0x8002 => Some("Frame dropped - no gateway"),
            _ => None,
        },
        // 0x8009: Time mismatch.
        0x8009 => match ext_error_type {
            0x0000 => Some("Reserved"),
            0x8000 => Some("No master detected"),
            0x8001 => Some("Drift exceeded"),
            0x8002 => Some("Time sync failure"),
            _ => None,
        },
        // 0x800B: Media redundancy with planned duplication.
        0x800B => match ext_error_type {
            0x0000 => Some("Reserved"),
            0x8000 => Some("MRPD loss of redundancy"),
            _ => None,
        },
        // General table for all other ChannelErrorTypes.
        _ => match ext_error_type {
            0x0000 => Some("Reserved"),
            0x8000 => Some("Accumulative info"),
            _ => None,
        },
    }
}

/// Decode ExtChannelErrorType based on the ChannelErrorType context
/// (`decode_ext_channel_error_type`).
pub fn decode_ext_channel_error_type(channel_error_type: u16, ext_error_type: u16) -> String {
    if let Some(name) = ext_channel_error_lookup(channel_error_type, ext_error_type) {
        return name.to_string();
    }
    match ext_error_type {
        0x8000 => "Accumulative info".to_string(),
        0x0001..=0x7FFF => format!("Manufacturer-specific (0x{ext_error_type:04X})"),
        0x8001..=0x8FFF => format!("Reserved (0x{ext_error_type:04X})"),
        0x9000..=0x9FFF => format!("Profile-specific (0x{ext_error_type:04X})"),
        _ => format!("Unknown (0x{ext_error_type:04X})"),
    }
}

// ---------------------------------------------------------------------------
// Parsing functions
// ---------------------------------------------------------------------------

fn u16_at(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Parse a DiagnosisData block from raw bytes (`parse_diagnosis_block`).
pub fn parse_diagnosis_block(data: &[u8], api: u32, slot: u16, subslot: u16) -> DiagnosisData {
    let mut result = DiagnosisData {
        api,
        slot,
        subslot,
        entries: Vec::new(),
        raw_data: data.to_vec(),
    };
    if data.len() < 6 {
        return result;
    }

    let mut api = api;
    let mut slot = slot;
    let mut subslot = subslot;
    let mut offset = 0usize;

    // Skip the block header (BlockType + BlockLength + BlockVersion) if the
    // first word looks like a diagnosis block type.
    let block_type = u16_at(data, 0);
    if matches!(block_type, 0x0010 | 0x0011 | 0x8010 | 0x8011 | 0x8012) {
        offset = 6;
    }

    while offset + 6 <= data.len() {
        // Heuristic location header: API(4) + SlotNumber(2) + SubslotNumber(2)
        // with a small API and slot < 0x8000.
        if offset + 8 <= data.len() {
            let loc_api = u32_at(data, offset);
            let loc_slot = u16_at(data, offset + 4);
            let loc_subslot = u16_at(data, offset + 6);
            if loc_api < 0x10000 && loc_slot < 0x8000 {
                api = loc_api;
                slot = loc_slot;
                subslot = loc_subslot;
                offset += 8;
            }
        }

        if offset + 6 > data.len() {
            break;
        }

        // ChannelNumber + ChannelProperties + UserStructureIdentifier.
        let channel_number = u16_at(data, offset);
        let channel_properties = ChannelProperties::from_u16(u16_at(data, offset + 2));
        let usi = u16_at(data, offset + 4);
        offset += 6;

        match usi {
            USI_EXT_CHANNEL_DIAGNOSIS => {
                // ChannelErrorType(2) + ExtChannelErrorType(2) + AddValue(4).
                if offset + 8 > data.len() {
                    break;
                }
                let error_type = u16_at(data, offset);
                let ext_error_type = u16_at(data, offset + 2);
                let ext_add_value = u32_at(data, offset + 4);
                offset += 8;
                result.entries.push(ChannelDiagnosis {
                    kind: DiagnosisKind::Ext,
                    api,
                    slot,
                    subslot,
                    channel_number,
                    channel_properties,
                    error_type,
                    error_type_name: decode_channel_error_type(error_type),
                    ext_error_type,
                    ext_error_type_name: decode_ext_channel_error_type(error_type, ext_error_type),
                    ext_add_value,
                    qualifier: 0,
                });
            }
            USI_QUALIFIED_CHANNEL_DIAGNOSIS => {
                // Same as Ext + QualifiedChannelQualifier(4).
                if offset + 12 > data.len() {
                    break;
                }
                let error_type = u16_at(data, offset);
                let ext_error_type = u16_at(data, offset + 2);
                let ext_add_value = u32_at(data, offset + 4);
                let qualifier = u32_at(data, offset + 8);
                offset += 12;
                result.entries.push(ChannelDiagnosis {
                    kind: DiagnosisKind::Qualified,
                    api,
                    slot,
                    subslot,
                    channel_number,
                    channel_properties,
                    error_type,
                    error_type_name: decode_channel_error_type(error_type),
                    ext_error_type,
                    ext_error_type_name: decode_ext_channel_error_type(error_type, ext_error_type),
                    ext_add_value,
                    qualifier,
                });
            }
            // USI 0x8000 and any unknown USI: ChannelErrorType(2) only (the
            // reference treats unknown USIs as a basic channel entry).
            _ => {
                if offset + 2 > data.len() {
                    break;
                }
                let error_type = u16_at(data, offset);
                offset += 2;
                result.entries.push(ChannelDiagnosis {
                    kind: DiagnosisKind::Channel,
                    api,
                    slot,
                    subslot,
                    channel_number,
                    channel_properties,
                    error_type,
                    error_type_name: decode_channel_error_type(error_type),
                    ..ChannelDiagnosis::default()
                });
            }
        }
    }

    result
}

/// Parse diagnosis data with simpler format detection
/// (`parse_diagnosis_simple`): 6-byte block header, then flat
/// ChannelNumber(2) + ChannelProperties(2) + ChannelErrorType(2) entries.
pub fn parse_diagnosis_simple(data: &[u8], api: u32, slot: u16, subslot: u16) -> DiagnosisData {
    let mut result = DiagnosisData {
        api,
        slot,
        subslot,
        entries: Vec::new(),
        raw_data: data.to_vec(),
    };
    if data.len() < 6 {
        return result;
    }

    let mut offset = 6usize;
    while offset + 6 <= data.len() {
        let channel_number = u16_at(data, offset);
        let channel_props_raw = u16_at(data, offset + 2);
        let error_type = u16_at(data, offset + 4);
        offset += 6;

        // Sanity check: an all-zero entry terminates the list.
        if error_type == 0 && channel_number == 0 && channel_props_raw == 0 {
            break;
        }

        result.entries.push(ChannelDiagnosis {
            kind: DiagnosisKind::Channel,
            api,
            slot,
            subslot,
            channel_number,
            channel_properties: ChannelProperties::from_u16(channel_props_raw),
            error_type,
            error_type_name: decode_channel_error_type(error_type),
            ..ChannelDiagnosis::default()
        });
    }

    result
}
