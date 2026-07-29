//! PROFINET alarm handling, ported from `alarms.py` (+ the alarm-related
//! constants and name helpers from `indices.py` and the AlarmCRBlockRes
//! parsing from `rpc.py`): AlarmNotification parsing, the alarm item types
//! (Diagnosis, Maintenance, Upload/Retrieval, RS, PE, PRAL) and the USI
//! dispatch. Per IEC 61158-6-10; all wire fields are big-endian.

// ---------------------------------------------------------------------------
// Block types and alarm types (indices.py)
// ---------------------------------------------------------------------------

pub const BLOCK_ALARM_NOTIFICATION_HIGH: u16 = 0x0001;
pub const BLOCK_ALARM_ACK_HIGH: u16 = 0x8001;
pub const BLOCK_ALARM_NOTIFICATION_LOW: u16 = 0x0002;
pub const BLOCK_ALARM_ACK_LOW: u16 = 0x8002;
pub const BLOCK_ALARM_CR_REQ: u16 = 0x0103;
pub const BLOCK_ALARM_CR_RES: u16 = 0x8103;

pub const ALARM_TYPE_DIAGNOSIS: u16 = 0x0001;
pub const ALARM_TYPE_PROCESS: u16 = 0x0002;
pub const ALARM_TYPE_PULL: u16 = 0x0003;
pub const ALARM_TYPE_PLUG: u16 = 0x0004;
pub const ALARM_TYPE_STATUS: u16 = 0x0005;
pub const ALARM_TYPE_UPDATE: u16 = 0x0006;
pub const ALARM_TYPE_REDUNDANCY: u16 = 0x0007;
pub const ALARM_TYPE_CONTROLLED_BY_SUPERVISOR: u16 = 0x0008;
pub const ALARM_TYPE_RELEASED: u16 = 0x0009;
pub const ALARM_TYPE_PLUG_WRONG_SUBMODULE: u16 = 0x000A;
pub const ALARM_TYPE_RETURN_OF_SUBMODULE: u16 = 0x000B;
pub const ALARM_TYPE_DIAGNOSIS_DISAPPEARS: u16 = 0x000C;
pub const ALARM_TYPE_MULTICAST_MISMATCH: u16 = 0x000D;
pub const ALARM_TYPE_PORT_DATA_CHANGE: u16 = 0x000E;
pub const ALARM_TYPE_SYNC_DATA_CHANGED: u16 = 0x000F;
pub const ALARM_TYPE_ISOCHRONOUS_MODE_PROBLEM: u16 = 0x0010;
pub const ALARM_TYPE_NETWORK_COMPONENT_PROBLEM: u16 = 0x0011;
pub const ALARM_TYPE_TIME_DATA_CHANGED: u16 = 0x0012;
pub const ALARM_TYPE_DFP_PROBLEM: u16 = 0x0013;
pub const ALARM_TYPE_UPLOAD_RETRIEVAL: u16 = 0x001E;
pub const ALARM_TYPE_PULL_MODULE: u16 = 0x001F;

/// Human-readable alarm type name (`get_alarm_type_name`).
pub fn get_alarm_type_name(alarm_type: u16) -> String {
    match alarm_type {
        ALARM_TYPE_DIAGNOSIS => "Diagnosis".to_string(),
        ALARM_TYPE_PROCESS => "Process".to_string(),
        ALARM_TYPE_PULL => "Pull".to_string(),
        ALARM_TYPE_PLUG => "Plug".to_string(),
        ALARM_TYPE_STATUS => "Status".to_string(),
        ALARM_TYPE_UPDATE => "Update".to_string(),
        ALARM_TYPE_REDUNDANCY => "Redundancy".to_string(),
        ALARM_TYPE_CONTROLLED_BY_SUPERVISOR => "ControlledBySupervisor".to_string(),
        ALARM_TYPE_RELEASED => "Released".to_string(),
        ALARM_TYPE_PLUG_WRONG_SUBMODULE => "PlugWrongSubmodule".to_string(),
        ALARM_TYPE_RETURN_OF_SUBMODULE => "ReturnOfSubmodule".to_string(),
        ALARM_TYPE_DIAGNOSIS_DISAPPEARS => "DiagnosisDisappears".to_string(),
        ALARM_TYPE_MULTICAST_MISMATCH => "MulticastMismatch".to_string(),
        ALARM_TYPE_PORT_DATA_CHANGE => "PortDataChange".to_string(),
        ALARM_TYPE_SYNC_DATA_CHANGED => "SyncDataChanged".to_string(),
        ALARM_TYPE_ISOCHRONOUS_MODE_PROBLEM => "IsochronousModeProblem".to_string(),
        ALARM_TYPE_NETWORK_COMPONENT_PROBLEM => "NetworkComponentProblem".to_string(),
        ALARM_TYPE_TIME_DATA_CHANGED => "TimeDataChanged".to_string(),
        ALARM_TYPE_DFP_PROBLEM => "DynamicFramePackingProblem".to_string(),
        ALARM_TYPE_UPLOAD_RETRIEVAL => "UploadAndRetrieval".to_string(),
        ALARM_TYPE_PULL_MODULE => "PullModule".to_string(),
        _ => format!("Unknown(0x{alarm_type:04X})"),
    }
}

// ---------------------------------------------------------------------------
// User Structure Identifiers for alarm items (indices.py)
// ---------------------------------------------------------------------------

pub const USI_CHANNEL_DIAGNOSIS: u16 = 0x8000;
pub const USI_MULTIPLE_DIAGNOSIS: u16 = 0x8001;
pub const USI_EXT_CHANNEL_DIAGNOSIS: u16 = 0x8002;
pub const USI_QUALIFIED_CHANNEL_DIAGNOSIS: u16 = 0x8003;
pub const USI_MAINTENANCE: u16 = 0x8100;
pub const USI_UPLOAD: u16 = 0x8200;
pub const USI_IPARAMETER: u16 = 0x8201;
pub const USI_RS_ALARM_LOW: u16 = 0x8300;
pub const USI_RS_ALARM_HIGH: u16 = 0x8301;
pub const USI_RS_ALARM_SUBMODULE: u16 = 0x8302;
pub const USI_PE_ALARM: u16 = 0x8310;
pub const USI_PRAL_ALARM: u16 = 0x8320;

/// Human-readable name for a User Structure Identifier (`get_usi_name`).
pub fn get_usi_name(usi: u16) -> String {
    match usi {
        USI_CHANNEL_DIAGNOSIS => "ChannelDiagnosis".to_string(),
        USI_MULTIPLE_DIAGNOSIS => "MultipleDiagnosis".to_string(),
        USI_EXT_CHANNEL_DIAGNOSIS => "ExtChannelDiagnosis".to_string(),
        USI_QUALIFIED_CHANNEL_DIAGNOSIS => "QualifiedChannelDiagnosis".to_string(),
        USI_MAINTENANCE => "MaintenanceItem".to_string(),
        USI_UPLOAD => "UploadRecord".to_string(),
        USI_IPARAMETER => "iParameterItem".to_string(),
        USI_RS_ALARM_LOW => "RS_AlarmItem_Low".to_string(),
        USI_RS_ALARM_HIGH => "RS_AlarmItem_High".to_string(),
        USI_RS_ALARM_SUBMODULE => "RS_AlarmItem_Submodule".to_string(),
        USI_PE_ALARM => "PE_AlarmItem".to_string(),
        USI_PRAL_ALARM => "PRAL_AlarmItem".to_string(),
        0x0000..=0x7FFF => format!("ManufacturerSpecific(0x{usi:04X})"),
        0x9000..=0x9FFF => format!("ProfileSpecific(0x{usi:04X})"),
        _ => format!("Reserved(0x{usi:04X})"),
    }
}

// ---------------------------------------------------------------------------
// PROFIenergy operational modes (indices.py)
// ---------------------------------------------------------------------------

pub const PE_MODE_POWER_OFF: u8 = 0x00;
pub const PE_MODE_ENERGY_SAVING_MIN: u8 = 0x01;
pub const PE_MODE_ENERGY_SAVING_MAX: u8 = 0x1F;
pub const PE_MODE_OPERATE: u8 = 0xF0;
pub const PE_MODE_SLEEP_MODE_WOL: u8 = 0xFE;
pub const PE_MODE_READY_TO_OPERATE: u8 = 0xFF;

/// Human-readable name for a PROFIenergy mode (`get_pe_mode_name`).
pub fn get_pe_mode_name(mode: u8) -> String {
    match mode {
        PE_MODE_POWER_OFF => "PE_PowerOff".to_string(),
        PE_MODE_ENERGY_SAVING_MIN..=PE_MODE_ENERGY_SAVING_MAX => {
            format!("PE_EnergySavingMode_{mode}")
        }
        PE_MODE_OPERATE => "PE_Operate".to_string(),
        PE_MODE_SLEEP_MODE_WOL => "PE_SleepModeWOL".to_string(),
        PE_MODE_READY_TO_OPERATE => "PE_ReadyToOperate".to_string(),
        _ => format!("PE_Reserved(0x{mode:02X})"),
    }
}

// ---------------------------------------------------------------------------
// Alarm item types
// ---------------------------------------------------------------------------

/// Diagnosis alarm item, `DiagnosisItem` (USI 0x8000, 0x8002, 0x8003).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiagnosisItem {
    pub user_structure_id: u16,
    pub channel_number: u16,
    pub channel_properties: u16,
    pub channel_error_type: u16,
    pub ext_channel_error_type: u16,
    pub ext_channel_add_value: u32,
    pub qualified_channel_qualifier: u32,
}

impl DiagnosisItem {
    /// Actual channel number, bits 0-14 (`channel_number_value`).
    pub fn channel_number_value(&self) -> u16 {
        self.channel_number & 0x7FFF
    }

    /// Bit 15: accumulative, multiple errors on channel (`is_accumulative`).
    pub fn is_accumulative(&self) -> bool {
        self.channel_number & 0x8000 != 0
    }

    /// Channel type from properties bits 0-7 (`channel_type`).
    pub fn channel_type(&self) -> u16 {
        self.channel_properties & 0xFF
    }

    /// True for extended diagnosis, USI 0x8002 or 0x8003 (`is_extended`).
    pub fn is_extended(&self) -> bool {
        matches!(
            self.user_structure_id,
            USI_EXT_CHANNEL_DIAGNOSIS | USI_QUALIFIED_CHANNEL_DIAGNOSIS
        )
    }

    /// True for qualified diagnosis, USI 0x8003 (`is_qualified`).
    pub fn is_qualified(&self) -> bool {
        self.user_structure_id == USI_QUALIFIED_CHANNEL_DIAGNOSIS
    }
}

/// Maintenance alarm item, `MaintenanceItem` (USI 0x8100):
/// BlockHeader(6) + Padding(2) + MaintenanceStatus(4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MaintenanceItem {
    pub block_type: u16,
    pub block_length: u16,
    pub block_version: u16,
    pub maintenance_status: u32,
}

impl MaintenanceItem {
    /// Bit 0: maintenance required (`maintenance_required`).
    pub fn maintenance_required(&self) -> bool {
        self.maintenance_status & 0x01 != 0
    }

    /// Bit 1: maintenance demanded (`maintenance_demanded`).
    pub fn maintenance_demanded(&self) -> bool {
        self.maintenance_status & 0x02 != 0
    }
}

/// Upload/Retrieval alarm item, `UploadRetrievalItem` (USI 0x8200, 0x8201):
/// BlockHeader(6) + Padding(2) + URRecordIndex(4) + URRecordLength(4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UploadRetrievalItem {
    pub user_structure_id: u16,
    pub block_type: u16,
    pub block_length: u16,
    pub block_version: u16,
    pub ur_record_index: u32,
    pub ur_record_length: u32,
}

impl UploadRetrievalItem {
    /// True if this is an upload request (`is_upload`).
    pub fn is_upload(&self) -> bool {
        self.user_structure_id == USI_UPLOAD
    }

    /// True if this is a retrieval request (`is_retrieval`).
    pub fn is_retrieval(&self) -> bool {
        self.user_structure_id == USI_IPARAMETER
    }
}

/// iParameter alarm item, `iParameterItem` (USI 0x8201). Defined for parity
/// with the reference dataclass; like the reference, the alarm item parser
/// never produces it (USI 0x8201 dispatches to [`UploadRetrievalItem`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IParameterItem {
    pub block_type: u16,
    pub block_length: u16,
    pub block_version: u16,
    pub ipar_req_header: u32,
    pub max_segment_size: u32,
    pub transfer_index: u32,
    pub total_ipar_size: u32,
}

/// PROFIenergy alarm item, `PE_AlarmItem` (USI 0x8310):
/// BlockHeader(6) + PE_OperationalMode(1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeAlarmItem {
    pub block_type: u16,
    pub block_length: u16,
    pub block_version: u16,
    pub pe_operational_mode: u8,
}

impl PeAlarmItem {
    /// Human-readable mode name (`mode_name`).
    pub fn mode_name(&self) -> String {
        get_pe_mode_name(self.pe_operational_mode)
    }
}

/// Reporting System alarm item, `RS_AlarmItem` (USI 0x8300-0x8302):
/// RS_AlarmInfo(2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RsAlarmItem {
    pub user_structure_id: u16,
    pub rs_alarm_info: u16,
}

impl RsAlarmItem {
    /// RS Specifier from AlarmInfo bits 0-10 (`rs_specifier`).
    pub fn rs_specifier(&self) -> u16 {
        self.rs_alarm_info & 0x07FF
    }

    /// Sequence number, same as specifier for these items
    /// (`rs_sequence_number`).
    pub fn rs_sequence_number(&self) -> u16 {
        self.rs_specifier()
    }
}

/// Pull Request alarm item, `PRAL_AlarmItem` (USI 0x8320):
/// ChannelNumber(2) + PRAL_ChannelProperties(2) + PRAL_Reason(2) +
/// PRAL_ExtReason(2) + PRAL_ReasonAddValue(variable).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PralAlarmItem {
    pub channel_number: u16,
    pub pral_channel_properties: u16,
    pub pral_reason: u16,
    pub pral_ext_reason: u16,
    pub pral_reason_add_value: Vec<u8>,
}

/// One parsed alarm payload item (`AlarmItem` and its subclasses; the
/// reference models these as a dataclass hierarchy, the Rust port as an
/// enum). `Generic` covers unknown/manufacturer-specific USIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlarmItem {
    Diagnosis(DiagnosisItem),
    Maintenance(MaintenanceItem),
    UploadRetrieval(UploadRetrievalItem),
    Pe(PeAlarmItem),
    Rs(RsAlarmItem),
    Pral(PralAlarmItem),
    /// Unknown/manufacturer-specific USI: the raw remaining payload.
    Generic {
        user_structure_id: u16,
        raw_data: Vec<u8>,
    },
}

impl AlarmItem {
    /// The item's User Structure Identifier (`user_structure_id`).
    pub fn user_structure_id(&self) -> u16 {
        match self {
            AlarmItem::Diagnosis(i) => i.user_structure_id,
            AlarmItem::Maintenance(_) => USI_MAINTENANCE,
            AlarmItem::UploadRetrieval(i) => i.user_structure_id,
            AlarmItem::Pe(_) => USI_PE_ALARM,
            AlarmItem::Rs(i) => i.user_structure_id,
            AlarmItem::Pral(_) => USI_PRAL_ALARM,
            AlarmItem::Generic {
                user_structure_id, ..
            } => *user_structure_id,
        }
    }

    /// Human-readable USI name (`usi_name`).
    pub fn usi_name(&self) -> String {
        get_usi_name(self.user_structure_id())
    }
}

// ---------------------------------------------------------------------------
// Alarm notification
// ---------------------------------------------------------------------------

/// Complete parsed alarm notification (`AlarmNotification`): the PDU header
/// combined with the parsed alarm items.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlarmNotification {
    // From block header.
    pub block_type: u16,
    pub block_version: (u8, u8),

    // From PDU body.
    pub alarm_type: u16,
    pub api: u32,
    pub slot_number: u16,
    pub subslot_number: u16,
    pub module_ident_number: u32,
    pub submodule_ident_number: u32,

    // AlarmSpecifier bits.
    pub alarm_sequence_number: u16,
    pub channel_diagnosis: bool,
    pub manufacturer_specific: bool,
    pub submodule_diagnosis_state: bool,
    pub ar_diagnosis_state: bool,

    // Parsed alarm payload items.
    pub items: Vec<AlarmItem>,

    // Raw payload for debugging.
    pub raw_payload: Vec<u8>,
}

impl AlarmNotification {
    /// True if this is a high-priority alarm (`is_high_priority`).
    pub fn is_high_priority(&self) -> bool {
        self.block_type == BLOCK_ALARM_NOTIFICATION_HIGH
    }

    /// True if this is a low-priority alarm (`is_low_priority`).
    pub fn is_low_priority(&self) -> bool {
        self.block_type == BLOCK_ALARM_NOTIFICATION_LOW
    }

    /// Human-readable alarm type (`alarm_type_name`).
    pub fn alarm_type_name(&self) -> String {
        get_alarm_type_name(self.alarm_type)
    }

    /// Location string API:Slot:Subslot (`location`).
    pub fn location(&self) -> String {
        format!(
            "{}:{}:0x{:04X}",
            self.api, self.slot_number, self.subslot_number
        )
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

/// Parse a single alarm item at `offset` (`parse_alarm_item`), returning the
/// item and the new offset after it.
pub fn parse_alarm_item(data: &[u8], offset: usize) -> Result<(AlarmItem, usize), String> {
    if data.len() < offset + 2 {
        return Err("Insufficient data for USI".to_string());
    }
    let usi = u16_at(data, offset);
    let offset = offset + 2;

    match usi {
        USI_CHANNEL_DIAGNOSIS | USI_EXT_CHANNEL_DIAGNOSIS | USI_QUALIFIED_CHANNEL_DIAGNOSIS => {
            parse_diagnosis_item(data, offset, usi)
        }
        USI_MAINTENANCE => parse_maintenance_item(data, offset),
        USI_UPLOAD | USI_IPARAMETER => parse_upload_retrieval_item(data, offset, usi),
        USI_RS_ALARM_LOW | USI_RS_ALARM_HIGH | USI_RS_ALARM_SUBMODULE => {
            parse_rs_alarm_item(data, offset, usi)
        }
        USI_PE_ALARM => parse_pe_alarm_item(data, offset),
        USI_PRAL_ALARM => parse_pral_alarm_item(data, offset),
        // Unknown/manufacturer-specific: generic item with remaining data.
        _ => Ok((
            AlarmItem::Generic {
                user_structure_id: usi,
                raw_data: data[offset..].to_vec(),
            },
            data.len(),
        )),
    }
}

/// Parse a DiagnosisItem (`_parse_diagnosis_item`; USI 0x8000/0x8002/0x8003).
fn parse_diagnosis_item(
    data: &[u8],
    mut offset: usize,
    usi: u16,
) -> Result<(AlarmItem, usize), String> {
    // ChannelNumber(2) + ChannelProperties(2) + ChannelErrorType(2).
    if data.len() < offset + 6 {
        return Err("Truncated DiagnosisItem".to_string());
    }
    let mut item = DiagnosisItem {
        user_structure_id: usi,
        channel_number: u16_at(data, offset),
        channel_properties: u16_at(data, offset + 2),
        channel_error_type: u16_at(data, offset + 4),
        ..DiagnosisItem::default()
    };
    offset += 6;

    // Extended diagnosis: ExtChannelErrorType(2) + ExtChannelAddValue(4).
    if usi == USI_EXT_CHANNEL_DIAGNOSIS || usi == USI_QUALIFIED_CHANNEL_DIAGNOSIS {
        if data.len() < offset + 6 {
            return Err("Truncated ExtChannelDiagnosis".to_string());
        }
        item.ext_channel_error_type = u16_at(data, offset);
        item.ext_channel_add_value = u32_at(data, offset + 2);
        offset += 6;
    }

    // Qualified diagnosis: QualifiedChannelQualifier(4).
    if usi == USI_QUALIFIED_CHANNEL_DIAGNOSIS {
        if data.len() < offset + 4 {
            return Err("Truncated QualifiedChannelDiagnosis".to_string());
        }
        item.qualified_channel_qualifier = u32_at(data, offset);
        offset += 4;
    }

    Ok((AlarmItem::Diagnosis(item), offset))
}

/// Parse a MaintenanceItem (`_parse_maintenance_item`; USI 0x8100):
/// BlockHeader(6) + Padding(2) + MaintenanceStatus(4).
fn parse_maintenance_item(data: &[u8], mut offset: usize) -> Result<(AlarmItem, usize), String> {
    if data.len() < offset + 12 {
        return Err("Truncated MaintenanceItem".to_string());
    }
    let block_type = u16_at(data, offset);
    let block_length = u16_at(data, offset + 2);
    let block_version = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
    offset += 6;
    offset += 2; // Padding.
    let maintenance_status = u32_at(data, offset);
    offset += 4;

    Ok((
        AlarmItem::Maintenance(MaintenanceItem {
            block_type,
            block_length,
            block_version,
            maintenance_status,
        }),
        offset,
    ))
}

/// Parse an UploadRetrievalItem (`_parse_upload_retrieval_item`; USI
/// 0x8200/0x8201): BlockHeader(6) + Padding(2) + URRecordIndex(4) +
/// URRecordLength(4).
fn parse_upload_retrieval_item(
    data: &[u8],
    mut offset: usize,
    usi: u16,
) -> Result<(AlarmItem, usize), String> {
    if data.len() < offset + 16 {
        return Err("Truncated UploadRetrievalItem".to_string());
    }
    let block_type = u16_at(data, offset);
    let block_length = u16_at(data, offset + 2);
    let block_version = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
    offset += 6;
    offset += 2; // Padding.
    let ur_record_index = u32_at(data, offset);
    let ur_record_length = u32_at(data, offset + 4);
    offset += 8;

    Ok((
        AlarmItem::UploadRetrieval(UploadRetrievalItem {
            user_structure_id: usi,
            block_type,
            block_length,
            block_version,
            ur_record_index,
            ur_record_length,
        }),
        offset,
    ))
}

/// Parse a PE_AlarmItem (`_parse_pe_alarm_item`; USI 0x8310):
/// BlockHeader(6) + PE_OperationalMode(1).
fn parse_pe_alarm_item(data: &[u8], mut offset: usize) -> Result<(AlarmItem, usize), String> {
    if data.len() < offset + 7 {
        return Err("Truncated PE_AlarmItem".to_string());
    }
    let block_type = u16_at(data, offset);
    let block_length = u16_at(data, offset + 2);
    let block_version = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
    offset += 6;
    let pe_operational_mode = data[offset];
    offset += 1;

    Ok((
        AlarmItem::Pe(PeAlarmItem {
            block_type,
            block_length,
            block_version,
            pe_operational_mode,
        }),
        offset,
    ))
}

/// Parse an RS_AlarmItem (`_parse_rs_alarm_item`; USI 0x8300-0x8302):
/// RS_AlarmInfo(2).
fn parse_rs_alarm_item(
    data: &[u8],
    mut offset: usize,
    usi: u16,
) -> Result<(AlarmItem, usize), String> {
    if data.len() < offset + 2 {
        return Err("Truncated RS_AlarmItem".to_string());
    }
    let rs_alarm_info = u16_at(data, offset);
    offset += 2;

    Ok((
        AlarmItem::Rs(RsAlarmItem {
            user_structure_id: usi,
            rs_alarm_info,
        }),
        offset,
    ))
}

/// Parse a PRAL_AlarmItem (`_parse_pral_alarm_item`; USI 0x8320): consumes
/// the rest of the payload (the tail is PRAL_ReasonAddValue).
fn parse_pral_alarm_item(data: &[u8], offset: usize) -> Result<(AlarmItem, usize), String> {
    if data.len() < offset + 8 {
        return Err("Truncated PRAL_AlarmItem".to_string());
    }
    Ok((
        AlarmItem::Pral(PralAlarmItem {
            channel_number: u16_at(data, offset),
            pral_channel_properties: u16_at(data, offset + 2),
            pral_reason: u16_at(data, offset + 4),
            pral_ext_reason: u16_at(data, offset + 6),
            pral_reason_add_value: data[offset + 8..].to_vec(),
        }),
        data.len(),
    ))
}

/// Parse a complete AlarmNotification PDU (`parse_alarm_notification`).
pub fn parse_alarm_notification(data: &[u8]) -> Result<AlarmNotification, String> {
    // Minimum: BlockHeader(6) + Body(22).
    if data.len() < 28 {
        return Err("AlarmNotification too short".to_string());
    }

    // Block header.
    let block_type = u16_at(data, 0);
    let ver_high = data[4];
    let ver_low = data[5];

    // PDU body.
    let alarm_type = u16_at(data, 6);
    let api = u32_at(data, 8);
    let slot_number = u16_at(data, 12);
    let subslot_number = u16_at(data, 14);
    let module_ident = u32_at(data, 16);
    let submodule_ident = u32_at(data, 20);
    let alarm_specifier = u16_at(data, 24);
    let offset = 28;

    // AlarmSpecifier bits.
    let mut notification = AlarmNotification {
        block_type,
        block_version: (ver_high, ver_low),
        alarm_type,
        api,
        slot_number,
        subslot_number,
        module_ident_number: module_ident,
        submodule_ident_number: submodule_ident,
        alarm_sequence_number: alarm_specifier & 0x07FF,
        channel_diagnosis: alarm_specifier & 0x0800 != 0,
        manufacturer_specific: alarm_specifier & 0x1000 != 0,
        submodule_diagnosis_state: alarm_specifier & 0x2000 != 0,
        ar_diagnosis_state: alarm_specifier & 0x4000 != 0,
        items: Vec::new(),
        raw_payload: data[offset..].to_vec(),
    };

    // Alarm payload items; stop on the first parse error, keeping what we
    // have (the reference swallows the ValueError).
    let payload = &data[offset..];
    let mut item_offset = 0usize;
    while item_offset < payload.len() {
        match parse_alarm_item(payload, item_offset) {
            Ok((item, next)) => {
                notification.items.push(item);
                item_offset = next;
            }
            Err(_) => break,
        }
    }

    Ok(notification)
}

/// Scan a connect-response block list for AlarmCRBlockRes (0x8103) and
/// extract the device's local alarm reference (`_parse_alarm_cr_response`;
/// `None` where the reference returns -1).
pub fn parse_alarm_cr_res(response_data: &[u8]) -> Option<u16> {
    let mut offset = 0usize;
    while offset + 6 <= response_data.len() {
        let block_type = u16_at(response_data, offset);
        let block_length = u16_at(response_data, offset + 2);
        if block_type == BLOCK_ALARM_CR_RES {
            // The full PNAlarmCRBlockRes is 12 bytes: BlockHeader(6) +
            // AlarmCRType(2) + LocalAlarmReference(2) + MaxAlarmDataLength(2);
            // a truncated block is skipped like the reference's except-pass.
            if offset + 12 <= response_data.len() {
                return Some(u16_at(response_data, offset + 8));
            }
        }
        // Next block: block_length + 4 for the type/length words.
        offset += 4 + block_length as usize;
    }
    None
}
