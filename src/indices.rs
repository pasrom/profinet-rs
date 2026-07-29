//! PROFINET IO Record Data Index definitions.
//!
//! Provides constants for all standardized PROFINET indices organized by
//! category. Index ranges determine addressing scope:
//! - 0x0000-0x7FFF: User/manufacturer specific
//! - 0x8000-0x8FFF: Subslot level
//! - 0xA000-0xAFFF: I&M data (slot level)
//! - 0xC000-0xCFFF: Slot level
//! - 0xE000-0xEFFF: AR (Application Relationship) level
//! - 0xF000-0xF7FF: API level
//! - 0xF800-0xFBFF: Device level
//!
//! Ported 1:1 from `profinet/indices.py`. This is the canonical constant set;
//! a few constants also exist in `im`/`transport` from earlier ports and are
//! intentionally left in place.

// =============================================================================
// Block Types (from Wireshark pn_io_block_type dissector)
// Used in block headers to identify block content
// =============================================================================

// Diagnosis blocks
pub const BLOCK_DIAGNOSIS_DATA: u16 = 0x0010;
pub const BLOCK_EXPECTED_IDENTIFICATION_DATA: u16 = 0x0012;
pub const BLOCK_REAL_IDENTIFICATION_DATA: u16 = 0x0013;

// I&M blocks
pub const BLOCK_IM0: u16 = 0x0020;
pub const BLOCK_IM1: u16 = 0x0021;
pub const BLOCK_IM2: u16 = 0x0022;
pub const BLOCK_IM3: u16 = 0x0023;
pub const BLOCK_IM4: u16 = 0x0024;
pub const BLOCK_IM5: u16 = 0x0025;
pub const BLOCK_IM6: u16 = 0x0026;
pub const BLOCK_IM7: u16 = 0x0027;
pub const BLOCK_IM8: u16 = 0x0028;
pub const BLOCK_IM9: u16 = 0x0029;
pub const BLOCK_IM10: u16 = 0x002A;
pub const BLOCK_IM11: u16 = 0x002B;
pub const BLOCK_IM12: u16 = 0x002C;
pub const BLOCK_IM13: u16 = 0x002D;
pub const BLOCK_IM14: u16 = 0x002E;
pub const BLOCK_IM15: u16 = 0x002F;

// Alarm blocks
pub const BLOCK_ALARM_NOTIFICATION_HIGH: u16 = 0x0001;
pub const BLOCK_ALARM_ACK_HIGH: u16 = 0x8001;
pub const BLOCK_ALARM_NOTIFICATION_LOW: u16 = 0x0002;
pub const BLOCK_ALARM_ACK_LOW: u16 = 0x8002;

// IOD Read/Write blocks
pub const BLOCK_IOD_WRITE_REQ: u16 = 0x0008;
pub const BLOCK_IOD_WRITE_RES: u16 = 0x8008;
pub const BLOCK_IOD_READ_REQ: u16 = 0x0009;
pub const BLOCK_IOD_READ_RES: u16 = 0x8009;

// AR data blocks
pub const BLOCK_AR_DATA: u16 = 0x0018;
pub const BLOCK_LOG_DATA: u16 = 0x0019;
pub const BLOCK_API_DATA: u16 = 0x001A;
pub const BLOCK_SRL_DATA: u16 = 0x001B;

// AR/IOCR/AlarmCR connection blocks
pub const BLOCK_AR_REQ: u16 = 0x0101;
pub const BLOCK_AR_RES: u16 = 0x8101;
pub const BLOCK_IOCR_REQ: u16 = 0x0102;
pub const BLOCK_IOCR_RES: u16 = 0x8102;
pub const BLOCK_ALARM_CR_REQ: u16 = 0x0103;
pub const BLOCK_ALARM_CR_RES: u16 = 0x8103;
pub const BLOCK_EXPECTED_SUBMODULE_REQ: u16 = 0x0104;
pub const BLOCK_MODULE_DIFF_BLOCK: u16 = 0x8104;

// Control operation blocks
pub const BLOCK_IOD_CONTROL_PRM_END_REQ: u16 = 0x0110;
pub const BLOCK_IOD_CONTROL_PRM_END_RES: u16 = 0x8110;
pub const BLOCK_IOD_CONTROL_APP_READY_REQ: u16 = 0x0112;
pub const BLOCK_IOD_CONTROL_APP_READY_RES: u16 = 0x8112;
pub const BLOCK_IOD_RELEASE_REQ: u16 = 0x0114;
pub const BLOCK_IOD_RELEASE_RES: u16 = 0x8114;
pub const BLOCK_IOD_CONTROL_RT_CLASS_3_REQ: u16 = 0x0117;
pub const BLOCK_IOD_CONTROL_RT_CLASS_3_RES: u16 = 0x8117;
pub const BLOCK_PRM_BEGIN_REQ: u16 = 0x0118;
pub const BLOCK_PRM_BEGIN_RES: u16 = 0x8118;
/// SubmoduleListBlock (appended to ApplicationReady)
pub const BLOCK_SUBMODULE_LIST: u16 = 0x0119;

// Control command values (bit field, each is BIT(n) per IEC 61158-6-10)
/// BIT(0): End parameter phase
pub const CONTROL_CMD_PRM_END: u16 = 0x0001;
/// BIT(1): Signal application ready
pub const CONTROL_CMD_APPLICATION_READY: u16 = 0x0002;
/// BIT(2): Release AR
pub const CONTROL_CMD_RELEASE: u16 = 0x0004;
/// BIT(3): Confirm/Done (used in CControl response)
pub const CONTROL_CMD_DONE: u16 = 0x0008;
/// BIT(4): Ready for companion AR
pub const CONTROL_CMD_READY_FOR_COMPANION: u16 = 0x0010;
/// BIT(5): Ready for isochronous mode
pub const CONTROL_CMD_READY_FOR_RT_CLASS_3: u16 = 0x0020;
/// BIT(6): Begin parameter phase
pub const CONTROL_CMD_PRM_BEGIN: u16 = 0x0040;

// Port and interface data blocks
pub const BLOCK_PD_PORT_DATA_CHECK: u16 = 0x0200;
pub const BLOCK_PD_PORT_DATA_ADJUST: u16 = 0x0202;
pub const BLOCK_PD_PORT_DATA_REAL: u16 = 0x020F;
pub const BLOCK_PD_INTERFACE_MRP_DATA_ADJUST: u16 = 0x0211;
pub const BLOCK_PD_INTERFACE_MRP_DATA_REAL: u16 = 0x0212;
pub const BLOCK_PD_PORT_MRP_DATA_REAL: u16 = 0x0215;
pub const BLOCK_MRP_RING_STATE_DATA: u16 = 0x0219;
pub const BLOCK_PD_PORT_FO_DATA_REAL: u16 = 0x0220;
pub const BLOCK_PD_PORT_FO_DATA_CHECK: u16 = 0x0221;
pub const BLOCK_PD_PORT_FO_DATA_ADJUST: u16 = 0x0222;
pub const BLOCK_PD_PORT_DATA_REAL_EXTENDED: u16 = 0x022C;
pub const BLOCK_PD_INTERFACE_DATA_REAL: u16 = 0x0240;
pub const BLOCK_PD_PORT_STATISTIC: u16 = 0x0251;

// Container blocks
pub const BLOCK_MULTIPLE_HEADER: u16 = 0x0400;
pub const BLOCK_CO_CONTAINER_CONTENT: u16 = 0x0401;

// Device-level blocks (0xF8xx)
pub const BLOCK_AR_SERVER_BLOCK: u16 = 0xF820;
pub const BLOCK_PD_REAL_DATA: u16 = 0xF841;
pub const BLOCK_PD_EXPECTED_DATA: u16 = 0xF842;

// API-level blocks (0xF0xx)
pub const BLOCK_REAL_IDENTIFICATION_DATA_API: u16 = 0xF000;

/// Block type name mapping for debugging/display.
pub static BLOCK_TYPE_NAMES: [(u16, &str); 69] = [
    (BLOCK_ALARM_NOTIFICATION_HIGH, "AlarmNotificationHigh"),
    (BLOCK_ALARM_ACK_HIGH, "AlarmAckHigh"),
    (BLOCK_ALARM_NOTIFICATION_LOW, "AlarmNotificationLow"),
    (BLOCK_ALARM_ACK_LOW, "AlarmAckLow"),
    (BLOCK_IOD_WRITE_REQ, "IODWriteReqHeader"),
    (BLOCK_IOD_WRITE_RES, "IODWriteResHeader"),
    (BLOCK_IOD_READ_REQ, "IODReadReqHeader"),
    (BLOCK_IOD_READ_RES, "IODReadResHeader"),
    (BLOCK_DIAGNOSIS_DATA, "DiagnosisData"),
    (
        BLOCK_EXPECTED_IDENTIFICATION_DATA,
        "ExpectedIdentificationData",
    ),
    (BLOCK_REAL_IDENTIFICATION_DATA, "RealIdentificationData"),
    (BLOCK_IM0, "I&M0"),
    (BLOCK_IM1, "I&M1"),
    (BLOCK_IM2, "I&M2"),
    (BLOCK_IM3, "I&M3"),
    (BLOCK_IM4, "I&M4"),
    (BLOCK_IM5, "I&M5"),
    (BLOCK_IM6, "I&M6"),
    (BLOCK_IM7, "I&M7"),
    (BLOCK_IM8, "I&M8"),
    (BLOCK_IM9, "I&M9"),
    (BLOCK_IM10, "I&M10"),
    (BLOCK_IM11, "I&M11"),
    (BLOCK_IM12, "I&M12"),
    (BLOCK_IM13, "I&M13"),
    (BLOCK_IM14, "I&M14"),
    (BLOCK_IM15, "I&M15"),
    (BLOCK_AR_REQ, "ARBlockReq"),
    (BLOCK_AR_RES, "ARBlockRes"),
    (BLOCK_IOCR_REQ, "IOCRBlockReq"),
    (BLOCK_IOCR_RES, "IOCRBlockRes"),
    (BLOCK_ALARM_CR_REQ, "AlarmCRBlockReq"),
    (BLOCK_ALARM_CR_RES, "AlarmCRBlockRes"),
    (BLOCK_EXPECTED_SUBMODULE_REQ, "ExpectedSubmoduleBlockReq"),
    (BLOCK_MODULE_DIFF_BLOCK, "ModuleDiffBlock"),
    (BLOCK_IOD_CONTROL_PRM_END_REQ, "IODControlReqPrmEnd"),
    (BLOCK_IOD_CONTROL_PRM_END_RES, "IODControlResPrmEnd"),
    (BLOCK_IOD_CONTROL_APP_READY_REQ, "IODControlReqAppReady"),
    (BLOCK_IOD_CONTROL_APP_READY_RES, "IODControlResAppReady"),
    (BLOCK_IOD_RELEASE_REQ, "IODReleaseReq"),
    (BLOCK_IOD_RELEASE_RES, "IODReleaseRes"),
    (BLOCK_IOD_CONTROL_RT_CLASS_3_REQ, "IODControlReqRTClass3"),
    (BLOCK_IOD_CONTROL_RT_CLASS_3_RES, "IODControlResRTClass3"),
    (BLOCK_PRM_BEGIN_REQ, "PrmBeginReq"),
    (BLOCK_PRM_BEGIN_RES, "PrmBeginRes"),
    (BLOCK_SUBMODULE_LIST, "SubmoduleListBlock"),
    (BLOCK_AR_DATA, "ARData"),
    (BLOCK_LOG_DATA, "LogData"),
    (BLOCK_API_DATA, "APIData"),
    (BLOCK_SRL_DATA, "SRLData"),
    (BLOCK_PD_PORT_DATA_CHECK, "PDPortDataCheck"),
    (BLOCK_PD_PORT_DATA_ADJUST, "PDPortDataAdjust"),
    (BLOCK_PD_PORT_DATA_REAL, "PDPortDataReal"),
    (
        BLOCK_PD_INTERFACE_MRP_DATA_ADJUST,
        "PDInterfaceMrpDataAdjust",
    ),
    (BLOCK_PD_INTERFACE_MRP_DATA_REAL, "PDInterfaceMrpDataReal"),
    (BLOCK_PD_PORT_MRP_DATA_REAL, "PDPortMrpDataReal"),
    (BLOCK_MRP_RING_STATE_DATA, "MrpRingStateData"),
    (BLOCK_PD_PORT_FO_DATA_REAL, "PDPortFODataReal"),
    (BLOCK_PD_PORT_FO_DATA_CHECK, "PDPortFODataCheck"),
    (BLOCK_PD_PORT_FO_DATA_ADJUST, "PDPortFODataAdjust"),
    (BLOCK_PD_PORT_DATA_REAL_EXTENDED, "PDPortDataRealExtended"),
    (BLOCK_PD_INTERFACE_DATA_REAL, "PDInterfaceDataReal"),
    (BLOCK_PD_PORT_STATISTIC, "PDPortStatistic"),
    (BLOCK_MULTIPLE_HEADER, "MultipleBlockHeader"),
    (BLOCK_CO_CONTAINER_CONTENT, "COContainerContent"),
    (BLOCK_AR_SERVER_BLOCK, "ARServerBlock"),
    (BLOCK_PD_REAL_DATA, "PDRealData"),
    (BLOCK_PD_EXPECTED_DATA, "PDExpectedData"),
    (
        BLOCK_REAL_IDENTIFICATION_DATA_API,
        "RealIdentificationDataAPI",
    ),
];

/// Get human-readable name for a block type.
pub fn get_block_type_name(block_type: u16) -> String {
    match BLOCK_TYPE_NAMES.iter().find(|&&(t, _)| t == block_type) {
        Some(&(_, name)) => name.to_string(),
        None => format!("Unknown(0x{block_type:04X})"),
    }
}

// =============================================================================
// Alarm Types (used in AlarmNotification blocks)
// =============================================================================

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

pub static ALARM_TYPE_NAMES: [(u16, &str); 21] = [
    (ALARM_TYPE_DIAGNOSIS, "Diagnosis"),
    (ALARM_TYPE_PROCESS, "Process"),
    (ALARM_TYPE_PULL, "Pull"),
    (ALARM_TYPE_PLUG, "Plug"),
    (ALARM_TYPE_STATUS, "Status"),
    (ALARM_TYPE_UPDATE, "Update"),
    (ALARM_TYPE_REDUNDANCY, "Redundancy"),
    (
        ALARM_TYPE_CONTROLLED_BY_SUPERVISOR,
        "ControlledBySupervisor",
    ),
    (ALARM_TYPE_RELEASED, "Released"),
    (ALARM_TYPE_PLUG_WRONG_SUBMODULE, "PlugWrongSubmodule"),
    (ALARM_TYPE_RETURN_OF_SUBMODULE, "ReturnOfSubmodule"),
    (ALARM_TYPE_DIAGNOSIS_DISAPPEARS, "DiagnosisDisappears"),
    (ALARM_TYPE_MULTICAST_MISMATCH, "MulticastMismatch"),
    (ALARM_TYPE_PORT_DATA_CHANGE, "PortDataChange"),
    (ALARM_TYPE_SYNC_DATA_CHANGED, "SyncDataChanged"),
    (
        ALARM_TYPE_ISOCHRONOUS_MODE_PROBLEM,
        "IsochronousModeProblem",
    ),
    (
        ALARM_TYPE_NETWORK_COMPONENT_PROBLEM,
        "NetworkComponentProblem",
    ),
    (ALARM_TYPE_TIME_DATA_CHANGED, "TimeDataChanged"),
    (ALARM_TYPE_DFP_PROBLEM, "DynamicFramePackingProblem"),
    (ALARM_TYPE_UPLOAD_RETRIEVAL, "UploadAndRetrieval"),
    (ALARM_TYPE_PULL_MODULE, "PullModule"),
];

/// Get human-readable name for an alarm type.
pub fn get_alarm_type_name(alarm_type: u16) -> String {
    match ALARM_TYPE_NAMES.iter().find(|&&(t, _)| t == alarm_type) {
        Some(&(_, name)) => name.to_string(),
        None => format!("Unknown(0x{alarm_type:04X})"),
    }
}

// =============================================================================
// IOCR (IO Connection Relationship) Types and Properties
// =============================================================================

// IOCR Types - used in IOCRBlockReq/Res
/// InputCR - receive data from device
pub const IOCR_TYPE_INPUT: u16 = 0x0001;
/// OutputCR - send data to device
pub const IOCR_TYPE_OUTPUT: u16 = 0x0002;
/// Multicast provider CR
pub const IOCR_TYPE_MULTICAST_PROVIDER: u16 = 0x0003;
/// Multicast consumer CR
pub const IOCR_TYPE_MULTICAST_CONSUMER: u16 = 0x0004;

pub static IOCR_TYPE_NAMES: [(u16, &str); 4] = [
    (IOCR_TYPE_INPUT, "InputCR"),
    (IOCR_TYPE_OUTPUT, "OutputCR"),
    (IOCR_TYPE_MULTICAST_PROVIDER, "MulticastProviderCR"),
    (IOCR_TYPE_MULTICAST_CONSUMER, "MulticastConsumerCR"),
];

// IOCR RT Classes (bits 0-3 of IOCRProperties)
/// RT_CLASS_1 (non-IRT, software scheduling)
pub const IOCR_RT_CLASS_1: u8 = 0x01;
/// RT_CLASS_2 (reserved)
pub const IOCR_RT_CLASS_2: u8 = 0x02;
/// RT_CLASS_3 (IRT, hardware scheduling)
pub const IOCR_RT_CLASS_3: u8 = 0x03;
/// RT_CLASS_UDP (UDP-based RT)
pub const IOCR_RT_CLASS_UDP: u8 = 0x04;

pub static IOCR_RT_CLASS_NAMES: [(u8, &str); 4] = [
    (IOCR_RT_CLASS_1, "RT_CLASS_1"),
    (IOCR_RT_CLASS_2, "RT_CLASS_2"),
    (IOCR_RT_CLASS_3, "RT_CLASS_3"),
    (IOCR_RT_CLASS_UDP, "RT_CLASS_UDP"),
];

/// Get human-readable name for an IOCR type.
pub fn get_iocr_type_name(iocr_type: u16) -> String {
    match IOCR_TYPE_NAMES.iter().find(|&&(t, _)| t == iocr_type) {
        Some(&(_, name)) => name.to_string(),
        None => format!("Unknown(0x{iocr_type:04X})"),
    }
}

/// Get human-readable name for an IOCR RT class.
pub fn get_iocr_rt_class_name(rt_class: u8) -> String {
    match IOCR_RT_CLASS_NAMES.iter().find(|&&(c, _)| c == rt_class) {
        Some(&(_, name)) => name.to_string(),
        None => format!("Unknown(0x{rt_class:02X})"),
    }
}

// =============================================================================
// AlarmCR (Alarm Connection Relationship) Types
// =============================================================================

/// Standard alarm CR
pub const ALARM_CR_TYPE_ALARM: u16 = 0x0001;

pub static ALARM_CR_TYPE_NAMES: [(u16, &str); 1] = [(ALARM_CR_TYPE_ALARM, "AlarmCR")];

// AlarmCR Transport (bit 1 of AlarmCRProperties)
/// RT-Acyclic Class 1 (Layer 2)
pub const ALARM_TRANSPORT_RTA_CLASS_1: u8 = 0x00;
/// RT-Acyclic over UDP
pub const ALARM_TRANSPORT_RTA_CLASS_UDP: u8 = 0x01;

pub static ALARM_TRANSPORT_NAMES: [(u8, &str); 2] = [
    (ALARM_TRANSPORT_RTA_CLASS_1, "RTA_CLASS_1"),
    (ALARM_TRANSPORT_RTA_CLASS_UDP, "RTA_CLASS_UDP"),
];

// =============================================================================
// AR (Application Relationship) Types
// =============================================================================

/// Standard single AR
pub const AR_TYPE_IOCAR_SINGLE: u16 = 0x0001;
/// Supervisor AR
pub const AR_TYPE_IOSAR: u16 = 0x0006;
/// Single AR with RT_CLASS_3
pub const AR_TYPE_IOCAR_SINGLE_RT_CLASS_3: u16 = 0x0010;
/// System redundancy AR
pub const AR_TYPE_IOCARSR: u16 = 0x0020;

pub static AR_TYPE_NAMES: [(u16, &str); 4] = [
    (AR_TYPE_IOCAR_SINGLE, "IOCARSingle"),
    (AR_TYPE_IOSAR, "IOSAR"),
    (AR_TYPE_IOCAR_SINGLE_RT_CLASS_3, "IOCARSingle_RT_CLASS_3"),
    (AR_TYPE_IOCARSR, "IOCARSR"),
];

// =============================================================================
// User Structure Identifiers (USI) for Alarm Items
// =============================================================================

/// ChannelDiagnosis
pub const USI_CHANNEL_DIAGNOSIS: u16 = 0x8000;
/// MultipleDiagnosis (list of ChannelDiagnosis)
pub const USI_MULTIPLE_DIAGNOSIS: u16 = 0x8001;
/// ExtChannelDiagnosis
pub const USI_EXT_CHANNEL_DIAGNOSIS: u16 = 0x8002;
/// QualifiedChannelDiagnosis
pub const USI_QUALIFIED_CHANNEL_DIAGNOSIS: u16 = 0x8003;
/// MaintenanceItem
pub const USI_MAINTENANCE: u16 = 0x8100;
/// UploadRecord
pub const USI_UPLOAD: u16 = 0x8200;
/// iParameterItem
pub const USI_IPARAMETER: u16 = 0x8201;
/// RS_AlarmItem (low priority)
pub const USI_RS_ALARM_LOW: u16 = 0x8300;
/// RS_AlarmItem (high priority)
pub const USI_RS_ALARM_HIGH: u16 = 0x8301;
/// RS_AlarmItem (submodule)
pub const USI_RS_ALARM_SUBMODULE: u16 = 0x8302;
/// PE_AlarmItem (PROFIenergy)
pub const USI_PE_ALARM: u16 = 0x8310;
/// PRAL_AlarmItem (Pull Request)
pub const USI_PRAL_ALARM: u16 = 0x8320;

pub static USI_NAMES: [(u16, &str); 12] = [
    (USI_CHANNEL_DIAGNOSIS, "ChannelDiagnosis"),
    (USI_MULTIPLE_DIAGNOSIS, "MultipleDiagnosis"),
    (USI_EXT_CHANNEL_DIAGNOSIS, "ExtChannelDiagnosis"),
    (USI_QUALIFIED_CHANNEL_DIAGNOSIS, "QualifiedChannelDiagnosis"),
    (USI_MAINTENANCE, "MaintenanceItem"),
    (USI_UPLOAD, "UploadRecord"),
    (USI_IPARAMETER, "iParameterItem"),
    (USI_RS_ALARM_LOW, "RS_AlarmItem_Low"),
    (USI_RS_ALARM_HIGH, "RS_AlarmItem_High"),
    (USI_RS_ALARM_SUBMODULE, "RS_AlarmItem_Submodule"),
    (USI_PE_ALARM, "PE_AlarmItem"),
    (USI_PRAL_ALARM, "PRAL_AlarmItem"),
];

/// Get human-readable name for a User Structure Identifier.
pub fn get_usi_name(usi: u16) -> String {
    if let Some(&(_, name)) = USI_NAMES.iter().find(|&&(u, _)| u == usi) {
        name.to_string()
    } else if usi <= 0x7FFF {
        format!("ManufacturerSpecific(0x{usi:04X})")
    } else if (0x9000..=0x9FFF).contains(&usi) {
        format!("ProfileSpecific(0x{usi:04X})")
    } else {
        format!("Reserved(0x{usi:04X})")
    }
}

// =============================================================================
// Module/Submodule State Values (for ModuleDiffBlock)
// =============================================================================

// Module states
pub const MODULE_STATE_NO_MODULE: u16 = 0x0000;
pub const MODULE_STATE_WRONG_MODULE: u16 = 0x0001;
pub const MODULE_STATE_PROPER_MODULE: u16 = 0x0002;
pub const MODULE_STATE_SUBSTITUTE_MODULE: u16 = 0x0003;

// Submodule states
pub const SUBMODULE_STATE_NO_SUBMODULE: u16 = 0x0000;
pub const SUBMODULE_STATE_WRONG_SUBMODULE: u16 = 0x0001;
pub const SUBMODULE_STATE_LOCKED_BY_SUPERVISOR: u16 = 0x0002;
pub const SUBMODULE_STATE_APPLICATION_READY_PENDING: u16 = 0x0004;
pub const SUBMODULE_STATE_OK: u16 = 0x0007;

pub static MODULE_STATE_NAMES: [(u16, &str); 4] = [
    (MODULE_STATE_NO_MODULE, "NoModule"),
    (MODULE_STATE_WRONG_MODULE, "WrongModule"),
    (MODULE_STATE_PROPER_MODULE, "ProperModule"),
    (MODULE_STATE_SUBSTITUTE_MODULE, "SubstituteModule"),
];

pub static SUBMODULE_STATE_NAMES: [(u16, &str); 5] = [
    (SUBMODULE_STATE_NO_SUBMODULE, "NoSubmodule"),
    (SUBMODULE_STATE_WRONG_SUBMODULE, "WrongSubmodule"),
    (SUBMODULE_STATE_LOCKED_BY_SUPERVISOR, "LockedBySupervisor"),
    (
        SUBMODULE_STATE_APPLICATION_READY_PENDING,
        "ApplicationReadyPending",
    ),
    (SUBMODULE_STATE_OK, "OK"),
];

// =============================================================================
// PROFIenergy Operational Modes
// =============================================================================

pub const PE_MODE_POWER_OFF: u8 = 0x00;
/// 0x01-0x1F are energy saving modes
pub const PE_MODE_ENERGY_SAVING_MIN: u8 = 0x01;
pub const PE_MODE_ENERGY_SAVING_MAX: u8 = 0x1F;
pub const PE_MODE_OPERATE: u8 = 0xF0;
pub const PE_MODE_SLEEP_MODE_WOL: u8 = 0xFE;
pub const PE_MODE_READY_TO_OPERATE: u8 = 0xFF;

/// Get human-readable name for a PROFIenergy mode.
pub fn get_pe_mode_name(mode: u8) -> String {
    if mode == PE_MODE_POWER_OFF {
        "PE_PowerOff".to_string()
    } else if (PE_MODE_ENERGY_SAVING_MIN..=PE_MODE_ENERGY_SAVING_MAX).contains(&mode) {
        format!("PE_EnergySavingMode_{mode}")
    } else if mode == PE_MODE_OPERATE {
        "PE_Operate".to_string()
    } else if mode == PE_MODE_SLEEP_MODE_WOL {
        "PE_SleepModeWOL".to_string()
    } else if mode == PE_MODE_READY_TO_OPERATE {
        "PE_ReadyToOperate".to_string()
    } else {
        format!("PE_Reserved(0x{mode:02X})")
    }
}

// =============================================================================
// I&M (Identification & Maintenance) Indices - 0xAFFx
// =============================================================================

/// Mandatory: VendorID, OrderID, SerialNumber, HW/SW revision
pub const IM0: u16 = 0xAFF0;
/// Tag_Function + Tag_Location
pub const IM1: u16 = 0xAFF1;
/// Installation_Date
pub const IM2: u16 = 0xAFF2;
/// Descriptor
pub const IM3: u16 = 0xAFF3;
/// Safety signature (PROFIsafe)
pub const IM4: u16 = 0xAFF4;
/// Annotation string
pub const IM5: u16 = 0xAFF5;
/// Reserved for future use
pub const IM6: u16 = 0xAFF6;
/// Reserved for future use
pub const IM7: u16 = 0xAFF7;
/// Reserved for future use
pub const IM8: u16 = 0xAFF8;
/// Reserved for future use
pub const IM9: u16 = 0xAFF9;
/// Reserved for future use
pub const IM10: u16 = 0xAFFA;
/// Reserved for future use
pub const IM11: u16 = 0xAFFB;
/// Reserved for future use
pub const IM12: u16 = 0xAFFC;
/// Reserved for future use
pub const IM13: u16 = 0xAFFD;
/// Reserved for future use
pub const IM14: u16 = 0xAFFE;
/// Reserved for future use
pub const IM15: u16 = 0xAFFF;
/// Lists all submodules with I&M data
pub const IM0_FILTER_DATA: u16 = 0xF840;

// =============================================================================
// Diagnosis Indices - Pattern: 0x__0A/B/C
// =============================================================================

// Subslot level (0x800x)
pub const DIAG_CHANNEL_SUBSLOT: u16 = 0x800A;
pub const DIAG_ALL_SUBSLOT: u16 = 0x800B;
pub const DIAG_MAINTENANCE_SUBSLOT: u16 = 0x800C;

// Slot level (0xC00x)
pub const DIAG_CHANNEL_SLOT: u16 = 0xC00A;
pub const DIAG_ALL_SLOT: u16 = 0xC00B;
pub const DIAG_MAINTENANCE_SLOT: u16 = 0xC00C;

// AR level (0xE00x)
pub const DIAG_CHANNEL_AR: u16 = 0xE00A;
pub const DIAG_ALL_AR: u16 = 0xE00B;
pub const DIAG_MAINTENANCE_AR: u16 = 0xE00C;

// API level (0xF00x)
pub const DIAG_CHANNEL_API: u16 = 0xF00A;
pub const DIAG_ALL_API: u16 = 0xF00B;
pub const DIAG_MAINTENANCE_API: u16 = 0xF00C;

// Device level
/// All diagnosis for entire device
pub const DIAG_DEVICE: u16 = 0xF80C;

// =============================================================================
// Maintenance Indices - Pattern: 0x__10-13
// =============================================================================

pub const MAINT_REQUIRED_CHANNEL_SUBSLOT: u16 = 0x8010;
pub const MAINT_DEMANDED_CHANNEL_SUBSLOT: u16 = 0x8011;
pub const MAINT_REQUIRED_ALL_SUBSLOT: u16 = 0x8012;
pub const MAINT_DEMANDED_ALL_SUBSLOT: u16 = 0x8013;

// =============================================================================
// Configuration/Identification Indices
// =============================================================================

// Subslot level
pub const EXPECTED_ID_SUBSLOT: u16 = 0x8000;
pub const REAL_ID_SUBSLOT: u16 = 0x8001;

// AR level
pub const EXPECTED_ID_AR: u16 = 0xE000;
pub const REAL_ID_AR: u16 = 0xE001;
/// Deviation between expected and real
pub const MODULE_DIFF_BLOCK: u16 = 0xE002;

// API level
pub const REAL_ID_API: u16 = 0xF000;

// Device level
pub const AR_DATA: u16 = 0xF820;
pub const API_DATA: u16 = 0xF821;
pub const PDEV_DATA: u16 = 0xF831;
pub const PD_REAL_DATA: u16 = 0xF841;
pub const PD_EXPECTED_DATA: u16 = 0xF842;
pub const AUTO_CONFIG: u16 = 0xF850;
pub const LOG_DATA: u16 = 0xF830;

// =============================================================================
// PDPort Indices (for port subslots 0x8001, 0x8002, etc.)
// =============================================================================

pub const PD_PORT_DATA_REAL: u16 = 0x802A;
pub const PD_PORT_DATA_CHECK: u16 = 0x802B;
pub const PD_IR_DATA: u16 = 0x802C;
pub const PD_SYNC_DATA: u16 = 0x802D;
pub const PD_PORT_DATA_ADJUST: u16 = 0x802F;
pub const PD_PORT_STATISTIC: u16 = 0x8072;

// =============================================================================
// PDInterface Indices (for interface subslot 0x8000)
// =============================================================================

pub const PD_NC_DATA_CHECK: u16 = 0x8070;
pub const PD_INTERFACE_ADJUST: u16 = 0x8071;
pub const PD_INTERFACE_DATA_REAL: u16 = 0x8080;
pub const PD_INTERFACE_FSU_ADJUST: u16 = 0x8090;

// =============================================================================
// Fiber Optic Indices
// =============================================================================

pub const PD_PORT_FO_DATA_REAL: u16 = 0x8060;
pub const PD_PORT_FO_DATA_CHECK: u16 = 0x8061;
pub const PD_PORT_FO_DATA_ADJUST: u16 = 0x8062;
pub const PD_PORT_SFP_DATA_CHECK: u16 = 0x8063;

// =============================================================================
// MRP (Media Redundancy Protocol) Indices
// =============================================================================

// Interface level (subslot 0x8000)
pub const PD_INTERFACE_MRP_DATA_REAL: u16 = 0x8050;
pub const PD_INTERFACE_MRP_DATA_CHECK: u16 = 0x8051;
pub const PD_INTERFACE_MRP_DATA_ADJUST: u16 = 0x8052;

// Port level
pub const PD_PORT_MRP_DATA_ADJUST: u16 = 0x8053;
pub const PD_PORT_MRP_DATA_REAL: u16 = 0x8054;
pub const PD_PORT_MRP_IC_DATA_ADJUST: u16 = 0x8055;
pub const PD_PORT_MRP_IC_DATA_CHECK: u16 = 0x8056;
pub const PD_PORT_MRP_IC_DATA_REAL: u16 = 0x8057;

// =============================================================================
// Sync/PTCP Indices
// =============================================================================

pub const PD_IR_SUBFRAME_DATA: u16 = 0x8020;
pub const ISOCHRONOUS_MODE_DATA: u16 = 0x8030;
pub const PD_TIME_DATA: u16 = 0x8031;

// =============================================================================
// I/O Data Indices
// =============================================================================

pub const SUBSTITUTE_VALUES: u16 = 0x801E;
pub const RECORD_INPUT_DATA: u16 = 0x8028;
pub const RECORD_OUTPUT_DATA: u16 = 0x8029;

// =============================================================================
// Asset Management Indices
// =============================================================================

pub const AM_DEVICE_ID: u16 = 0xF8E0;
pub const AM_FULL_INFO: u16 = 0xF8E1;
pub const AM_HW_ONLY: u16 = 0xF8E2;
pub const AM_FW_ONLY: u16 = 0xF8E3;
pub const AM_LOCATION_SLOT: u16 = 0xFBE0;
pub const AM_LOCATION_TREE: u16 = 0xFBE1;
pub const AM_DATA: u16 = 0xFBF0;

// =============================================================================
// PROFIsafe Indices
// =============================================================================

pub const F_PARAMETER_BLOCK: u16 = 0x0100;
pub const F_PRM_FLAG1: u16 = 0x0101;
pub const F_PRM_FLAG2: u16 = 0x0102;
pub const F_PARAMETER_WRITE: u16 = 0xE000;
pub const F_PARAMETER_READ: u16 = 0xE001;

// =============================================================================
// PROFIenergy Index
// =============================================================================

pub const PROFIENERGY: u16 = 0x80A0;

// =============================================================================
// AR-specific Indices
// =============================================================================

pub const WRITE_MULTIPLE: u16 = 0xE040;
pub const AR_FSU_DATA_ADJUST: u16 = 0xE050;

// =============================================================================
// Standard DAP Subslots
// =============================================================================

pub const SUBSLOT_DAP: u16 = 0x0001;
pub const SUBSLOT_INTERFACE: u16 = 0x8000;
pub const SUBSLOT_PORT1: u16 = 0x8001;
pub const SUBSLOT_PORT2: u16 = 0x8002;

// =============================================================================
// Index Categories for Enumeration
// =============================================================================

/// Critical indices that should always be tested.
pub static CRITICAL_INDICES: [(u16, &str); 7] = [
    (IM0, "I&M0 (mandatory)"),
    (IM0_FILTER_DATA, "I&M0FilterData"),
    (DIAG_DEVICE, "Device Diagnosis"),
    (MODULE_DIFF_BLOCK, "ModuleDiffBlock"),
    (PD_REAL_DATA, "PDRealData"),
    (AR_DATA, "ARData"),
    (LOG_DATA, "LogData"),
];

/// I&M indices.
pub static IM_INDICES: [(u16, &str); 16] = [
    (IM0, "I&M0"),
    (IM1, "I&M1"),
    (IM2, "I&M2"),
    (IM3, "I&M3"),
    (IM4, "I&M4"),
    (IM5, "I&M5"),
    (IM6, "I&M6"),
    (IM7, "I&M7"),
    (IM8, "I&M8"),
    (IM9, "I&M9"),
    (IM10, "I&M10"),
    (IM11, "I&M11"),
    (IM12, "I&M12"),
    (IM13, "I&M13"),
    (IM14, "I&M14"),
    (IM15, "I&M15"),
];

// Diagnosis indices by scope (DIAGNOSIS_INDICES dict in Python).
pub static DIAGNOSIS_INDICES_SUBSLOT: [(u16, &str); 3] = [
    (DIAG_CHANNEL_SUBSLOT, "DiagnosisChannel"),
    (DIAG_ALL_SUBSLOT, "DiagnosisAll"),
    (DIAG_MAINTENANCE_SUBSLOT, "DiagnosisMaintenance"),
];

pub static DIAGNOSIS_INDICES_SLOT: [(u16, &str); 3] = [
    (DIAG_CHANNEL_SLOT, "DiagnosisChannel"),
    (DIAG_ALL_SLOT, "DiagnosisAll"),
    (DIAG_MAINTENANCE_SLOT, "DiagnosisMaintenance"),
];

pub static DIAGNOSIS_INDICES_AR: [(u16, &str); 3] = [
    (DIAG_CHANNEL_AR, "DiagnosisChannel"),
    (DIAG_ALL_AR, "DiagnosisAll"),
    (DIAG_MAINTENANCE_AR, "DiagnosisMaintenance"),
];

pub static DIAGNOSIS_INDICES_API: [(u16, &str); 3] = [
    (DIAG_CHANNEL_API, "DiagnosisChannel"),
    (DIAG_ALL_API, "DiagnosisAll"),
    (DIAG_MAINTENANCE_API, "DiagnosisMaintenance"),
];

pub static DIAGNOSIS_INDICES_DEVICE: [(u16, &str); 1] = [(DIAG_DEVICE, "DeviceDiagnosis")];

/// Port-related indices.
pub static PORT_INDICES: [(u16, &str); 5] = [
    (PD_PORT_DATA_REAL, "PDPortDataReal"),
    (PD_PORT_DATA_CHECK, "PDPortDataCheck"),
    (PD_PORT_DATA_ADJUST, "PDPortDataAdjust"),
    (PD_PORT_STATISTIC, "PDPortStatistic"),
    (PD_PORT_MRP_DATA_REAL, "PDPortMrpDataReal"),
];

/// Interface-related indices.
pub static INTERFACE_INDICES: [(u16, &str); 3] = [
    (PD_INTERFACE_DATA_REAL, "PDInterfaceDataReal"),
    (PD_INTERFACE_MRP_DATA_REAL, "PDInterfaceMrpDataReal"),
    (PD_NC_DATA_CHECK, "PDNCDataCheck"),
];

/// Device-level indices.
pub static DEVICE_INDICES: [(u16, &str); 7] = [
    (AR_DATA, "ARData"),
    (API_DATA, "APIData"),
    (PDEV_DATA, "PDevData"),
    (PD_REAL_DATA, "PDRealData"),
    (PD_EXPECTED_DATA, "PDExpectedData"),
    (LOG_DATA, "LogData"),
    (AUTO_CONFIG, "AutoConfiguration"),
];

/// All standard indices for comprehensive enumeration.
///
/// Same composition and order as `ALL_STANDARD_INDICES` in indices.py:
/// IM + diagnosis(subslot) + diagnosis(device) + port + interface + device
/// + identification/IO extras.
pub fn all_standard_indices() -> Vec<(u16, &'static str)> {
    let mut v: Vec<(u16, &'static str)> = Vec::new();
    v.extend_from_slice(&IM_INDICES);
    v.extend_from_slice(&DIAGNOSIS_INDICES_SUBSLOT);
    v.extend_from_slice(&DIAGNOSIS_INDICES_DEVICE);
    v.extend_from_slice(&PORT_INDICES);
    v.extend_from_slice(&INTERFACE_INDICES);
    v.extend_from_slice(&DEVICE_INDICES);
    v.extend_from_slice(&[
        (EXPECTED_ID_SUBSLOT, "ExpectedIdentificationData"),
        (REAL_ID_SUBSLOT, "RealIdentificationData"),
        (MODULE_DIFF_BLOCK, "ModuleDiffBlock"),
        (SUBSTITUTE_VALUES, "SubstituteValues"),
        (RECORD_INPUT_DATA, "RecordInputData"),
        (RECORD_OUTPUT_DATA, "RecordOutputData"),
    ]);
    v
}

/// Get human-readable name for an index.
pub fn get_index_name(index: u16) -> String {
    for (idx, name) in all_standard_indices() {
        if idx == index {
            return name.to_string();
        }
    }

    // Check range for category
    if index <= 0x7FFF {
        format!("User-specific (0x{index:04X})")
    } else if (0xAFF0..=0xAFFF).contains(&index) {
        format!("I&M{}", index - 0xAFF0)
    } else if (0x8000..=0x8FFF).contains(&index) {
        format!("Subslot data (0x{index:04X})")
    } else if (0xC000..=0xCFFF).contains(&index) {
        format!("Slot data (0x{index:04X})")
    } else if (0xE000..=0xEFFF).contains(&index) {
        format!("AR data (0x{index:04X})")
    } else if (0xF000..=0xF7FF).contains(&index) {
        format!("API data (0x{index:04X})")
    } else if (0xF800..=0xFBFF).contains(&index) {
        format!("Device data (0x{index:04X})")
    } else {
        format!("Unknown (0x{index:04X})")
    }
}

/// Get the addressing scope for an index.
pub fn get_scope(index: u16) -> &'static str {
    if index <= 0x7FFF {
        "user"
    } else if (0x8000..=0x8FFF).contains(&index) {
        "subslot"
    } else if (0xA000..=0xAFFF).contains(&index) || (0xC000..=0xCFFF).contains(&index) {
        "slot"
    } else if (0xE000..=0xEFFF).contains(&index) {
        "ar"
    } else if (0xF000..=0xF7FF).contains(&index) {
        "api"
    } else if (0xF800..=0xFBFF).contains(&index) {
        "device"
    } else {
        "unknown"
    }
}
