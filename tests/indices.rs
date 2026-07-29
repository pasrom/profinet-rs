//! Ports of profinet-py tests/test_indices.py against the Rust `indices`
//! module. Python's name-lookup dicts (MODULE_STATE_NAMES, DIAGNOSIS_INDICES)
//! are Rust slices/functions: the state-name dicts become `[(u16, &str)]`
//! tables looked up by key, the per-scope DIAGNOSIS_INDICES dict becomes the
//! DIAGNOSIS_INDICES_{SUBSLOT,SLOT,AR,API,DEVICE} tables, and
//! ALL_STANDARD_INDICES is the `all_standard_indices()` function.

use profinet_rs::indices;

/// Look up a name in a `[(u16, &str)]` state table (Python dict indexing).
fn name_of(table: &[(u16, &'static str)], key: u16) -> &'static str {
    table
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, name)| *name)
        .unwrap_or_else(|| panic!("key 0x{key:04X} not in table"))
}

// --- TestGetBlockTypeName ----------------------------------------------------

#[test]
fn block_type_known() {
    assert_eq!(indices::get_block_type_name(0x0400), "MultipleBlockHeader");
    assert_eq!(indices::get_block_type_name(0x020F), "PDPortDataReal");
    assert_eq!(indices::get_block_type_name(0x0240), "PDInterfaceDataReal");
    assert_eq!(indices::get_block_type_name(0x0020), "I&M0");
    assert_eq!(indices::get_block_type_name(0x8104), "ModuleDiffBlock");
    assert_eq!(indices::get_block_type_name(0x0008), "IODWriteReqHeader");
    assert_eq!(indices::get_block_type_name(0x8008), "IODWriteResHeader");
    assert_eq!(indices::get_block_type_name(0x0101), "ARBlockReq");
    assert_eq!(indices::get_block_type_name(0x8101), "ARBlockRes");
}

#[test]
fn block_type_unknown() {
    let name = indices::get_block_type_name(0xFFFF);
    assert!(name.contains("Unknown"), "got {name}");
    assert!(name.contains("0xFFFF"), "got {name}");
}

#[test]
fn block_type_im() {
    for i in 0..16u16 {
        assert_eq!(indices::get_block_type_name(0x0020 + i), format!("I&M{i}"));
    }
}

// --- TestGetAlarmTypeName ----------------------------------------------------

#[test]
fn alarm_type_known() {
    assert_eq!(indices::get_alarm_type_name(0x0001), "Diagnosis");
    assert_eq!(indices::get_alarm_type_name(0x0002), "Process");
    assert_eq!(indices::get_alarm_type_name(0x0003), "Pull");
    assert_eq!(indices::get_alarm_type_name(0x0004), "Plug");
    assert_eq!(indices::get_alarm_type_name(0x0005), "Status");
    assert_eq!(indices::get_alarm_type_name(0x000A), "PlugWrongSubmodule");
    assert_eq!(indices::get_alarm_type_name(0x000C), "DiagnosisDisappears");
    assert_eq!(indices::get_alarm_type_name(0x001F), "PullModule");
}

#[test]
fn alarm_type_unknown() {
    let name = indices::get_alarm_type_name(0x0100);
    assert!(name.contains("Unknown"), "got {name}");
    assert!(name.contains("0x0100"), "got {name}");
}

// --- TestGetUSIName ----------------------------------------------------------

#[test]
fn usi_known() {
    assert_eq!(indices::get_usi_name(0x8000), "ChannelDiagnosis");
    assert_eq!(indices::get_usi_name(0x8001), "MultipleDiagnosis");
    assert_eq!(indices::get_usi_name(0x8002), "ExtChannelDiagnosis");
    assert_eq!(indices::get_usi_name(0x8003), "QualifiedChannelDiagnosis");
    assert_eq!(indices::get_usi_name(0x8100), "MaintenanceItem");
    assert_eq!(indices::get_usi_name(0x8310), "PE_AlarmItem");
}

#[test]
fn usi_manufacturer_specific() {
    assert!(indices::get_usi_name(0x0001).contains("ManufacturerSpecific"));
    assert!(indices::get_usi_name(0x7FFF).contains("ManufacturerSpecific"));
}

#[test]
fn usi_profile_specific() {
    assert!(indices::get_usi_name(0x9000).contains("ProfileSpecific"));
    assert!(indices::get_usi_name(0x9FFF).contains("ProfileSpecific"));
}

#[test]
fn usi_reserved() {
    assert!(indices::get_usi_name(0xA000).contains("Reserved"));
}

// --- TestGetIOCRTypeName -----------------------------------------------------

#[test]
fn iocr_type_known() {
    assert_eq!(indices::get_iocr_type_name(0x0001), "InputCR");
    assert_eq!(indices::get_iocr_type_name(0x0002), "OutputCR");
    assert_eq!(indices::get_iocr_type_name(0x0003), "MulticastProviderCR");
    assert_eq!(indices::get_iocr_type_name(0x0004), "MulticastConsumerCR");
}

#[test]
fn iocr_type_unknown() {
    assert!(indices::get_iocr_type_name(0x0010).contains("Unknown"));
}

// --- TestGetIOCRRTClassName --------------------------------------------------

#[test]
fn iocr_rt_class_known() {
    assert_eq!(indices::get_iocr_rt_class_name(0x01), "RT_CLASS_1");
    assert_eq!(indices::get_iocr_rt_class_name(0x02), "RT_CLASS_2");
    assert_eq!(indices::get_iocr_rt_class_name(0x03), "RT_CLASS_3");
    assert_eq!(indices::get_iocr_rt_class_name(0x04), "RT_CLASS_UDP");
}

#[test]
fn iocr_rt_class_unknown() {
    assert!(indices::get_iocr_rt_class_name(0xFF).contains("Unknown"));
}

// --- TestGetPEModeName -------------------------------------------------------

#[test]
fn pe_mode_power_off() {
    assert_eq!(indices::get_pe_mode_name(0x00), "PE_PowerOff");
}

#[test]
fn pe_mode_energy_saving_modes() {
    assert!(indices::get_pe_mode_name(0x01).contains("PE_EnergySavingMode"));
    assert!(indices::get_pe_mode_name(0x1F).contains("PE_EnergySavingMode"));
    assert!(indices::get_pe_mode_name(0x10).contains("PE_EnergySavingMode"));
}

#[test]
fn pe_mode_operate() {
    assert_eq!(indices::get_pe_mode_name(0xF0), "PE_Operate");
}

#[test]
fn pe_mode_sleep_mode_wol() {
    assert_eq!(indices::get_pe_mode_name(0xFE), "PE_SleepModeWOL");
}

#[test]
fn pe_mode_ready_to_operate() {
    assert_eq!(indices::get_pe_mode_name(0xFF), "PE_ReadyToOperate");
}

#[test]
fn pe_mode_reserved() {
    assert!(indices::get_pe_mode_name(0x20).contains("PE_Reserved"));
    assert!(indices::get_pe_mode_name(0xEF).contains("PE_Reserved"));
}

// --- TestGetIndexName --------------------------------------------------------

#[test]
fn index_name_im() {
    assert_eq!(indices::get_index_name(0xAFF0), "I&M0");
    assert_eq!(indices::get_index_name(0xAFF1), "I&M1");
    assert_eq!(indices::get_index_name(0xAFF5), "I&M5");
}

#[test]
fn index_name_im_range_fallback() {
    assert!(indices::get_index_name(0xAFF6).contains("I&M6"));
    assert!(indices::get_index_name(0xAFFF).contains("I&M15"));
}

#[test]
fn index_name_diagnosis() {
    assert!(indices::get_index_name(0x800A).contains("DiagnosisChannel"));
    assert!(indices::get_index_name(0x800B).contains("DiagnosisAll"));
    assert!(indices::get_index_name(0xF80C).contains("DeviceDiagnosis"));
}

#[test]
fn index_name_user_specific_range() {
    assert!(indices::get_index_name(0x0050).contains("User-specific"));
}

#[test]
fn index_name_subslot_data_range() {
    assert!(indices::get_index_name(0x8FFF).contains("Subslot data"));
}

#[test]
fn index_name_slot_data_range() {
    assert!(indices::get_index_name(0xC100).contains("Slot data"));
}

#[test]
fn index_name_ar_data_range() {
    assert!(indices::get_index_name(0xE100).contains("AR data"));
}

#[test]
fn index_name_api_data_range() {
    assert!(indices::get_index_name(0xF100).contains("API data"));
}

#[test]
fn index_name_device_data_range() {
    assert!(indices::get_index_name(0xF900).contains("Device data"));
}

#[test]
fn index_name_unknown_range() {
    assert!(indices::get_index_name(0xFC00).contains("Unknown"));
}

// --- TestGetScope ------------------------------------------------------------

#[test]
fn scope_user() {
    assert_eq!(indices::get_scope(0x0000), "user");
    assert_eq!(indices::get_scope(0x7FFF), "user");
}

#[test]
fn scope_subslot() {
    assert_eq!(indices::get_scope(0x8000), "subslot");
    assert_eq!(indices::get_scope(0x8FFF), "subslot");
}

#[test]
fn scope_slot() {
    assert_eq!(indices::get_scope(0xA000), "slot");
    assert_eq!(indices::get_scope(0xAFFF), "slot");
    assert_eq!(indices::get_scope(0xC000), "slot");
    assert_eq!(indices::get_scope(0xCFFF), "slot");
}

#[test]
fn scope_ar() {
    assert_eq!(indices::get_scope(0xE000), "ar");
    assert_eq!(indices::get_scope(0xEFFF), "ar");
}

#[test]
fn scope_api() {
    assert_eq!(indices::get_scope(0xF000), "api");
    assert_eq!(indices::get_scope(0xF7FF), "api");
}

#[test]
fn scope_device() {
    assert_eq!(indices::get_scope(0xF800), "device");
    assert_eq!(indices::get_scope(0xFBFF), "device");
}

#[test]
fn scope_unknown() {
    assert_eq!(indices::get_scope(0xFC00), "unknown");
    assert_eq!(indices::get_scope(0xFFFF), "unknown");
}

// --- TestModuleSubmoduleStateConstants ---------------------------------------

#[test]
fn module_state_values() {
    assert_eq!(indices::MODULE_STATE_NO_MODULE, 0x0000);
    assert_eq!(indices::MODULE_STATE_WRONG_MODULE, 0x0001);
    assert_eq!(indices::MODULE_STATE_PROPER_MODULE, 0x0002);
    assert_eq!(indices::MODULE_STATE_SUBSTITUTE_MODULE, 0x0003);
}

#[test]
fn submodule_state_values() {
    assert_eq!(indices::SUBMODULE_STATE_NO_SUBMODULE, 0x0000);
    assert_eq!(indices::SUBMODULE_STATE_WRONG_SUBMODULE, 0x0001);
    assert_eq!(indices::SUBMODULE_STATE_LOCKED_BY_SUPERVISOR, 0x0002);
    assert_eq!(indices::SUBMODULE_STATE_APPLICATION_READY_PENDING, 0x0004);
    assert_eq!(indices::SUBMODULE_STATE_OK, 0x0007);
}

#[test]
fn module_state_names() {
    assert_eq!(name_of(&indices::MODULE_STATE_NAMES, 0x0000), "NoModule");
    assert_eq!(
        name_of(&indices::MODULE_STATE_NAMES, 0x0002),
        "ProperModule"
    );
}

#[test]
fn submodule_state_names() {
    assert_eq!(name_of(&indices::SUBMODULE_STATE_NAMES, 0x0007), "OK");
    assert_eq!(
        name_of(&indices::SUBMODULE_STATE_NAMES, 0x0001),
        "WrongSubmodule"
    );
}

// --- TestIndexCategories -----------------------------------------------------

#[test]
fn critical_indices_not_empty() {
    assert!(!indices::CRITICAL_INDICES.is_empty());
    let im0 = indices::CRITICAL_INDICES
        .iter()
        .filter(|(idx, _)| *idx == 0xAFF0)
        .count();
    assert_eq!(im0, 1);
}

#[test]
fn im_indices_count() {
    assert_eq!(indices::IM_INDICES.len(), 16);
}

#[test]
fn diagnosis_indices_by_scope() {
    // Python's single DIAGNOSIS_INDICES dict keyed by scope is split into one
    // table per scope; each must be populated.
    assert!(!indices::DIAGNOSIS_INDICES_SUBSLOT.is_empty());
    assert!(!indices::DIAGNOSIS_INDICES_SLOT.is_empty());
    assert!(!indices::DIAGNOSIS_INDICES_AR.is_empty());
    assert!(!indices::DIAGNOSIS_INDICES_API.is_empty());
    assert!(!indices::DIAGNOSIS_INDICES_DEVICE.is_empty());
}

#[test]
fn all_standard_indices_not_empty() {
    assert!(indices::all_standard_indices().len() > 20);
}

#[test]
fn standard_dap_subslots() {
    assert_eq!(indices::SUBSLOT_DAP, 0x0001);
    assert_eq!(indices::SUBSLOT_INTERFACE, 0x8000);
    assert_eq!(indices::SUBSLOT_PORT1, 0x8001);
    assert_eq!(indices::SUBSLOT_PORT2, 0x8002);
}

// --- TestControlCommandConstants ---------------------------------------------

#[test]
fn control_command_values() {
    assert_eq!(indices::CONTROL_CMD_PRM_END, 0x0001);
    assert_eq!(indices::CONTROL_CMD_APPLICATION_READY, 0x0002);
    assert_eq!(indices::CONTROL_CMD_RELEASE, 0x0004);
    assert_eq!(indices::CONTROL_CMD_DONE, 0x0008);
    assert_eq!(indices::CONTROL_CMD_PRM_BEGIN, 0x0040);
}
