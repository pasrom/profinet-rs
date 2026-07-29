//! Structural golden tests for the GSDML parser: the Rust model extracted
//! from tests/data/demo.gsdml.xml must equal the dump produced from the Python
//! reference (tools/gen_gsdml_golden.py -> tests/golden/gsdml.json).

use profinet_rs::gsdml::{
    load_gsdml, parse_gsdml, parse_gsdml_str, DeviceSlot, GsdmlDevice, GsdmlModule, GsdmlSubmodule,
    IoSlot, ItemRef,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn fixture_path() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/demo.gsdml.xml").to_string()
}

fn golden() -> Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/gsdml.json"
    ))
    .expect("read golden file");
    serde_json::from_str(&raw).expect("parse golden file")
}

// --- JSON dump helpers mirroring tools/gen_gsdml_golden.py -------------------

fn dump_submodule(sub: &GsdmlSubmodule) -> Value {
    json!({
        "id": sub.id,
        "submodule_ident": sub.submodule_ident,
        "input_length": sub.input_length,
        "output_length": sub.output_length,
    })
}

fn dump_refs(refs: &[ItemRef]) -> Value {
    refs.iter()
        .map(|r| json!({"target": r.target, "fixed": r.fixed, "allowed": r.allowed}))
        .collect()
}

fn dump_device(device: &GsdmlDevice) -> Value {
    json!({
        "vendor_id": device.vendor_id,
        "device_id": device.device_id,
        "daps": device.daps.iter().map(|dap| json!({
            "id": dap.id,
            "module_ident": dap.module_ident,
            "submodules": dap.submodules.iter().map(dump_submodule).collect::<Value>(),
            "system_submodules": dap.system_submodules.iter().map(|s| json!({
                "subslot_number": s.subslot_number,
                "submodule_ident": s.submodule_ident,
            })).collect::<Value>(),
            "useable_modules": dump_refs(&dap.useable_modules),
        })).collect::<Value>(),
        "modules": device.modules.iter().map(|m| json!({
            "id": m.id,
            "module_ident": m.module_ident,
            "submodules": m.submodules.iter().map(dump_submodule).collect::<Value>(),
            "useable_submodules": dump_refs(&m.useable_submodules),
        })).collect::<Value>(),
        "submodule_catalog": device.submodule_catalog.iter().map(dump_submodule).collect::<Value>(),
    })
}

fn dump_io_slots(slots: &[IoSlot]) -> Value {
    slots
        .iter()
        .map(|s| {
            json!({
                "slot": s.slot,
                "subslot": s.subslot,
                "module_ident": s.module_ident,
                "submodule_ident": s.submodule_ident,
                "input_length": s.input_length,
                "output_length": s.output_length,
            })
        })
        .collect()
}

// --- structural golden tests -------------------------------------------------

#[test]
fn golden_device_model() {
    let device = load_gsdml(fixture_path()).expect("load demo GSDML");
    assert_eq!(dump_device(&device), golden()["device"]);
}

#[test]
fn golden_io_slots() {
    let device = load_gsdml(fixture_path()).expect("load demo GSDML");
    let slots = device
        .build_io_slots(None, None, None)
        .expect("build_io_slots");
    assert_eq!(dump_io_slots(&slots), golden()["io_slots"]);
}

#[test]
fn golden_io_slots_from_device() {
    let device = load_gsdml(fixture_path()).expect("load demo GSDML");
    // Same discovered-slot view the generator fed to the reference: the
    // device's real slots plus one ident pair unknown to the GSDML.
    let mut device_slots: Vec<DeviceSlot> = device
        .build_io_slots(None, None, None)
        .expect("build_io_slots")
        .iter()
        .map(|s| DeviceSlot {
            slot: s.slot,
            subslot: s.subslot,
            module_ident: s.module_ident,
            submodule_ident: s.submodule_ident,
        })
        .collect();
    device_slots.push(DeviceSlot {
        slot: 9,
        subslot: 1,
        module_ident: 0xDEAD,
        submodule_ident: 0xBEEF,
    });
    let slots = device
        .build_io_slots_from_device(&device_slots, None)
        .expect("build_io_slots_from_device");
    assert_eq!(dump_io_slots(&slots), golden()["io_slots_from_device"]);
}

// --- focused semantics tests -------------------------------------------------

#[test]
fn data_submodule_lengths_resolved_by_ident() {
    // Slots as a device reports them carry only idents, no lengths: the IO
    // widths have to come from the GSDML, matched by module/submodule ident
    // rather than by slot number. The demo device's I/O submodule is 40 bytes
    // in, 2 bytes out.
    let device = load_gsdml(fixture_path()).expect("load demo GSDML");
    let device_slots = [DeviceSlot {
        slot: 1,
        subslot: 1,
        module_ident: 0x0000_0010,
        submodule_ident: 0x0000_0011,
    }];
    let slots = device
        .build_io_slots_from_device(&device_slots, None)
        .expect("build_io_slots_from_device");
    assert_eq!(
        slots,
        vec![IoSlot {
            slot: 1,
            subslot: 1,
            module_ident: 0x0000_0010,
            submodule_ident: 0x0000_0011,
            input_length: 47,
            output_length: 2,
        }]
    );
}

#[test]
fn device_identity() {
    let device = load_gsdml(fixture_path()).expect("load demo GSDML");
    assert_eq!(device.vendor_id, 0x0ABC);
    assert_eq!(device.device_id, 0x0007);
}

// --- error cases -------------------------------------------------------------

#[test]
fn missing_file_is_error() {
    let err = load_gsdml("/nonexistent/nope.gsdml.xml").unwrap_err();
    assert!(err.contains("cannot read"), "unexpected error: {err}");
}

#[test]
fn malformed_xml_is_error() {
    let dir = std::env::temp_dir().join("profinet-rs-gsdml-test");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("malformed.xml");
    std::fs::write(&path, "<ISO15745Profile><unclosed>").expect("write temp file");
    let err = load_gsdml(&path).unwrap_err();
    assert!(
        err.contains("malformed GSDML XML"),
        "unexpected error: {err}"
    );
}

#[test]
fn no_dap_is_error() {
    let device =
        profinet_rs::gsdml::parse_gsdml_str("<ISO15745Profile></ISO15745Profile>").expect("parse");
    let err = device.build_io_slots(None, None, None).unwrap_err();
    assert_eq!(err, "No DAP found in GSDML");
    let err = device.get_dap(Some("DAP 2")).unwrap_err();
    assert_eq!(err, "No DAP found in GSDML");
}

// ---------------------------------------------------------------------------
// Ports of profinet-py tests/test_gsdml.py. The Python tests drive the parser
// with small synthetic GSDML fixtures and the private _parse_io_data_size /
// _parse_slot_spec helpers; the Rust equivalents are exercised through the
// public parse_gsdml_str path (the io-data size and slot-spec parsing live
// inside it). Python's dict-shaped models (dap.useable_modules, dev.modules,
// dap.fixed_slots) map to Rust's Vec<ItemRef> / Vec<GsdmlModule> looked up by
// id/target.
// ---------------------------------------------------------------------------

const MINIMAL_GSDML: &str = r#"
<ISO15745Profile>
  <ProfileBody>
    <DeviceIdentity VendorID="0x002A" DeviceID="0x0003"/>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP_1" ModuleIdentNumber="0x00000001">
          <SystemDefinedSubmoduleList>
            <InterfaceSubmoduleItem SubslotNumber="0x8000"
                                    SubmoduleIdentNumber="0x00000100"/>
            <PortSubmoduleItem SubslotNumber="0x8001"
                               SubmoduleIdentNumber="0x00000200"/>
          </SystemDefinedSubmoduleList>
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="DAP_Sub" SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Input>
                  <DataItem DataType="Unsigned8"/>
                </Input>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
          <UseableModules>
            <ModuleItemRef ModuleItemTarget="MOD_INPUT"
                           AllowedInSlots="1..3" FixedInSlots="1"/>
            <ModuleItemRef ModuleItemTarget="MOD_OUTPUT"
                           AllowedInSlots="1..3" FixedInSlots="2"/>
          </UseableModules>
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList>
        <ModuleItem ID="MOD_INPUT" ModuleIdentNumber="0x00000010">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="MOD_IN_Sub"
                                  SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Input>
                  <DataItem DataType="OctetString" Length="4"/>
                </Input>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
        <ModuleItem ID="MOD_OUTPUT" ModuleIdentNumber="0x00000020">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="MOD_OUT_Sub"
                                  SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Output>
                  <DataItem DataType="Unsigned16"/>
                </Output>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
      </ModuleList>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"#;

const NAMESPACED_GSDML: &str = r#"
<ISO15745Profile xmlns="http://www.profibus.com/GSDML/2.4">
  <ProfileBody>
    <DeviceIdentity VendorID="0x0042" DeviceID="0x0007"/>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP_NS" ModuleIdentNumber="0x00000002">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="Sub1" SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Input>
                  <DataItem DataType="Unsigned32"/>
                </Input>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList>
        <ModuleItem ID="MOD_A" ModuleIdentNumber="0x000000AA">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="MOD_A_Sub" SubmoduleIdentNumber="0x00000001">
              <IOData>
                <Output>
                  <DataItem DataType="Float32"/>
                </Output>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
      </ModuleList>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"#;

const GSDML_WITH_SUBMODULE_LIST: &str = r#"
<ISO15745Profile>
  <ProfileBody>
    <DeviceIdentity VendorID="0x02B8" DeviceID="0x07A3"/>
    <ApplicationProcess>
      <DeviceAccessPointList>
        <DeviceAccessPointItem ID="DAP_1" ModuleIdentNumber="0x00003011">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="DAP" SubmoduleIdentNumber="0x00003010">
              <IOData/>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
          <UseableModules>
            <ModuleItemRef ModuleItemTarget="IDM_DEV" FixedInSlots="1"/>
            <ModuleItemRef ModuleItemTarget="IDM_PWR" FixedInSlots="2"/>
          </UseableModules>
        </DeviceAccessPointItem>
      </DeviceAccessPointList>
      <ModuleList>
        <ModuleItem ID="IDM_DEV" ModuleIdentNumber="0x10000000">
          <VirtualSubmoduleList>
            <VirtualSubmoduleItem ID="DEV_S" SubmoduleIdentNumber="0x20000000">
              <IOData>
                <Input><DataItem DataType="Integer16"/></Input>
                <Output><DataItem DataType="Unsigned16"/></Output>
              </IOData>
            </VirtualSubmoduleItem>
          </VirtualSubmoduleList>
        </ModuleItem>
        <ModuleItem ID="IDM_PWR" ModuleIdentNumber="0x1000032A">
          <UseableSubmodules>
            <SubmoduleItemRef SubmoduleItemTarget="IDS_TOTAL"
                              AllowedInSubslots="1" FixedInSubslots="1"/>
            <SubmoduleItemRef SubmoduleItemTarget="IDS_4CH"
                              AllowedInSubslots="2"/>
            <SubmoduleItemRef SubmoduleItemTarget="IDS_8CH"
                              AllowedInSubslots="2"/>
          </UseableSubmodules>
        </ModuleItem>
      </ModuleList>
      <SubmoduleList>
        <SubmoduleItem ID="IDS_TOTAL" SubmoduleIdentNumber="0x00000001">
          <IOData>
            <Input><DataItem DataType="Unsigned16"/></Input>
          </IOData>
        </SubmoduleItem>
        <SubmoduleItem ID="IDS_4CH" SubmoduleIdentNumber="0x00000114">
          <IOData>
            <Input><DataItem DataType="OctetString" Length="40"/></Input>
            <Output><DataItem DataType="OctetString" Length="8"/></Output>
          </IOData>
        </SubmoduleItem>
        <SubmoduleItem ID="IDS_8CH" SubmoduleIdentNumber="0x00000118">
          <IOData>
            <Input><DataItem DataType="OctetString" Length="80"/></Input>
            <Output><DataItem DataType="OctetString" Length="16"/></Output>
          </IOData>
        </SubmoduleItem>
      </SubmoduleList>
    </ApplicationProcess>
  </ProfileBody>
</ISO15745Profile>
"#;

fn device_from_xml(xml: &str) -> GsdmlDevice {
    parse_gsdml_str(xml).expect("parse gsdml")
}

fn find_module<'a>(dev: &'a GsdmlDevice, id: &str) -> &'a GsdmlModule {
    dev.modules
        .iter()
        .find(|m| m.id == id)
        .unwrap_or_else(|| panic!("module {id} not found"))
}

fn find_catalog<'a>(dev: &'a GsdmlDevice, id: &str) -> &'a GsdmlSubmodule {
    dev.submodule_catalog
        .iter()
        .find(|s| s.id == id)
        .unwrap_or_else(|| panic!("catalog submodule {id} not found"))
}

fn find_ref<'a>(refs: &'a [ItemRef], target: &str) -> &'a ItemRef {
    refs.iter()
        .find(|r| r.target == target)
        .unwrap_or_else(|| panic!("item ref {target} not found"))
}

/// Parse one VirtualSubmoduleItem carrying the given IOData snippet and return
/// the resulting submodule (drives the same code path as _parse_io_data_size,
/// which computes both input and output lengths).
fn sub_with_iodata(iodata: &str) -> GsdmlSubmodule {
    let xml = format!(
        "<ISO15745Profile><ProfileBody><ApplicationProcess>\
         <DeviceAccessPointList><DeviceAccessPointItem ID=\"DAP\" ModuleIdentNumber=\"0x1\">\
         <VirtualSubmoduleList><VirtualSubmoduleItem ID=\"S\" SubmoduleIdentNumber=\"0x1\">{iodata}\
         </VirtualSubmoduleItem></VirtualSubmoduleList>\
         </DeviceAccessPointItem></DeviceAccessPointList>\
         </ApplicationProcess></ProfileBody></ISO15745Profile>"
    );
    device_from_xml(&xml).daps[0].submodules[0].clone()
}

/// Parse a UseableModules ModuleItemRef with the given raw slot attribute and
/// return its resolved fixed-slot list (drives _parse_slot_spec).
fn fixed_of(attr: &str) -> Vec<u16> {
    let xml = format!(
        "<ISO15745Profile><ProfileBody><ApplicationProcess>\
         <DeviceAccessPointList><DeviceAccessPointItem ID=\"DAP\" ModuleIdentNumber=\"0x1\">\
         <UseableModules><ModuleItemRef ModuleItemTarget=\"M\" {attr}/></UseableModules>\
         </DeviceAccessPointItem></DeviceAccessPointList>\
         </ApplicationProcess></ProfileBody></ISO15745Profile>"
    );
    device_from_xml(&xml).daps[0].useable_modules[0]
        .fixed
        .clone()
}

// --- TestParseIODataSize -----------------------------------------------------

#[test]
fn io_size_unsigned8() {
    assert_eq!(
        sub_with_iodata("<IOData><Input><DataItem DataType=\"Unsigned8\"/></Input></IOData>")
            .input_length,
        1
    );
}

#[test]
fn io_size_unsigned16() {
    assert_eq!(
        sub_with_iodata("<IOData><Input><DataItem DataType=\"Unsigned16\"/></Input></IOData>")
            .input_length,
        2
    );
}

#[test]
fn io_size_unsigned32() {
    assert_eq!(
        sub_with_iodata("<IOData><Output><DataItem DataType=\"Unsigned32\"/></Output></IOData>")
            .output_length,
        4
    );
}

#[test]
fn io_size_float32() {
    assert_eq!(
        sub_with_iodata("<IOData><Input><DataItem DataType=\"Float32\"/></Input></IOData>")
            .input_length,
        4
    );
}

#[test]
fn io_size_float64() {
    assert_eq!(
        sub_with_iodata("<IOData><Input><DataItem DataType=\"Float64\"/></Input></IOData>")
            .input_length,
        8
    );
}

#[test]
fn io_size_integer16() {
    assert_eq!(
        sub_with_iodata("<IOData><Input><DataItem DataType=\"Integer16\"/></Input></IOData>")
            .input_length,
        2
    );
}

#[test]
fn io_size_octet_string_with_length() {
    assert_eq!(
        sub_with_iodata(
            "<IOData><Input><DataItem DataType=\"OctetString\" Length=\"10\"/></Input></IOData>"
        )
        .input_length,
        10
    );
}

#[test]
fn io_size_visible_string_with_length() {
    assert_eq!(
        sub_with_iodata(
            "<IOData><Output><DataItem DataType=\"VisibleString\" Length=\"32\"/></Output></IOData>"
        )
        .output_length,
        32
    );
}

#[test]
fn io_size_explicit_length_overrides_type() {
    // Length attribute is used even for fixed-size types.
    assert_eq!(
        sub_with_iodata(
            "<IOData><Input><DataItem DataType=\"Unsigned8\" Length=\"3\"/></Input></IOData>"
        )
        .input_length,
        3
    );
}

#[test]
fn io_size_multiple_data_items() {
    assert_eq!(
        sub_with_iodata(
            "<IOData><Input>\
             <DataItem DataType=\"Unsigned16\"/>\
             <DataItem DataType=\"Unsigned8\"/>\
             <DataItem DataType=\"OctetString\" Length=\"5\"/>\
             </Input></IOData>"
        )
        .input_length,
        2 + 1 + 5
    );
}

#[test]
fn io_size_missing_direction_returns_zero() {
    assert_eq!(
        sub_with_iodata("<IOData><Input><DataItem DataType=\"Unsigned8\"/></Input></IOData>")
            .output_length,
        0
    );
}

#[test]
fn io_size_no_io_data_returns_zero() {
    let sub = sub_with_iodata("");
    assert_eq!(sub.input_length, 0);
    assert_eq!(sub.output_length, 0);
}

#[test]
fn io_size_empty_direction_returns_zero() {
    assert_eq!(
        sub_with_iodata("<IOData><Input></Input></IOData>").input_length,
        0
    );
}

#[test]
fn io_size_unknown_type_no_length_ignored() {
    assert_eq!(
        sub_with_iodata("<IOData><Input><DataItem DataType=\"SomeCustomType\"/></Input></IOData>")
            .input_length,
        0
    );
}

#[test]
fn io_size_boolean() {
    assert_eq!(
        sub_with_iodata("<IOData><Input><DataItem DataType=\"Boolean\"/></Input></IOData>")
            .input_length,
        1
    );
}

#[test]
fn io_size_timestamp() {
    assert_eq!(
        sub_with_iodata("<IOData><Input><DataItem DataType=\"TimeStamp\"/></Input></IOData>")
            .input_length,
        8
    );
}

// --- TestLoadGsdml -----------------------------------------------------------

#[test]
fn load_vendor_and_device_id() {
    let dev = device_from_xml(MINIMAL_GSDML);
    assert_eq!(dev.vendor_id, 0x002A);
    assert_eq!(dev.device_id, 0x0003);
}

#[test]
fn load_dap_count() {
    assert_eq!(device_from_xml(MINIMAL_GSDML).daps.len(), 1);
}

#[test]
fn load_dap_id_and_module_ident() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let dap = &dev.daps[0];
    assert_eq!(dap.id, "DAP_1");
    assert_eq!(dap.module_ident, 0x0000_0001);
}

#[test]
fn load_dap_virtual_submodule() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let dap = &dev.daps[0];
    assert_eq!(dap.submodules.len(), 1);
    let sub = &dap.submodules[0];
    assert_eq!(sub.id, "DAP_Sub");
    assert_eq!(sub.submodule_ident, 0x0000_0001);
    assert_eq!(sub.input_length, 1); // Unsigned8
    assert_eq!(sub.output_length, 0);
}

#[test]
fn load_dap_system_submodules() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let dap = &dev.daps[0];
    assert_eq!(dap.system_submodules.len(), 2);
    assert_eq!(dap.system_submodules[0].subslot_number, 0x8000);
    assert_eq!(dap.system_submodules[0].submodule_ident, 0x0000_0100);
    assert_eq!(dap.system_submodules[1].subslot_number, 0x8001);
    assert_eq!(dap.system_submodules[1].submodule_ident, 0x0000_0200);
}

#[test]
fn load_useable_modules() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let refs = &dev.daps[0].useable_modules;
    assert!(refs.iter().any(|r| r.target == "MOD_INPUT"));
    assert!(refs.iter().any(|r| r.target == "MOD_OUTPUT"));
}

#[test]
fn load_fixed_slots() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let refs = &dev.daps[0].useable_modules;
    assert_eq!(find_ref(refs, "MOD_INPUT").fixed, vec![1]);
    assert_eq!(find_ref(refs, "MOD_OUTPUT").fixed, vec![2]);
}

#[test]
fn load_allowed_slots() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let refs = &dev.daps[0].useable_modules;
    assert_eq!(find_ref(refs, "MOD_INPUT").allowed, vec![1, 2, 3]);
    assert_eq!(find_ref(refs, "MOD_OUTPUT").allowed, vec![1, 2, 3]);
}

#[test]
fn load_module_count() {
    assert_eq!(device_from_xml(MINIMAL_GSDML).modules.len(), 2);
}

#[test]
fn load_module_input() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let m = find_module(&dev, "MOD_INPUT");
    assert_eq!(m.module_ident, 0x0000_0010);
    assert_eq!(m.submodules.len(), 1);
    assert_eq!(m.submodules[0].input_length, 4);
    assert_eq!(m.submodules[0].output_length, 0);
}

#[test]
fn load_module_output() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let m = find_module(&dev, "MOD_OUTPUT");
    assert_eq!(m.module_ident, 0x0000_0020);
    assert_eq!(m.submodules.len(), 1);
    assert_eq!(m.submodules[0].input_length, 0);
    assert_eq!(m.submodules[0].output_length, 2); // Unsigned16
}

#[test]
fn load_get_dap_default() {
    let dev = device_from_xml(MINIMAL_GSDML);
    assert_eq!(dev.get_dap(None).unwrap().id, "DAP_1");
}

#[test]
fn load_get_dap_by_id() {
    let dev = device_from_xml(MINIMAL_GSDML);
    assert_eq!(dev.get_dap(Some("DAP_1")).unwrap().id, "DAP_1");
}

#[test]
fn load_get_dap_not_found() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let err = dev.get_dap(Some("NONEXISTENT")).unwrap_err();
    assert!(err.contains("not found"), "unexpected error: {err}");
}

// --- TestBuildIOSlots --------------------------------------------------------

#[test]
fn build_fixed_in_slots_auto() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    // slot 0: DAP sub + interface + port; slot 1: MOD_INPUT; slot 2: MOD_OUTPUT
    assert_eq!(slots.len(), 5);
}

#[test]
fn build_dap_always_slot_zero() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    assert_eq!(slots.iter().filter(|s| s.slot == 0).count(), 3);
}

#[test]
fn build_dap_subslot_one() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    let dap_sub = slots
        .iter()
        .find(|s| s.slot == 0 && s.subslot == 1)
        .unwrap();
    assert_eq!(dap_sub.input_length, 1);
    assert_eq!(dap_sub.output_length, 0);
    assert_eq!(dap_sub.module_ident, 0x0000_0001);
}

#[test]
fn build_system_submodule_slots() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    let iface = slots.iter().find(|s| s.subslot == 0x8000).unwrap();
    assert_eq!(iface.slot, 0);
    assert_eq!(iface.module_ident, 0x0000_0001);
    assert_eq!(iface.submodule_ident, 0x0000_0100);
    let port = slots.iter().find(|s| s.subslot == 0x8001).unwrap();
    assert_eq!(port.slot, 0);
    assert_eq!(port.submodule_ident, 0x0000_0200);
}

#[test]
fn build_module_slot_1_input() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    let mod_in = slots.iter().find(|s| s.slot == 1).unwrap();
    assert_eq!(mod_in.subslot, 1);
    assert_eq!(mod_in.input_length, 4);
    assert_eq!(mod_in.output_length, 0);
    assert_eq!(mod_in.module_ident, 0x0000_0010);
}

#[test]
fn build_module_slot_2_output() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    let mod_out = slots.iter().find(|s| s.slot == 2).unwrap();
    assert_eq!(mod_out.subslot, 1);
    assert_eq!(mod_out.input_length, 0);
    assert_eq!(mod_out.output_length, 2);
    assert_eq!(mod_out.module_ident, 0x0000_0020);
}

#[test]
fn build_explicit_slot_assignment() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let mut assignment = BTreeMap::new();
    assignment.insert(3u16, "MOD_OUTPUT".to_string());
    assignment.insert(5u16, "MOD_INPUT".to_string());
    let slots = dev.build_io_slots(Some(&assignment), None, None).unwrap();
    let mod_slots: Vec<&IoSlot> = slots.iter().filter(|s| s.slot > 0).collect();
    assert_eq!(mod_slots.len(), 2);
    assert_eq!(mod_slots[0].slot, 3);
    assert_eq!(mod_slots[0].output_length, 2);
    assert_eq!(mod_slots[1].slot, 5);
    assert_eq!(mod_slots[1].input_length, 4);
}

#[test]
fn build_explicit_assignment_unknown_module_skipped() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let mut assignment = BTreeMap::new();
    assignment.insert(1u16, "NONEXISTENT".to_string());
    let slots = dev.build_io_slots(Some(&assignment), None, None).unwrap();
    assert!(slots.iter().all(|s| s.slot == 0));
}

#[test]
fn build_slot_order() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    let slot_nums: Vec<u16> = slots.iter().map(|s| s.slot).collect();
    assert_eq!(slot_nums, vec![0, 0, 0, 1, 2]);
}

// --- TestBuildIOSlotsFromDevice ----------------------------------------------

#[test]
fn from_device_matching_fills_io_sizes() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let device_slots = [
        DeviceSlot {
            slot: 0,
            subslot: 1,
            module_ident: 0x0000_0001,
            submodule_ident: 0x0000_0001,
        },
        DeviceSlot {
            slot: 1,
            subslot: 1,
            module_ident: 0x0000_0010,
            submodule_ident: 0x0000_0001,
        },
    ];
    let slots = dev.build_io_slots_from_device(&device_slots, None).unwrap();
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0].input_length, 1); // DAP Unsigned8
    assert_eq!(slots[1].input_length, 4); // MOD_INPUT OctetString(4)
}

#[test]
fn from_device_unknown_module_gets_zero() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let device_slots = [DeviceSlot {
        slot: 1,
        subslot: 1,
        module_ident: 0xDEAD_BEEF,
        submodule_ident: 0x0000_0001,
    }];
    let slots = dev.build_io_slots_from_device(&device_slots, None).unwrap();
    assert_eq!(slots[0].input_length, 0);
    assert_eq!(slots[0].output_length, 0);
}

#[test]
fn from_device_preserves_slot_subslot() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let device_slots = [DeviceSlot {
        slot: 7,
        subslot: 3,
        module_ident: 0x0000_0020,
        submodule_ident: 0x0000_0001,
    }];
    let slots = dev.build_io_slots_from_device(&device_slots, None).unwrap();
    assert_eq!(slots[0].slot, 7);
    assert_eq!(slots[0].subslot, 3);
    assert_eq!(slots[0].output_length, 2);
}

#[test]
fn from_device_system_submodule_matching() {
    let dev = device_from_xml(MINIMAL_GSDML);
    let device_slots = [DeviceSlot {
        slot: 0,
        subslot: 0x8000,
        module_ident: 0x0000_0001,
        submodule_ident: 0x0000_0100,
    }];
    let slots = dev.build_io_slots_from_device(&device_slots, None).unwrap();
    assert_eq!(slots[0].input_length, 0);
    assert_eq!(slots[0].output_length, 0);
}

#[test]
fn from_device_empty_device_slots() {
    let dev = device_from_xml(MINIMAL_GSDML);
    assert_eq!(dev.build_io_slots_from_device(&[], None).unwrap(), vec![]);
}

// --- TestNamespaceHandling ---------------------------------------------------

#[test]
fn ns_vendor_id() {
    assert_eq!(device_from_xml(NAMESPACED_GSDML).vendor_id, 0x0042);
}

#[test]
fn ns_device_id() {
    assert_eq!(device_from_xml(NAMESPACED_GSDML).device_id, 0x0007);
}

#[test]
fn ns_dap_parsed() {
    let dev = device_from_xml(NAMESPACED_GSDML);
    assert_eq!(dev.daps.len(), 1);
    assert_eq!(dev.daps[0].id, "DAP_NS");
    assert_eq!(dev.daps[0].module_ident, 0x0000_0002);
}

#[test]
fn ns_submodule_io() {
    let dev = device_from_xml(NAMESPACED_GSDML);
    assert_eq!(dev.daps[0].submodules[0].input_length, 4); // Unsigned32
}

#[test]
fn ns_module() {
    let dev = device_from_xml(NAMESPACED_GSDML);
    let m = find_module(&dev, "MOD_A");
    assert_eq!(m.module_ident, 0x0000_00AA);
    assert_eq!(m.submodules[0].output_length, 4); // Float32
}

#[test]
fn ns_different_version() {
    let xml = NAMESPACED_GSDML.replace("GSDML/2.4", "GSDML/2.3");
    let dev = device_from_xml(&xml);
    assert_eq!(dev.vendor_id, 0x0042);
    assert_eq!(dev.daps.len(), 1);
}

// --- TestEdgeCases -----------------------------------------------------------

#[test]
fn edge_no_io_data_module() {
    let xml = r#"
<ISO15745Profile><ProfileBody><ApplicationProcess>
  <DeviceAccessPointList>
    <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001"></DeviceAccessPointItem>
  </DeviceAccessPointList>
  <ModuleList>
    <ModuleItem ID="NO_IO" ModuleIdentNumber="0x00000099">
      <VirtualSubmoduleList>
        <VirtualSubmoduleItem ID="S1" SubmoduleIdentNumber="0x00000001"></VirtualSubmoduleItem>
      </VirtualSubmoduleList>
    </ModuleItem>
  </ModuleList>
</ApplicationProcess></ProfileBody></ISO15745Profile>"#;
    let dev = device_from_xml(xml);
    let m = find_module(&dev, "NO_IO");
    assert_eq!(m.submodules[0].input_length, 0);
    assert_eq!(m.submodules[0].output_length, 0);
}

#[test]
fn edge_no_virtual_submodule_list() {
    let xml = r#"
<ISO15745Profile><ProfileBody><ApplicationProcess>
  <DeviceAccessPointList>
    <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001"></DeviceAccessPointItem>
  </DeviceAccessPointList>
  <ModuleList>
    <ModuleItem ID="EMPTY" ModuleIdentNumber="0x000000FF"></ModuleItem>
  </ModuleList>
</ApplicationProcess></ProfileBody></ISO15745Profile>"#;
    let dev = device_from_xml(xml);
    assert_eq!(find_module(&dev, "EMPTY").submodules, vec![]);
}

#[test]
fn edge_multiple_daps() {
    let xml = r#"
<ISO15745Profile><ProfileBody><ApplicationProcess>
  <DeviceAccessPointList>
    <DeviceAccessPointItem ID="DAP_A" ModuleIdentNumber="0x00000001"></DeviceAccessPointItem>
    <DeviceAccessPointItem ID="DAP_B" ModuleIdentNumber="0x00000002"></DeviceAccessPointItem>
  </DeviceAccessPointList>
  <ModuleList/>
</ApplicationProcess></ProfileBody></ISO15745Profile>"#;
    let dev = device_from_xml(xml);
    assert_eq!(dev.daps.len(), 2);
    assert_eq!(dev.get_dap(None).unwrap().id, "DAP_A");
    assert_eq!(dev.get_dap(Some("DAP_B")).unwrap().id, "DAP_B");
    assert_eq!(
        dev.get_dap(Some("DAP_B")).unwrap().module_ident,
        0x0000_0002
    );
}

#[test]
fn edge_no_device_identity() {
    let xml = r#"
<ISO15745Profile><ProfileBody><ApplicationProcess>
  <DeviceAccessPointList>
    <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001"></DeviceAccessPointItem>
  </DeviceAccessPointList>
  <ModuleList/>
</ApplicationProcess></ProfileBody></ISO15745Profile>"#;
    let dev = device_from_xml(xml);
    assert_eq!(dev.vendor_id, 0);
    assert_eq!(dev.device_id, 0);
}

#[test]
fn edge_no_dap_raises_on_get() {
    let dev = GsdmlDevice::default();
    let err = dev.get_dap(None).unwrap_err();
    assert!(err.contains("No DAP"), "unexpected error: {err}");
}

#[test]
fn edge_no_useable_modules() {
    let xml = r#"
<ISO15745Profile><ProfileBody><ApplicationProcess>
  <DeviceAccessPointList>
    <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001">
      <VirtualSubmoduleList>
        <VirtualSubmoduleItem ID="S" SubmoduleIdentNumber="0x00000001">
          <IOData><Input><DataItem DataType="Unsigned8"/></Input></IOData>
        </VirtualSubmoduleItem>
      </VirtualSubmoduleList>
    </DeviceAccessPointItem>
  </DeviceAccessPointList>
  <ModuleList/>
</ApplicationProcess></ProfileBody></ISO15745Profile>"#;
    let dev = device_from_xml(xml);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].slot, 0);
    assert_eq!(slots[0].subslot, 1);
    assert_eq!(slots[0].input_length, 1);
}

#[test]
fn edge_module_with_multiple_submodules() {
    let xml = r#"
<ISO15745Profile><ProfileBody><ApplicationProcess>
  <DeviceAccessPointList>
    <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001">
      <UseableModules>
        <ModuleItemRef ModuleItemTarget="MULTI" FixedInSlots="1"/>
      </UseableModules>
    </DeviceAccessPointItem>
  </DeviceAccessPointList>
  <ModuleList>
    <ModuleItem ID="MULTI" ModuleIdentNumber="0x00000030">
      <VirtualSubmoduleList>
        <VirtualSubmoduleItem ID="MS1" SubmoduleIdentNumber="0x00000001">
          <IOData><Input><DataItem DataType="Unsigned16"/></Input></IOData>
        </VirtualSubmoduleItem>
        <VirtualSubmoduleItem ID="MS2" SubmoduleIdentNumber="0x00000002">
          <IOData><Output><DataItem DataType="Unsigned32"/></Output></IOData>
        </VirtualSubmoduleItem>
      </VirtualSubmoduleList>
    </ModuleItem>
  </ModuleList>
</ApplicationProcess></ProfileBody></ISO15745Profile>"#;
    let dev = device_from_xml(xml);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    let mod_slots: Vec<&IoSlot> = slots.iter().filter(|s| s.slot == 1).collect();
    assert_eq!(mod_slots.len(), 2);
    assert_eq!(mod_slots[0].subslot, 1);
    assert_eq!(mod_slots[0].input_length, 2);
    assert_eq!(mod_slots[1].subslot, 2);
    assert_eq!(mod_slots[1].output_length, 4);
}

#[test]
fn edge_dap_with_multiple_virtual_submodules() {
    let xml = r#"
<ISO15745Profile><ProfileBody><ApplicationProcess>
  <DeviceAccessPointList>
    <DeviceAccessPointItem ID="DAP" ModuleIdentNumber="0x00000001">
      <VirtualSubmoduleList>
        <VirtualSubmoduleItem ID="DS1" SubmoduleIdentNumber="0x00000001">
          <IOData><Input><DataItem DataType="Unsigned8"/></Input></IOData>
        </VirtualSubmoduleItem>
        <VirtualSubmoduleItem ID="DS2" SubmoduleIdentNumber="0x00000002">
          <IOData><Output><DataItem DataType="Unsigned16"/></Output></IOData>
        </VirtualSubmoduleItem>
      </VirtualSubmoduleList>
    </DeviceAccessPointItem>
  </DeviceAccessPointList>
  <ModuleList/>
</ApplicationProcess></ProfileBody></ISO15745Profile>"#;
    let dev = device_from_xml(xml);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0].subslot, 1);
    assert_eq!(slots[0].input_length, 1);
    assert_eq!(slots[1].subslot, 2);
    assert_eq!(slots[1].output_length, 2);
}

// --- TestParseSlotSpec -------------------------------------------------------

#[test]
fn slot_spec_single() {
    assert_eq!(fixed_of("FixedInSlots=\"1\""), vec![1]);
}

#[test]
fn slot_spec_range() {
    assert_eq!(fixed_of("FixedInSlots=\"1..3\""), vec![1, 2, 3]);
}

#[test]
fn slot_spec_space_separated() {
    assert_eq!(fixed_of("FixedInSlots=\"1 3 5\""), vec![1, 3, 5]);
}

#[test]
fn slot_spec_mixed() {
    assert_eq!(fixed_of("FixedInSlots=\"1..3 5\""), vec![1, 2, 3, 5]);
}

#[test]
fn slot_spec_empty() {
    assert_eq!(fixed_of("FixedInSlots=\"\""), Vec::<u16>::new());
}

#[test]
fn slot_spec_none() {
    // No FixedInSlots attribute at all -> empty list.
    assert_eq!(fixed_of(""), Vec::<u16>::new());
}

#[test]
fn slot_spec_comma_separated() {
    assert_eq!(fixed_of("FixedInSlots=\"1,2,3\""), vec![1, 2, 3]);
}

// --- TestLoadGsdmlFile -------------------------------------------------------

fn write_temp_gsdml(name: &str, contents: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("profinet-rs-gsdml-file-tests");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write temp gsdml");
    path
}

#[test]
fn file_load_gsdml() {
    let path = write_temp_gsdml("load.xml", MINIMAL_GSDML);
    let dev = load_gsdml(&path).unwrap();
    assert_eq!(dev.vendor_id, 0x002A);
    assert_eq!(dev.daps.len(), 1);
    assert_eq!(dev.modules.len(), 2);
}

#[test]
fn file_parse_gsdml() {
    let path = write_temp_gsdml("parse.xml", MINIMAL_GSDML);
    let slots = parse_gsdml(&path, None).unwrap();
    assert_eq!(slots.len(), 5);
}

#[test]
fn file_parse_gsdml_with_assignment() {
    let path = write_temp_gsdml("parse_assign.xml", MINIMAL_GSDML);
    let mut assignment = BTreeMap::new();
    assignment.insert(1u16, "MOD_OUTPUT".to_string());
    let slots = parse_gsdml(&path, Some(&assignment)).unwrap();
    let mod_slots: Vec<&IoSlot> = slots.iter().filter(|s| s.slot > 0).collect();
    assert_eq!(mod_slots.len(), 1);
    assert_eq!(mod_slots[0].output_length, 2);
}

#[test]
fn file_load_gsdml_str_path() {
    let path = write_temp_gsdml("load_str.xml", MINIMAL_GSDML);
    let dev = load_gsdml(path.to_str().unwrap()).unwrap();
    assert_eq!(dev.vendor_id, 0x002A);
}

// --- TestUseableSubmodules ---------------------------------------------------

#[test]
fn useable_submodule_catalog_parsed() {
    let dev = device_from_xml(GSDML_WITH_SUBMODULE_LIST);
    assert_eq!(dev.submodule_catalog.len(), 3);
    assert_eq!(find_catalog(&dev, "IDS_TOTAL").input_length, 2);
    assert_eq!(find_catalog(&dev, "IDS_4CH").input_length, 40);
    assert_eq!(find_catalog(&dev, "IDS_8CH").output_length, 16);
}

#[test]
fn useable_module_useable_submodules() {
    let dev = device_from_xml(GSDML_WITH_SUBMODULE_LIST);
    let pwr = find_module(&dev, "IDM_PWR");
    let targets: Vec<&str> = pwr
        .useable_submodules
        .iter()
        .map(|r| r.target.as_str())
        .collect();
    assert!(targets.contains(&"IDS_TOTAL"));
    assert!(targets.contains(&"IDS_4CH"));
    assert!(targets.contains(&"IDS_8CH"));
}

#[test]
fn useable_module_fixed_subslots() {
    let dev = device_from_xml(GSDML_WITH_SUBMODULE_LIST);
    let pwr = find_module(&dev, "IDM_PWR");
    // Only IDS_TOTAL carries FixedInSubslots="1"; the others are empty.
    assert_eq!(
        find_ref(&pwr.useable_submodules, "IDS_TOTAL").fixed,
        vec![1]
    );
    assert!(find_ref(&pwr.useable_submodules, "IDS_4CH")
        .fixed
        .is_empty());
    assert!(find_ref(&pwr.useable_submodules, "IDS_8CH")
        .fixed
        .is_empty());
}

#[test]
fn useable_build_io_slots_fixed_only() {
    let dev = device_from_xml(GSDML_WITH_SUBMODULE_LIST);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    let pwr_slots: Vec<&IoSlot> = slots.iter().filter(|s| s.slot == 2).collect();
    assert_eq!(pwr_slots.len(), 1); // only IDS_TOTAL (fixed)
    assert_eq!(pwr_slots[0].subslot, 1);
    assert_eq!(pwr_slots[0].input_length, 2);
    assert_eq!(pwr_slots[0].module_ident, 0x1000_032A);
}

#[test]
fn useable_build_io_slots_with_submodule_assignment() {
    let dev = device_from_xml(GSDML_WITH_SUBMODULE_LIST);
    let mut inner = BTreeMap::new();
    inner.insert(2u16, "IDS_8CH".to_string());
    let mut outer = BTreeMap::new();
    outer.insert(2u16, inner);
    let slots = dev.build_io_slots(None, Some(&outer), None).unwrap();
    let pwr_slots: Vec<&IoSlot> = slots.iter().filter(|s| s.slot == 2).collect();
    assert_eq!(pwr_slots.len(), 2);
    assert_eq!(pwr_slots[0].subslot, 1); // IDS_TOTAL (fixed)
    assert_eq!(pwr_slots[0].input_length, 2);
    assert_eq!(pwr_slots[1].subslot, 2); // IDS_8CH (assigned)
    assert_eq!(pwr_slots[1].input_length, 80);
    assert_eq!(pwr_slots[1].output_length, 16);
    assert_eq!(pwr_slots[1].submodule_ident, 0x0000_0118);
}

#[test]
fn useable_build_io_slots_from_device_with_catalog() {
    let dev = device_from_xml(GSDML_WITH_SUBMODULE_LIST);
    let device_slots = [
        DeviceSlot {
            slot: 1,
            subslot: 1,
            module_ident: 0x1000_0000,
            submodule_ident: 0x2000_0000,
        }, // IDM_DEV inline
        DeviceSlot {
            slot: 2,
            subslot: 1,
            module_ident: 0x1000_032A,
            submodule_ident: 0x0000_0001,
        }, // IDS_TOTAL
        DeviceSlot {
            slot: 2,
            subslot: 2,
            module_ident: 0x1000_032A,
            submodule_ident: 0x0000_0114,
        }, // IDS_4CH
    ];
    let slots = dev.build_io_slots_from_device(&device_slots, None).unwrap();
    assert_eq!(slots[0].input_length, 2); // Integer16
    assert_eq!(slots[0].output_length, 2); // Unsigned16
    assert_eq!(slots[1].input_length, 2); // IDS_TOTAL
    assert_eq!(slots[2].input_length, 40); // IDS_4CH
    assert_eq!(slots[2].output_length, 8);
}

#[test]
fn useable_inline_module_unaffected() {
    let dev = device_from_xml(GSDML_WITH_SUBMODULE_LIST);
    let slots = dev.build_io_slots(None, None, None).unwrap();
    let dev_slots: Vec<&IoSlot> = slots.iter().filter(|s| s.slot == 1).collect();
    assert_eq!(dev_slots.len(), 1);
    assert_eq!(dev_slots[0].input_length, 2);
    assert_eq!(dev_slots[0].output_length, 2);
}
