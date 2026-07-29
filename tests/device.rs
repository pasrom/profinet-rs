//! Unit tests for the high-level device module (device.py port): the pure
//! selection/record-building helpers, the DeviceInfo composition and the
//! ProfinetDevice constructor/accessor handling. The live connect/read path
//! is exercised by the bench binary and the hardware-gated test below.

use std::time::Duration;

use profinet_rs::connect::build_device_access_connect_request;
use profinet_rs::dcp::DcpDevice;
use profinet_rs::device::{
    alarm_from_record, find_by_identifier, find_by_ip, im1_record, im2_record, im3_record,
    parse_mac_flexible, DeviceInfo, ProfinetDevice, WriteItem,
};
use profinet_rs::im::{BlockHeader, InM0};
use profinet_rs::vendors::get_vendor_name;

fn demo_device() -> DcpDevice {
    DcpDevice {
        mac: [0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF],
        name: "device".to_string(),
        device_type: "ExampleIO".to_string(),
        ip: [192, 168, 0, 2],
        netmask: [255, 255, 255, 0],
        gateway: [192, 168, 0, 1],
        vendor_id: 0x0ABC,
        device_id: 0x0007,
        role: 0x01,
    }
}

fn other() -> DcpDevice {
    DcpDevice {
        mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        name: "other-device".to_string(),
        ip: [192, 168, 0, 3],
        ..DcpDevice::default()
    }
}

// ---------------------------------------------------------------------------
// parse_mac_flexible (_parse_mac)
// ---------------------------------------------------------------------------

#[test]
fn parse_mac_flexible_accepts_separators_and_case() {
    let expected = [0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF];
    for s in [
        "00:0c:29:ab:cd:ef",
        "00-0C-29-AB-CD-EF",
        "00.0c.29.ab.cd.ef",
        " 00:0C:29:ab:CD:ef ",
    ] {
        assert_eq!(parse_mac_flexible(s), Some(expected), "input {s:?}");
    }
}

#[test]
fn parse_mac_flexible_rejects_non_macs() {
    for s in [
        "device",
        "",
        "00:0c:29:ab:cd",
        "00:0c:29:ab:cd:ef:12",
        "zz:0c:29:ab:cd:ef",
    ] {
        assert_eq!(parse_mac_flexible(s), None, "input {s:?}");
    }
}

// ---------------------------------------------------------------------------
// Device selection (discover / from_ip filters)
// ---------------------------------------------------------------------------

#[test]
fn find_by_identifier_matches_name_then_mac() {
    let devices = [demo_device(), other()];
    assert_eq!(find_by_identifier(&devices, "device"), Some(demo_device()));
    assert_eq!(find_by_identifier(&devices, "other-device"), Some(other()));
    // A MAC-shaped identifier selects by MAC, any separator style.
    assert_eq!(
        find_by_identifier(&devices, "00-0C-29-AB-CD-EF"),
        Some(demo_device())
    );
    assert_eq!(
        find_by_identifier(&devices, "02:00:00:00:00:01"),
        Some(other())
    );
    assert_eq!(find_by_identifier(&devices, "joker"), None);
    assert_eq!(find_by_identifier(&devices, "ff:ff:ff:ff:ff:ff"), None);
    assert_eq!(find_by_identifier(&[], "device"), None);
}

#[test]
fn find_by_ip_matches_dotted_decimal() {
    let devices = [demo_device(), other()];
    assert_eq!(find_by_ip(&devices, "192.168.0.2"), Some(demo_device()));
    assert_eq!(find_by_ip(&devices, "192.168.0.3"), Some(other()));
    assert_eq!(find_by_ip(&devices, "192.168.0.9"), None);
}

// ---------------------------------------------------------------------------
// I&M write record builders (write_im1/2/3 payloads)
// ---------------------------------------------------------------------------

#[test]
fn im1_record_layout_matches_reference() {
    let data = im1_record("Pump Control", "Building A").expect("valid I&M1");
    assert_eq!(data.len(), 62);
    // BlockHeader: type 0x0021, length 58, version 1.0, then 2 pad bytes.
    assert_eq!(
        &data[..8],
        &[0x00, 0x21, 0x00, 0x3A, 0x01, 0x00, 0x00, 0x00]
    );
    // TagFunction: 32 bytes, space-padded.
    assert_eq!(&data[8..20], b"Pump Control");
    assert!(data[20..40].iter().all(|&b| b == 0x20));
    // TagLocation: 22 bytes, space-padded.
    assert_eq!(&data[40..50], b"Building A");
    assert!(data[50..62].iter().all(|&b| b == 0x20));
}

#[test]
fn im1_record_enforces_length_limits() {
    assert!(im1_record(&"x".repeat(33), "ok").is_err());
    assert!(im1_record("ok", &"x".repeat(23)).is_err());
    assert_eq!(
        im1_record(&"x".repeat(32), &"y".repeat(22))
            .expect("max lengths valid")
            .len(),
        62
    );
}

#[test]
fn im_records_encode_latin1_and_reject_beyond() {
    // Latin-1 characters encode as their single byte, like Python's
    // .encode("latin-1").
    let data = im2_record("Präzision").expect("Latin-1 valid");
    assert_eq!(data[8 + 2], 0xE4); // 'ä'
                                   // Characters beyond U+00FF raised UnicodeEncodeError in the reference.
    assert!(im2_record("日付").is_err());
}

#[test]
fn im2_record_layout_matches_reference() {
    let data = im2_record("2026-07-18 12:00").expect("valid I&M2");
    assert_eq!(data.len(), 24);
    assert_eq!(
        &data[..8],
        &[0x00, 0x22, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00]
    );
    assert_eq!(&data[8..24], b"2026-07-18 12:00");
    assert!(im2_record(&"x".repeat(17)).is_err());
}

#[test]
fn im3_record_layout_matches_reference() {
    let data = im3_record("test descriptor").expect("valid I&M3");
    assert_eq!(data.len(), 62);
    assert_eq!(
        &data[..8],
        &[0x00, 0x23, 0x00, 0x3A, 0x01, 0x00, 0x00, 0x00]
    );
    assert_eq!(&data[8..23], b"test descriptor");
    assert!(data[23..62].iter().all(|&b| b == 0x20));
    assert!(im3_record(&"x".repeat(55)).is_err());
}

// ---------------------------------------------------------------------------
// Alarm record interpretation (read_alarm)
// ---------------------------------------------------------------------------

#[test]
fn alarm_from_record_needs_minimum_length() {
    // Below the 28-byte minimum alarm notification size: no alarm.
    assert_eq!(alarm_from_record(&[]), None);
    assert_eq!(alarm_from_record(&[0u8; 27]), None);
    // At the minimum size the (lenient) parser yields a notification, like
    // the reference's parse_alarm_notification.
    assert!(alarm_from_record(&[0u8; 28]).is_some());
}

// ---------------------------------------------------------------------------
// DeviceInfo composition (get_info)
// ---------------------------------------------------------------------------

#[test]
fn device_info_from_dcp_maps_all_fields() {
    let info = DeviceInfo::from_dcp(&demo_device());
    assert_eq!(info.name, "device");
    assert_eq!(info.ip, "192.168.0.2");
    assert_eq!(info.mac, "00:0c:29:ab:cd:ef");
    assert_eq!(info.vendor_id, 0x0ABC);
    assert_eq!(info.device_id, 0x0007);
    assert_eq!(info.device_type, "ExampleIO");
    assert_eq!(info.netmask, "255.255.255.0");
    assert_eq!(info.gateway, "192.168.0.1");
    assert_eq!(info.role, 0x01);
    assert_eq!(info.vendor_name, get_vendor_name(0x0ABC));
    assert_eq!(info.im0, None);
    assert_eq!(info.topology, None);
    assert_eq!(info.annotation, "");
}

#[test]
fn device_info_im0_helpers_default_without_im0() {
    let info = DeviceInfo::from_dcp(&demo_device());
    assert_eq!(info.serial_number(), "");
    assert_eq!(info.order_id(), "");
    assert_eq!(info.hardware_revision(), 0);
    assert_eq!(info.software_revision(), "");
}

#[test]
fn device_info_im0_helpers_expose_identification() {
    let mut order_id = [0x20u8; 20];
    order_id[..6].copy_from_slice(b"DEV-42");
    let mut serial = [0x20u8; 16];
    serial[..5].copy_from_slice(b"SN123");
    let im0 = InM0 {
        block_header: BlockHeader {
            block_type: 0x0020,
            block_length: 56,
            version_high: 1,
            version_low: 0,
        },
        vendor_id_high: 0x04,
        vendor_id_low: 0xB0,
        order_id,
        im_serial_number: serial,
        im_hardware_revision: 3,
        sw_revision_prefix: b'V',
        im_sw_revision_functional_enhancement: 1,
        im_sw_revision_bug_fix: 2,
        im_sw_revision_internal_change: 3,
        im_revision_counter: 0,
        im_profile_id: 0,
        im_profile_specific_type: 0,
        im_version: 0x0101,
        im_supported: 0x000E,
    };
    let info = DeviceInfo {
        im0: Some(im0),
        ..DeviceInfo::from_dcp(&demo_device())
    };
    assert_eq!(info.order_id(), "DEV-42");
    assert_eq!(info.serial_number(), "SN123");
    assert_eq!(info.hardware_revision(), 3);
    assert_eq!(info.software_revision(), "V1.2.3");
}

// ---------------------------------------------------------------------------
// ProfinetDevice constructor/accessors (no device required)
// ---------------------------------------------------------------------------

#[test]
fn profinet_device_accessors_and_display() {
    let dev = ProfinetDevice::new(
        demo_device(),
        "en8",
        [0x02, 0, 0, 0, 0, 0xAA],
        [192, 168, 0, 10],
        Duration::from_secs(5),
    );
    assert_eq!(dev.name(), "device");
    assert_eq!(dev.ip(), "192.168.0.2");
    assert_eq!(dev.mac(), "00:0c:29:ab:cd:ef");
    assert_eq!(dev.dcp_info(), &demo_device());
    assert!(!dev.is_connected());
    assert_eq!(
        dev.to_string(),
        "ProfinetDevice(\"device\", 192.168.0.2, disconnected)"
    );
}

#[test]
fn write_item_carries_record_addressing() {
    let item = WriteItem {
        slot: 0,
        subslot: 1,
        index: 0xAFF1,
        data: vec![1, 2, 3],
    };
    assert_eq!(item.clone(), item);
}

// ---------------------------------------------------------------------------
// Device-Access connect request (the AR ProfinetDevice::connect establishes)
// ---------------------------------------------------------------------------

#[test]
fn device_access_connect_request_is_a_lone_iosar_ar_block() {
    let req = build_device_access_connect_request(
        &[0x11; 16],
        &[0x22; 16],
        &[0x33; 16],
        &[0x44; 16],
        0xBEEF,
        &[0x02, 0, 0, 0, 0, 0xAA],
        b"tp",
        7,
    );
    // 80-byte RPC header + 20-byte NRD + a single 60-byte ARBlockReq.
    assert_eq!(req.len(), 160);
    let body = &req[100..];
    // BlockHeader: ARBlockReq 0x0101, length 54 + len("tp"), version 1.0.
    assert_eq!(&body[..6], &[0x01, 0x01, 0x00, 0x38, 0x01, 0x00]);
    // AR type IOSAR (DeviceAccess), not IOCARSingle.
    assert_eq!(&body[6..8], &[0x00, 0x06]);
    assert_eq!(&body[8..24], &[0x44; 16]); // ar_uuid
    assert_eq!(&body[24..26], &[0xBE, 0xEF]); // session_key
    assert_eq!(&body[26..32], &[0x02, 0, 0, 0, 0, 0xAA]); // CMInitiatorMacAdd
                                                          // ARProperties: State=Active + PrmServer=CM_Initiator + DeviceAccess.
    assert_eq!(&body[48..52], &[0x00, 0x00, 0x01, 0x11]);
    // Timeout factor 100, UDP RT port 0x8892, then the station name.
    assert_eq!(&body[52..56], &[0x00, 0x64, 0x88, 0x92]);
    assert_eq!(&body[56..60], &[0x00, 0x02, b't', b'p']);
}

// ---------------------------------------------------------------------------
// Live path (hardware required)
// ---------------------------------------------------------------------------

/// Full high-level flow against a real device: discover by IP, connect the
/// Device-Access AR, read I&M0. Point `PROFINET_TEST_IP` / `PROFINET_TEST_IFACE`
/// at your own device; there are no useful defaults for someone else's bench.
#[test]
#[ignore = "requires a live PROFINET device on the interface"]
fn live_from_ip_connect_read_im0() {
    let ip = std::env::var("PROFINET_TEST_IP").expect("set PROFINET_TEST_IP");
    let iface = std::env::var("PROFINET_TEST_IFACE").expect("set PROFINET_TEST_IFACE");
    let mut dev =
        ProfinetDevice::from_ip(&ip, &iface, Duration::from_secs(5)).expect("discover device");
    let im0 = dev.read_im0().expect("read I&M0");
    assert!(im0.vendor_id() != 0, "I&M0 should carry a vendor id");
    dev.close();
}
