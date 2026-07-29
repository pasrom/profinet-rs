//! Tests for the raw-L2 pcap backend's pure helpers: BPF filter string
//! construction and the discovery aggregation (frames -> Vec<DcpDevice>),
//! fed with the golden DCP identify response vectors. The live socket path
//! (open/send/recv) is bench-validated; the live test below is ignored.

use std::time::Duration;

use profinet_rs::dcp::DcpDevice;
use profinet_rs::pcap::{aggregate_responses, bpf_filter, discover};

/// Our MAC: the dst of the golden identify response frames.
const MY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DEV_MAC: [u8; 6] = [0x00, 0x1b, 0x1b, 0xaa, 0xbb, 0xcc];
/// The xid the golden identify frames were generated with.
const XID: u32 = 0x0102_0304;

fn golden_hex(name: &str) -> String {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/foundation.json"
    ))
    .expect("read golden file");
    let golden: serde_json::Value = serde_json::from_str(&raw).expect("parse golden file");
    golden[name]["hex"]
        .as_str()
        .unwrap_or_else(|| panic!("golden entry {name} missing hex"))
        .to_string()
}

fn golden_frame(name: &str) -> Vec<u8> {
    hex::decode(golden_hex(name)).expect("decode golden hex")
}

fn expected_device() -> DcpDevice {
    DcpDevice {
        mac: DEV_MAC,
        name: "device-io".to_string(),
        device_type: "S7-1200".to_string(),
        ip: [192, 168, 10, 3],
        netmask: [255, 255, 255, 0],
        gateway: [192, 168, 10, 1],
        vendor_id: 0x002A,
        device_id: 0x0101,
        role: 0x01,
    }
}

#[test]
fn bpf_filter_is_vlan_aware() {
    assert_eq!(
        bpf_filter(0x8892),
        "ether proto 0x8892 or (vlan and ether proto 0x8892)"
    );
    // Sub-0x1000 EtherType keeps the 4-digit zero padding.
    assert_eq!(
        bpf_filter(0x0800),
        "ether proto 0x0800 or (vlan and ether proto 0x0800)"
    );
}

#[test]
fn aggregate_parses_golden_response() {
    let frames = vec![golden_frame("dcp_identify_response")];
    assert_eq!(
        aggregate_responses(&frames, &MY_MAC, XID),
        vec![expected_device()]
    );
}

#[test]
fn aggregate_dedups_by_mac() {
    // Same device answering plain and VLAN-tagged: one entry, later frame
    // wins (read_response's `result[eth.src] = parsed`).
    let frames = vec![
        golden_frame("dcp_identify_response"),
        golden_frame("dcp_identify_response_vlan"),
        golden_frame("dcp_identify_response"),
    ];
    assert_eq!(
        aggregate_responses(&frames, &MY_MAC, XID),
        vec![expected_device()]
    );
}

#[test]
fn aggregate_keeps_distinct_devices() {
    let mut other = golden_frame("dcp_identify_response");
    other[6..12].copy_from_slice(&[0x00, 0x1b, 0x1b, 0x11, 0x22, 0x33]);
    let frames = vec![golden_frame("dcp_identify_response"), other];

    let devices = aggregate_responses(&frames, &MY_MAC, XID);
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0], expected_device());
    assert_eq!(devices[1].mac, [0x00, 0x1b, 0x1b, 0x11, 0x22, 0x33]);
    assert_eq!(devices[1].name, expected_device().name);
}

#[test]
fn aggregate_filters_frames_not_addressed_to_us() {
    let frames = vec![golden_frame("dcp_identify_response")];
    let other_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    assert_eq!(aggregate_responses(&frames, &other_mac, XID), vec![]);
}

#[test]
fn aggregate_skips_garbage_frames() {
    // Too short for an Ethernet header, and addressed-to-us but unparseable
    // (a DCP request, not a response): both silently skipped.
    let mut request_to_us = golden_frame("dcp_identify_all_request");
    request_to_us[0..6].copy_from_slice(&MY_MAC);
    let frames = vec![
        vec![0x02, 0x00, 0x00],
        request_to_us,
        golden_frame("dcp_identify_response"),
    ];
    assert_eq!(
        aggregate_responses(&frames, &MY_MAC, XID),
        vec![expected_device()]
    );
}

#[test]
fn aggregate_skips_foreign_xid() {
    // A valid, well-formed identify response addressed to us, but answering a
    // different controller's Identify-All (mismatched xid): not our discovery.
    let mut foreign = golden_frame("dcp_identify_response");
    // xid lives at Ethernet(14) + frame_id(2) + service_id(1) + service_type(1).
    foreign[18..22].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    let frames = vec![foreign];
    assert_eq!(aggregate_responses(&frames, &MY_MAC, XID), vec![]);
    // ...and it is accepted when we ask for that xid, proving only the match filters.
    assert_eq!(aggregate_responses(&frames, &MY_MAC, 0xDEAD_BEEF).len(), 1);
}

/// Live discovery against real hardware; needs a PROFINET device on the
/// interface and BPF capture privileges. Run with:
/// `PROFINET_IFACE=en7 cargo test --test pcap -- --ignored --nocapture`
#[test]
#[ignore = "requires a live interface with BPF capture privileges"]
fn live_discover() {
    let iface = std::env::var("PROFINET_IFACE").unwrap_or_else(|_| "en0".to_string());
    let devices = discover(&iface, Duration::from_secs(3)).expect("discover");
    println!("discovered on {iface}: {devices:#?}");
}
