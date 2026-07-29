//! Golden byte-fidelity tests for the foundation module, asserting
//! byte-for-byte equality against vectors generated from the Python
//! reference (tools/gen_golden.py -> tests/golden/foundation.json).

use profinet_rs::blocks::{block_header, iod_read_request, iod_write_request};
use profinet_rs::util::{ip2s, mac2s, s2ip, s2mac};

fn golden() -> serde_json::Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/foundation.json"
    ))
    .expect("read golden file");
    serde_json::from_str(&raw).expect("parse golden file")
}

fn golden_hex(name: &str) -> String {
    golden()[name]["hex"]
        .as_str()
        .unwrap_or_else(|| panic!("golden entry {name} missing hex"))
        .to_string()
}

fn ar_uuid() -> [u8; 16] {
    let mut ar = [0u8; 16];
    for (i, b) in ar.iter_mut().enumerate() {
        *b = i as u8;
    }
    ar
}

#[test]
fn golden_s2mac() {
    assert_eq!(
        hex::encode(s2mac("01:02:03:04:05:06").unwrap()),
        golden_hex("s2mac")
    );
}

#[test]
fn golden_ip2s() {
    assert_eq!(
        hex::encode(ip2s("192.168.0.2").unwrap()),
        golden_hex("ip2s")
    );
}

#[test]
fn golden_block_header() {
    assert_eq!(
        hex::encode(block_header(0x0009, 60, 1, 0)),
        golden_hex("block_iod_read_header")
    );
}

#[test]
fn golden_iod_read() {
    let ar = ar_uuid();
    assert_eq!(
        hex::encode(iod_read_request(&ar, 0, 1, 1, 4660, 8)),
        golden_hex("iod_read_record")
    );
}

#[test]
fn golden_iod_write() {
    let ar = ar_uuid();
    assert_eq!(
        hex::encode(iod_write_request(&ar, 0, 2, 1, 5000, &[0x01])),
        golden_hex("iod_write_5000")
    );
}

#[test]
fn mac_round_trip() {
    let s = "de:ad:be:ef:00:42";
    assert_eq!(mac2s(&s2mac(s).unwrap()), s);
}

#[test]
fn ip_round_trip() {
    let s = "192.168.0.2";
    assert_eq!(s2ip(&ip2s(s).unwrap()).unwrap(), s);
}

#[test]
fn bad_mac_rejected() {
    assert!(s2mac("").is_err());
    assert!(s2mac("01:02:03:04:05").is_err());
    assert!(s2mac("01:02:03:04:05:06:07").is_err());
    assert!(s2mac("gg:02:03:04:05:06").is_err());
    assert!(s2mac("1:2:3:4:5:6").is_err());
}

#[test]
fn bad_ip_rejected() {
    assert!(ip2s("").is_err());
    assert!(ip2s("192.168.0").is_err());
    assert!(ip2s("192.168.0.2.5").is_err());
    assert!(ip2s("256.0.0.1").is_err());
    assert!(ip2s("192.168.0.x").is_err());
    assert!(s2ip(&[1, 2, 3]).is_err());
}

// ---------------------------------------------------------------------------
// Ports of profinet-py tests/test_util.py (MAC/IP conversions). Note the
// direction naming follows the reference: ip2s parses a string into bytes,
// s2ip formats bytes into a string.
// ---------------------------------------------------------------------------

mod py_parity {
    use profinet_rs::util::{ip2s, mac2s, s2ip, s2mac};

    // test_s2mac_valid
    #[test]
    fn s2mac_valid() {
        assert_eq!(
            s2mac("01:02:03:04:05:06").unwrap(),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
        );
    }

    // test_s2mac_uppercase
    #[test]
    fn s2mac_uppercase() {
        assert_eq!(
            s2mac("AA:BB:CC:DD:EE:FF").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    // test_s2mac_mixed_case
    #[test]
    fn s2mac_mixed_case() {
        assert_eq!(
            s2mac("aA:Bb:cC:Dd:Ee:Ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    // test_s2mac_invalid_format, test_s2mac_empty, test_s2mac_too_short
    #[test]
    fn s2mac_invalid_inputs() {
        assert!(s2mac("invalid-mac").is_err());
        assert!(s2mac("").is_err());
        assert!(s2mac("01:02:03").is_err());
    }

    // test_mac2s_valid
    #[test]
    fn mac2s_valid() {
        assert_eq!(
            mac2s(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            "01:02:03:04:05:06"
        );
    }

    // test_mac_roundtrip
    #[test]
    fn mac_roundtrip() {
        let original = "de:ad:be:ef:ca:fe";
        assert_eq!(mac2s(&s2mac(original).unwrap()), original);
    }

    // test_s2ip_valid
    #[test]
    fn s2ip_valid() {
        assert_eq!(s2ip(&[0xc0, 0xa8, 0x01, 0x01]).unwrap(), "192.168.1.1");
    }

    // test_s2ip_zeros
    #[test]
    fn s2ip_zeros() {
        assert_eq!(s2ip(&[0, 0, 0, 0]).unwrap(), "0.0.0.0");
    }

    // test_s2ip_broadcast
    #[test]
    fn s2ip_broadcast() {
        assert_eq!(s2ip(&[0xff, 0xff, 0xff, 0xff]).unwrap(), "255.255.255.255");
    }

    // test_s2ip_too_short
    #[test]
    fn s2ip_too_short() {
        assert!(s2ip(&[0x01, 0x02]).is_err());
    }

    // test_ip2s_valid
    #[test]
    fn ip2s_valid() {
        assert_eq!(ip2s("192.168.1.1").unwrap(), [0xc0, 0xa8, 0x01, 0x01]);
    }

    // test_ip2s_zeros
    #[test]
    fn ip2s_zeros() {
        assert_eq!(ip2s("0.0.0.0").unwrap(), [0, 0, 0, 0]);
    }

    // test_ip2s_invalid_format, test_ip2s_out_of_range, test_ip2s_empty
    #[test]
    fn ip2s_invalid_inputs() {
        assert!(ip2s("invalid.ip").is_err());
        assert!(ip2s("256.1.1.1").is_err());
        assert!(ip2s("").is_err());
    }

    // test_ip_roundtrip
    #[test]
    fn ip_roundtrip() {
        let original = "10.20.30.40";
        assert_eq!(s2ip(&ip2s(original).unwrap()).unwrap(), original);
    }
}
