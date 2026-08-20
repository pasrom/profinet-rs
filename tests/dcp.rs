//! Golden byte-fidelity and parsing tests for the DCP module, asserting
//! byte-for-byte equality against vectors generated from the Python
//! reference (tools/gen_golden.py -> tests/golden/foundation.json).

use profinet_rs::dcp::{
    identify_all_request, parse_identify_response, set_ip_request, set_name_request,
    set_name_request_qualified, DcpDevice,
};

const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DST_MAC: [u8; 6] = [0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f];
const DEV_MAC: [u8; 6] = [0x00, 0x1b, 0x1b, 0xaa, 0xbb, 0xcc];
const XID: u32 = 0x01020304;

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

#[test]
fn golden_identify_all_request() {
    assert_eq!(
        hex::encode(identify_all_request(&SRC_MAC, XID)),
        golden_hex("dcp_identify_all_request")
    );
}

#[test]
fn golden_set_name_request_even() {
    assert_eq!(
        hex::encode(set_name_request(&SRC_MAC, &DST_MAC, XID, "device")),
        golden_hex("dcp_set_name_request")
    );
}

#[test]
fn golden_set_name_request_odd() {
    // Odd-length name: the DCP length field counts a pad byte the reference
    // never appends to the frame; the golden vector locks in that quirk.
    assert_eq!(
        hex::encode(set_name_request(&SRC_MAC, &DST_MAC, XID, "plc-1")),
        golden_hex("dcp_set_name_request_odd")
    );
}

#[test]
fn golden_set_ip_request() {
    assert_eq!(
        hex::encode(set_ip_request(
            &SRC_MAC,
            &DST_MAC,
            XID,
            &[192, 168, 10, 3],
            &[255, 255, 255, 0],
            &[192, 168, 10, 1],
        )),
        golden_hex("dcp_set_ip_request")
    );
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
fn parse_golden_identify_response() {
    let frame = hex::decode(golden_hex("dcp_identify_response")).expect("decode golden hex");
    let device = parse_identify_response(&frame).expect("parse identify response");
    assert_eq!(device, expected_device());
}

#[test]
fn parse_golden_identify_response_vlan() {
    let frame = hex::decode(golden_hex("dcp_identify_response_vlan")).expect("decode golden hex");
    let device = parse_identify_response(&frame).expect("parse VLAN identify response");
    assert_eq!(device, expected_device());
}

/// Response block: option ++ suboption ++ length(incl. status) ++ status ++
/// payload, padded to 2-byte alignment.
fn resp_block(option: u8, suboption: u8, status: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![option, suboption];
    out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(payload);
    if out.len() % 2 == 1 {
        out.push(0x00);
    }
    out
}

fn response_frame(blocks: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&SRC_MAC); // dst: us
    frame.extend_from_slice(&DEV_MAC); // src: device
    frame.extend_from_slice(&0x8892u16.to_be_bytes());
    frame.extend_from_slice(&0xFEFFu16.to_be_bytes()); // frame_id
    frame.push(0x05); // service_id IDENTIFY
    frame.push(0x01); // service_type RESPONSE
    frame.extend_from_slice(&XID.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // resp
    frame.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
    frame.extend_from_slice(blocks);
    frame
}

#[test]
fn parse_minimal_response_name_and_device_id() {
    let mut blocks = resp_block(0x02, 0x02, 0x0000, b"dev");
    blocks.extend_from_slice(&resp_block(0x02, 0x03, 0x0000, &[0x0A, 0xBC, 0x00, 0x07]));
    let device = parse_identify_response(&response_frame(&blocks)).expect("parse");
    assert_eq!(device.mac, DEV_MAC);
    assert_eq!(device.name, "dev");
    assert_eq!(device.vendor_id, 0x0ABC);
    assert_eq!(device.device_id, 0x0007);
    // Blocks absent from the response keep their defaults.
    assert_eq!(device.ip, [0, 0, 0, 0]);
    assert_eq!(device.device_type, "");
    assert_eq!(device.role, 0);
}

#[test]
fn parse_rejects_truncated_frame() {
    let frame = hex::decode(golden_hex("dcp_identify_response")).expect("decode golden hex");
    assert!(parse_identify_response(&frame[..10]).is_err()); // inside eth header
    assert!(parse_identify_response(&frame[..20]).is_err()); // inside DCP header
}

#[test]
fn parse_rejects_wrong_ethertype() {
    let mut frame = hex::decode(golden_hex("dcp_identify_response")).expect("decode golden hex");
    frame[12] = 0x08; // 0x0800 IPv4
    frame[13] = 0x00;
    let err = parse_identify_response(&frame).unwrap_err();
    assert!(err.contains("EtherType"), "unexpected error: {err}");
}

#[test]
fn parse_rejects_vlan_with_wrong_inner_ethertype() {
    let mut frame =
        hex::decode(golden_hex("dcp_identify_response_vlan")).expect("decode golden hex");
    frame[16] = 0x08; // inner ethertype -> 0x0800
    frame[17] = 0x00;
    let err = parse_identify_response(&frame).unwrap_err();
    assert!(err.contains("inner EtherType"), "unexpected error: {err}");
}

#[test]
fn parse_rejects_request_service_type() {
    // Our own Identify request must not parse as a response.
    let frame = identify_all_request(&SRC_MAC, XID);
    let err = parse_identify_response(&frame).unwrap_err();
    assert!(err.contains("service_type"), "unexpected error: {err}");
}

#[test]
fn parse_survives_truncated_block() {
    // A block whose length field runs past the end of the frame must not
    // panic; the walker stops like the reference's silent slicing.
    let mut blocks = resp_block(0x02, 0x02, 0x0000, b"dev");
    blocks.extend_from_slice(&[0x01, 0x02, 0x00, 0x40, 0x00, 0x01, 0xAA]); // claims 0x40 bytes
    let device = parse_identify_response(&response_frame(&blocks)).expect("parse");
    assert_eq!(device.name, "dev");
    assert_eq!(device.ip, [0, 0, 0, 0]);
}

// ---------------------------------------------------------------------------
// CLI-facing DCP builders/parsers (get/set/signal/reset), byte-verified
// against the Python reference (construct-backed protocol.py).
// ---------------------------------------------------------------------------

mod cli_builders {
    use profinet_rs::dcp::*;

    const S: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const D: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const X: u32 = 0x12345678;

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn get_request_matches_reference() {
        assert_eq!(
            hx(&get_request(
                &S,
                &D,
                X,
                DCP_OPTION_DEVICE,
                DCP_SUBOPTION_DEVICE_NAME
            )),
            "aabbccddeeff0011223344558892fefd0300123456780000000202020000"
        );
    }

    #[test]
    fn signal_request_matches_reference() {
        // 3000 ms -> 30 (0x1e) units of 100 ms, temporary-signal qualifier.
        assert_eq!(
            hx(&signal_request(&S, &D, X, 3000)),
            "aabbccddeeff0011223344558892fefd04001234567800000008050300040001001e"
        );
    }

    #[test]
    fn reset_request_matches_reference() {
        assert_eq!(
            hx(&reset_request(&S, &D, X, RESET_MODE_FACTORY)),
            "aabbccddeeff0011223344558892fefd04001234567800000006050600020040"
        );
    }

    #[test]
    fn set_ip_permanent_matches_reference() {
        assert_eq!(
            hx(&set_ip_request_qualified(
                &S,
                &D,
                X,
                &[192, 168, 0, 5],
                &[255, 255, 255, 0],
                &[192, 168, 0, 1],
                true
            )),
            "aabbccddeeff0011223344558892fefd040012345678000000120102000e0001c0a80005ffffff00c0a80001"
        );
    }

    /// Build a minimal Ethernet+DCP SET response carrying a Control/Response
    /// block (option 5, suboption 4) with the given block error byte.
    fn set_response_frame(block_error: u8) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&S); // dst = our MAC
        f.extend_from_slice(&D); // src = device
        f.extend_from_slice(&0x8892u16.to_be_bytes());
        // DCP header: frame_id, service_id=SET, service_type=RESPONSE_SUCCESS.
        f.extend_from_slice(&0xfefdu16.to_be_bytes());
        f.push(DCP_SERVICE_ID_SET);
        f.push(DCP_SERVICE_TYPE_RESPONSE_SUCCESS);
        f.extend_from_slice(&X.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes()); // resp
        let block = [
            DCP_OPTION_CONTROL,
            DCP_SUBOPTION_CONTROL_RESPONSE,
            0x00,
            0x03,
            0x05,
            0x04,
            block_error,
            0x00,
        ];
        f.extend_from_slice(&(block.len() as u16).to_be_bytes());
        f.extend_from_slice(&block);
        f
    }

    #[test]
    fn parse_set_response_reads_block_error() {
        assert_eq!(
            parse_set_response(&set_response_frame(0x00), X).unwrap(),
            Some(0)
        );
        assert_eq!(
            parse_set_response(&set_response_frame(0x06), X).unwrap(),
            Some(6)
        );
    }

    #[test]
    fn parse_set_response_skips_request_frame() {
        // Our own SET request is not a response; the parser skips it (Ok(None))
        // so the receive loop keeps waiting instead of aborting on a stray frame.
        let req = set_name_request(&S, &D, X, "x");
        assert_eq!(parse_set_response(&req, X).unwrap(), None);
    }

    #[test]
    fn parse_set_response_skips_foreign_xid() {
        // A valid SET response, but to a different transaction: not ours.
        assert_eq!(
            parse_set_response(&set_response_frame(0x00), X ^ 0xff).unwrap(),
            None
        );
    }

    #[test]
    fn parse_dcp_xid_reads_transaction_id() {
        assert_eq!(parse_dcp_xid(&set_response_frame(0x00)), Some(X));
        assert_eq!(parse_dcp_xid(&[0u8; 4]), None); // too short
    }

    #[test]
    fn block_error_names_cover_known_and_unknown() {
        assert_eq!(block_error_name(0x00), "OK");
        assert_eq!(block_error_name(0x06), "In operation, SET not possible");
        assert_eq!(block_error_name(0x99), "Unknown error (0x99)");
    }
}

// ---------------------------------------------------------------------------
// Ports of profinet-py tests/test_dcp.py. The Python tests feed raw block
// dicts to DCPDeviceDescription; here the same block payloads are wrapped in
// an Identify response frame (with a BlockInfo status word, as on the wire)
// and run through parse_identify_response. SET-response tests reuse the
// frame layout of the reference's _build_dcp_set_response helper.
// ---------------------------------------------------------------------------

mod py_parity {
    use profinet_rs::dcp::*;
    use profinet_rs::util::{mac2s, s2ip};

    const MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const XID: u32 = 0x01020304;

    /// Response block: option ++ suboption ++ length (incl. status word) ++
    /// status ++ payload, padded to 2-byte alignment.
    fn blk(option: u8, suboption: u8, status: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![option, suboption];
        out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&status.to_be_bytes());
        out.extend_from_slice(payload);
        if out.len() % 2 == 1 {
            out.push(0x00);
        }
        out
    }

    fn identify_frame(src: &[u8; 6], blocks: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&MAC); // dst: us
        frame.extend_from_slice(src); // src: device
        frame.extend_from_slice(&PROFINET_ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(&DCP_IDENTIFY_RESPONSE_FRAME_ID.to_be_bytes());
        frame.push(DCP_SERVICE_ID_IDENTIFY);
        frame.push(DCP_SERVICE_TYPE_RESPONSE_SUCCESS);
        frame.extend_from_slice(&XID.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes()); // resp
        frame.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
        frame.extend_from_slice(blocks);
        frame
    }

    fn parse(blocks: &[Vec<u8>]) -> DcpDevice {
        let joined = blocks.concat();
        parse_identify_response(&identify_frame(&MAC, &joined)).expect("parse identify response")
    }

    // test_basic_creation
    #[test]
    fn basic_creation() {
        let device = parse(&[
            blk(0x02, 0x02, 0x0000, b"test-device"),
            blk(
                0x01,
                0x02,
                0x0000,
                b"\xc0\xa8\x01\x01\xff\xff\xff\x00\xc0\xa8\x01\xfe",
            ),
            blk(0x02, 0x03, 0x0000, &[0x00, 0x2a, 0x00, 0x01]),
        ]);
        assert_eq!(mac2s(&device.mac), "00:11:22:33:44:55");
        assert_eq!(device.name, "test-device");
        assert_eq!(s2ip(&device.ip).unwrap(), "192.168.1.1");
        assert_eq!(s2ip(&device.netmask).unwrap(), "255.255.255.0");
        assert_eq!(s2ip(&device.gateway).unwrap(), "192.168.1.254");
        assert_eq!(device.vendor_id, 0x002A);
        assert_eq!(device.device_id, 0x0001);
    }

    // test_missing_name
    #[test]
    fn missing_name_defaults_empty() {
        let device = parse(&[blk(
            0x01,
            0x02,
            0x0000,
            b"\xc0\xa8\x01\x01\xff\xff\xff\x00\x00\x00\x00\x00",
        )]);
        assert_eq!(device.name, "");
    }

    // test_missing_ip
    #[test]
    fn missing_ip_defaults_zero() {
        let device = parse(&[blk(0x02, 0x02, 0x0000, b"test-device")]);
        assert_eq!(s2ip(&device.ip).unwrap(), "0.0.0.0");
        assert_eq!(s2ip(&device.netmask).unwrap(), "0.0.0.0");
        assert_eq!(s2ip(&device.gateway).unwrap(), "0.0.0.0");
    }

    // test_missing_device_id
    #[test]
    fn missing_device_id_defaults_zero() {
        let device = parse(&[blk(0x02, 0x02, 0x0000, b"test-device")]);
        assert_eq!(device.vendor_id, 0);
        assert_eq!(device.device_id, 0);
    }

    // test_vendor_id_property
    #[test]
    fn vendor_and_device_id_split() {
        let device = parse(&[blk(0x02, 0x03, 0x0000, &[0x02, 0xb8, 0x00, 0x42])]);
        assert_eq!(device.vendor_id, 0x02B8);
        assert_eq!(device.device_id, 0x0042);
    }

    // test_device_type_parsing
    #[test]
    fn device_type_parsed() {
        let device = parse(&[
            blk(0x02, 0x02, 0x0000, b"test-device"),
            blk(0x02, 0x01, 0x0000, b"S7-1200"),
        ]);
        assert_eq!(device.device_type, "S7-1200");
    }

    // test_device_type_with_null_terminator
    #[test]
    fn device_type_null_terminator_stripped() {
        let device = parse(&[blk(0x02, 0x01, 0x0000, b"ET 200SP\x00\x00\x00")]);
        assert_eq!(device.device_type, "ET 200SP");
    }

    // test_device_role_io_device
    #[test]
    fn device_role_io_device() {
        let device = parse(&[blk(0x02, 0x04, 0x0000, &[0x01, 0x00])]);
        assert_eq!(device.role, 0x01);
    }

    // test_device_role_io_controller
    #[test]
    fn device_role_io_controller() {
        let device = parse(&[blk(0x02, 0x04, 0x0000, &[0x02, 0x00])]);
        assert_eq!(device.role, 0x02);
    }

    // test_device_role_combined
    #[test]
    fn device_role_combined() {
        let device = parse(&[blk(0x02, 0x04, 0x0000, &[0x03, 0x00])]);
        assert_eq!(device.role, 0x03);
    }

    // test_raw_blocks_unknown_option, adapted: Rust has no raw_blocks store,
    // so the equivalent guarantee is that a vendor-specific block is skipped
    // without disturbing the known fields.
    #[test]
    fn unknown_vendor_block_ignored() {
        let device = parse(&[
            blk(0x02, 0x02, 0x0000, b"test-device"),
            blk(0x80, 0x01, 0x0000, b"\xde\xad\xbe\xef"),
        ]);
        assert_eq!(device.name, "test-device");
        assert_eq!(device.vendor_id, 0);
    }

    // test_reserved_option_blocks_in_raw_blocks, adapted the same way for
    // option 0x04 (Reserved / LLDP).
    #[test]
    fn reserved_option_block_ignored() {
        let device = parse(&[
            blk(0x02, 0x02, 0x0000, b"test-device"),
            blk(0x04, 0x05, 0x0000, b"switch-01\x00"),
        ]);
        assert_eq!(device.name, "test-device");
    }

    // test_full_siemens_device (device_instance has no Rust field; its block
    // plus Device/Options must still be skipped cleanly).
    #[test]
    fn full_siemens_device() {
        let src: [u8; 6] = [0x28, 0x63, 0x36, 0x80, 0xb1, 0xf4];
        let blocks = [
            blk(0x02, 0x02, 0x0000, b"plcxb1d0ed"),
            blk(0x02, 0x01, 0x0000, b"S7-1200"),
            blk(
                0x01,
                0x02,
                0x0000,
                b"\xc0\xa8\x00\xd7\xff\xff\xff\x00\xc0\xa8\x00\x01",
            ),
            blk(0x02, 0x03, 0x0000, &[0x00, 0x2a, 0x01, 0x0d]),
            blk(0x02, 0x04, 0x0000, &[0x02, 0x00]),
            blk(0x02, 0x07, 0x0000, &[0x00, 0x64]),
            blk(0x02, 0x05, 0x0000, &[0x02, 0x07]),
        ]
        .concat();
        let device = parse_identify_response(&identify_frame(&src, &blocks)).expect("parse");
        assert_eq!(mac2s(&device.mac), "28:63:36:80:b1:f4");
        assert_eq!(device.name, "plcxb1d0ed");
        assert_eq!(device.device_type, "S7-1200");
        assert_eq!(s2ip(&device.ip).unwrap(), "192.168.0.215");
        assert_eq!(device.vendor_id, 0x002A);
        assert_eq!(device.device_id, 0x010D);
        assert_eq!(device.role, 0x02);
    }

    // test_ip_block_with_block_info_prefix / _conflict / _dhcp, adapted: the
    // BlockInfo word is the on-wire status; whatever its value (IP_SET,
    // IP_SET_CONFLICT, IP_SET_BY_DHCP), the address triple must still parse.
    #[test]
    fn ip_block_info_variants_still_parse() {
        for status in [0x0001u16, 0x0081, 0x0002] {
            let device = parse(&[blk(
                0x01,
                0x02,
                status,
                b"\xc0\xa8\x01\x01\xff\xff\xff\x00\xc0\xa8\x01\xfe",
            )]);
            assert_eq!(
                s2ip(&device.ip).unwrap(),
                "192.168.1.1",
                "status {status:#06x}"
            );
            assert_eq!(s2ip(&device.netmask).unwrap(), "255.255.255.0");
            assert_eq!(s2ip(&device.gateway).unwrap(), "192.168.1.254");
        }
    }

    /// SET response frame with the exact layout of the reference test helper
    /// _build_dcp_set_response: Control/Response block (option 0x05,
    /// suboption 0x04, length 3) whose payload is option-for-response ++
    /// suboption-for-response ++ block_error ++ pad.
    fn set_response_frame(
        block_error: u8,
        resp_option: u8,
        resp_suboption: u8,
        service_type: u8,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&MAC); // dst: us
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src: device
        frame.extend_from_slice(&PROFINET_ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(&DCP_GET_SET_FRAME_ID.to_be_bytes());
        frame.push(DCP_SERVICE_ID_SET);
        frame.push(service_type);
        frame.extend_from_slice(&1u32.to_be_bytes()); // xid
        frame.extend_from_slice(&0u16.to_be_bytes()); // resp
        let block = [
            0x05,
            0x04,
            0x00,
            0x03,
            resp_option,
            resp_suboption,
            block_error,
            0x00,
        ];
        frame.extend_from_slice(&(block.len() as u16).to_be_bytes());
        frame.extend_from_slice(&block);
        frame
    }

    // test_signal_device_success / test_reset_to_factory_success: a
    // Control/Response block with error 0x00 means success.
    #[test]
    fn set_response_control_success() {
        let frame = set_response_frame(0x00, 0x05, 0x03, DCP_SERVICE_TYPE_RESPONSE_SUCCESS);
        assert_eq!(
            parse_set_response(&frame, 1).unwrap(),
            Some(DCP_BLOCK_ERROR_OK)
        );
    }

    // test_set_ip_success
    #[test]
    fn set_ip_response_success() {
        let frame = set_response_frame(0x00, 0x01, 0x02, DCP_SERVICE_TYPE_RESPONSE_SUCCESS);
        assert_eq!(
            parse_set_response(&frame, 1).unwrap(),
            Some(DCP_BLOCK_ERROR_OK)
        );
    }

    // test_set_ip_error_response (block_error 0x05 = SET not possible; the
    // Rust parser returns the code, raising is the caller's job)
    #[test]
    fn set_ip_response_set_not_possible() {
        let frame = set_response_frame(0x05, 0x01, 0x02, DCP_SERVICE_TYPE_RESPONSE_SUCCESS);
        let code = parse_set_response(&frame, 1).unwrap().unwrap();
        assert_eq!(code, DCP_BLOCK_ERROR_SET_NOT_POSSIBLE);
        assert!(block_error_name(code).contains("SET not possible"));
    }

    // test_set_param_error_response / _option_unsupported / _resource_error /
    // _in_operation
    #[test]
    fn set_param_response_error_codes() {
        for (code, expected) in [
            (0x01u8, "Option not supported"),
            (0x02, "Suboption not supported"),
            (0x04, "Resource error"),
            (0x06, "In operation"),
        ] {
            let frame = set_response_frame(code, 0x02, 0x02, DCP_SERVICE_TYPE_RESPONSE_SUCCESS);
            assert_eq!(parse_set_response(&frame, 1).unwrap(), Some(code));
            assert!(
                block_error_name(code).contains(expected),
                "code {code:#04x}: {}",
                block_error_name(code)
            );
        }
    }

    // test_set_param_unsupported_service_type
    #[test]
    fn set_response_unsupported_service_type() {
        let frame = set_response_frame(0x00, 0x02, 0x02, DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED);
        let err = parse_set_response(&frame, 1).unwrap_err();
        assert!(err.contains("not supported"), "got: {err}");
    }

    // test_reset_modes_defined
    #[test]
    fn reset_mode_constants() {
        assert_eq!(RESET_MODE_COMMUNICATION, 0x0002);
        assert_eq!(RESET_MODE_APPLICATION, 0x0004);
        assert_eq!(RESET_MODE_FACTORY, 0x0040);
    }

    // test_multicast_address
    #[test]
    fn multicast_mac_constant() {
        assert_eq!(mac2s(&DCP_MULTICAST_MAC), "01:0e:cf:00:00:00");
    }

    // test_max_name_length_value
    #[test]
    fn max_name_length_constant() {
        assert_eq!(DCP_MAX_NAME_LENGTH, 240);
    }

    // TestDCPBlockErrorConstants: constant values plus the name table.
    #[test]
    fn block_error_constants_and_names() {
        assert_eq!(DCP_BLOCK_ERROR_OK, 0x00);
        assert_eq!(DCP_BLOCK_ERROR_OPTION_UNSUPPORTED, 0x01);
        assert_eq!(DCP_BLOCK_ERROR_SUBOPTION_UNSUPPORTED, 0x02);
        assert_eq!(DCP_BLOCK_ERROR_SUBOPTION_NOT_SET, 0x03);
        assert_eq!(DCP_BLOCK_ERROR_RESOURCE, 0x04);
        assert_eq!(DCP_BLOCK_ERROR_SET_NOT_POSSIBLE, 0x05);
        assert_eq!(DCP_BLOCK_ERROR_IN_OPERATION, 0x06);
        assert_eq!(block_error_name(0x00), "OK");
        assert!(block_error_name(0x01).contains("Option not supported"));
        assert!(block_error_name(0x02).contains("Suboption not supported"));
        assert!(block_error_name(0x03).contains("Suboption not set"));
        assert!(block_error_name(0x04).contains("Resource error"));
        assert!(block_error_name(0x05).contains("SET not possible"));
        assert!(block_error_name(0x06).contains("In operation"));
    }
}

// ---------------------------------------------------------------------------
// Ports of profinet-py tests/test_protocol.py DCP constant tests
// (TestPNDCPHeader::test_dcp_header_constants, TestPNDCPHeaderExtended-
// Constants, TestPNDCPBlock::test_dcp_block_constants, TestPNDCPBlock-
// ExtendedConstants). The PNDCPHeader/PNDCPBlock parse and roundtrip tests
// are not ported one-to-one: Rust parses DCP only as complete frames, which
// the golden and hand-built frame tests above already cover.
// ---------------------------------------------------------------------------

mod py_parity_constants {
    use profinet_rs::dcp::{
        DCP_OPTION_ALL, DCP_OPTION_DEVICE, DCP_OPTION_IP, DCP_SERVICE_ID_GET, DCP_SERVICE_ID_HELLO,
        DCP_SERVICE_ID_IDENTIFY, DCP_SERVICE_ID_SET, DCP_SERVICE_TYPE_REQUEST,
        DCP_SERVICE_TYPE_RESPONSE_SUCCESS, DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED,
        DCP_SUBOPTION_DEVICE_ALIAS, DCP_SUBOPTION_DEVICE_ID, DCP_SUBOPTION_DEVICE_INSTANCE,
        DCP_SUBOPTION_DEVICE_NAME, DCP_SUBOPTION_DEVICE_OPTIONS, DCP_SUBOPTION_DEVICE_ROLE,
        DCP_SUBOPTION_DEVICE_TYPE, DCP_SUBOPTION_IP_FULL_SUITE, DCP_SUBOPTION_IP_MAC,
        DCP_SUBOPTION_IP_PARAMETER,
    };

    // TestPNDCPHeader::test_dcp_header_constants + extended constants
    #[test]
    fn dcp_service_constants() {
        assert_eq!(DCP_SERVICE_ID_IDENTIFY, 0x05);
        assert_eq!(DCP_SERVICE_ID_GET, 0x03);
        assert_eq!(DCP_SERVICE_ID_SET, 0x04);
        assert_eq!(DCP_SERVICE_ID_HELLO, 6);
        assert_eq!(DCP_SERVICE_TYPE_REQUEST, 0x00);
        assert_eq!(DCP_SERVICE_TYPE_RESPONSE_SUCCESS, 0x01);
        assert_eq!(DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED, 5);
    }

    // TestPNDCPBlock::test_dcp_block_constants + TestPNDCPBlockExtended-
    // Constants::test_all_block_constants ((option, suboption) pairs)
    #[test]
    fn dcp_block_option_constants() {
        assert_eq!((DCP_OPTION_IP, DCP_SUBOPTION_IP_MAC), (1, 1));
        assert_eq!((DCP_OPTION_IP, DCP_SUBOPTION_IP_PARAMETER), (1, 2));
        assert_eq!((DCP_OPTION_IP, DCP_SUBOPTION_IP_FULL_SUITE), (1, 3));
        assert_eq!((DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_TYPE), (2, 1));
        assert_eq!((DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_NAME), (2, 2));
        assert_eq!((DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_ID), (2, 3));
        assert_eq!((DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_ROLE), (2, 4));
        assert_eq!((DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_OPTIONS), (2, 5));
        assert_eq!((DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_ALIAS), (2, 6));
        assert_eq!((DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_INSTANCE), (2, 7));
        assert_eq!(DCP_OPTION_ALL, 0xFF);
    }
}

#[test]
fn golden_set_name_request_permanent() {
    // BlockQualifier bit 0 asks the device to keep the name across a power
    // cycle; without it the name is temporary.
    assert_eq!(
        hex::encode(set_name_request_qualified(
            &SRC_MAC, &DST_MAC, XID, "device", true
        )),
        golden_hex("dcp_set_name_request_permanent")
    );
}

#[test]
fn dcp_data_length_matches_the_bytes_actually_sent() {
    // DCPDataLength counts the pad byte an odd-length block carries. Declaring
    // it without appending it left the frame one byte shorter than announced,
    // which a device is entitled to reject — and this is the case that hits
    // every station name with an odd number of characters.
    for name in ["device", "plc-1", "a", "ab"] {
        let frame = set_name_request(&SRC_MAC, &DST_MAC, XID, name);
        // Ethernet(14) + frame id(2) + service id(1) + type(1) + xid(4)
        // + reserved(2) = 24, then the 2-byte DCPDataLength.
        let declared = u16::from_be_bytes([frame[24], frame[25]]) as usize;
        assert_eq!(
            declared,
            frame.len() - 26,
            "name {name:?}: DCPDataLength {declared} but {} bytes follow",
            frame.len() - 26
        );
        // Odd values are padded to an even block length.
        assert_eq!(declared % 2, 0, "name {name:?}: block length must be even");
    }
}
