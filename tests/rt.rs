//! Golden byte-fidelity tests for the RT_CLASS_1 framing module, asserting
//! byte-for-byte equality against vectors generated from the Python
//! reference (tools/gen_golden.py -> tests/golden/foundation.json).

use profinet_rs::rt::{
    build_ethernet_frame, parse_ethernet_frame, CyclicDataBuilder, IoDataObject, IocrConfig,
    RtFrame, DATA_STATUS_PROVIDER_RUN, DATA_STATUS_STATE, DATA_STATUS_STATION_OK,
    DATA_STATUS_VALID, IOCR_TYPE_INPUT, IOCR_TYPE_OUTPUT, IOXS_GOOD,
};

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

fn input_frame() -> RtFrame {
    RtFrame {
        frame_id: 0xC001,
        cycle_counter: 0x1234,
        data_status: DATA_STATUS_VALID
            | DATA_STATUS_PROVIDER_RUN
            | DATA_STATUS_STATION_OK
            | DATA_STATUS_STATE,
        transfer_status: 0x00,
        payload: (0..40).collect(),
    }
}

fn output_frame() -> RtFrame {
    RtFrame {
        frame_id: 0xC000,
        cycle_counter: 0x0001,
        data_status: DATA_STATUS_VALID | DATA_STATUS_PROVIDER_RUN,
        transfer_status: 0x00,
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }
}

#[test]
fn golden_rt_frame_c001() {
    assert_eq!(
        hex::encode(input_frame().to_bytes()),
        golden_hex("rt_frame_c001")
    );
}

#[test]
fn golden_rt_frame_c000_small() {
    assert_eq!(
        hex::encode(output_frame().to_bytes()),
        golden_hex("rt_frame_c000_small")
    );
}

#[test]
fn golden_rt_ethernet_frame() {
    let dst = [0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F];
    let src = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    assert_eq!(
        hex::encode(build_ethernet_frame(&dst, &src, &input_frame())),
        golden_hex("rt_ethernet_frame_c001")
    );
}

#[test]
fn round_trip() {
    for frame in [input_frame(), output_frame()] {
        assert_eq!(RtFrame::from_bytes(&frame.to_bytes()).unwrap(), frame);
    }
}

#[test]
fn ethernet_round_trip() {
    let frame = input_frame();
    let eth = build_ethernet_frame(&[0xFF; 6], &[0x11; 6], &frame);
    assert_eq!(parse_ethernet_frame(&eth).unwrap(), frame);
}

#[test]
fn parse_ethernet_rejects_wrong_ethertype() {
    let mut eth = build_ethernet_frame(&[0xFF; 6], &[0x11; 6], &input_frame());
    eth[12] = 0x08;
    eth[13] = 0x00;
    assert!(parse_ethernet_frame(&eth).is_none());
}

#[test]
fn from_bytes_too_short() {
    assert_eq!(
        RtFrame::from_bytes(&[0xC0, 0x01, 0x00, 0x00, 0x14]),
        Err("RT frame too short: 5 bytes".to_string())
    );
}

#[test]
fn from_bytes_minimum_length_has_empty_payload() {
    // 6 bytes = frame_id + trailer, zero-length C_SDU (reference minimum).
    let frame = RtFrame::from_bytes(&[0xC0, 0x00, 0x00, 0x07, 0x35, 0x00]).unwrap();
    assert_eq!(frame.frame_id, 0xC000);
    assert_eq!(frame.cycle_counter, 7);
    assert_eq!(frame.data_status, 0x35);
    assert_eq!(frame.transfer_status, 0);
    assert!(frame.payload.is_empty());
}

#[test]
fn data_status_predicates() {
    let frame = input_frame();
    assert!(frame.is_valid());
    assert!(frame.is_running());
    assert!(frame.is_ok());
    assert!(frame.is_primary());

    let frame = output_frame();
    assert!(frame.is_valid());
    assert!(frame.is_running());
    assert!(!frame.is_ok());
    assert!(!frame.is_primary());

    let idle = RtFrame {
        data_status: 0x00,
        ..output_frame()
    };
    assert!(!idle.is_valid() && !idle.is_running());
}

#[test]
fn iocr_config_defaults_and_timing() {
    let iocr = IocrConfig::new(IOCR_TYPE_INPUT, 1, 0xC001);
    // Reference defaults: 32 * 32 * 31.25us = 32ms cycle, watchdog x3.
    assert_eq!(iocr.send_clock_factor, 32);
    assert_eq!(iocr.reduction_ratio, 32);
    assert_eq!(iocr.watchdog_factor, 3);
    assert_eq!(iocr.data_length, 40);
    assert_eq!(iocr.cycle_time_us(), 32_000);
    assert_eq!(iocr.cycle_time_ms(), 32.0);
    assert_eq!(iocr.watchdog_time_us(), 96_000);
    assert!(iocr.is_input());
    assert!(!iocr.is_output());

    let out = IocrConfig::new(IOCR_TYPE_OUTPUT, 2, 0xC000);
    assert!(out.is_output());
    assert!(!out.is_input());
}

// ---------------------------------------------------------------------------
// Remaining test_rt.py ports (behaviors not already covered above). Several
// Python tests collapse onto existing tests here:
//   - test_to_bytes_roundtrip                     -> round_trip
//   - test_is_valid/is_running/is_ok/is_primary/combined_status
//                                                 -> data_status_predicates
//   - test_is_input                               -> iocr_config_defaults_and_timing
//   - test_build_ethernet_frame/parse_ethernet_frame -> ethernet_round_trip
//   - test_parse_non_profinet_returns_none        -> parse_ethernet_rejects_wrong_ethertype
// Two Python tests have no Rust equivalent and are omitted:
//   - test_repr:  RTFrame's human-readable __repr__ (VALID/RUN/10B) is a Python
//     convenience; RtFrame carries only a derived Debug.
//   - test_concurrent_set_and_build:  set_data takes &mut self, so concurrent
//     access is unrepresentable without external synchronization; the data
//     race the Python test guards against cannot occur by construction.
// ---------------------------------------------------------------------------

fn builder_config(data_length: usize, objects: Vec<IoDataObject>) -> IocrConfig {
    IocrConfig {
        iocr_type: IOCR_TYPE_OUTPUT,
        iocr_reference: 1,
        frame_id: 0xC000,
        send_clock_factor: 32,
        reduction_ratio: 32,
        phase: 0,
        watchdog_factor: 3,
        data_length,
        objects,
    }
}

fn data_object(
    slot: u16,
    subslot: u16,
    frame_offset: usize,
    data_length: usize,
    iops_offset: usize,
) -> IoDataObject {
    IoDataObject {
        slot,
        subslot,
        frame_offset,
        data_length,
        iops_offset,
        iocs_offset: 0,
    }
}

// --- TestRTFrame (byte-layout cases) -----------------------------------------

#[test]
fn rtframe_from_bytes_minimal() {
    // frame_id + 2-byte payload + cycle(2) + status(2).
    let data = [0xC0, 0x00, 0x01, 0x02, 0x12, 0x34, 0xA4, 0x00];
    let frame = RtFrame::from_bytes(&data).unwrap();
    assert_eq!(frame.frame_id, 0xC000);
    assert_eq!(frame.payload, vec![0x01, 0x02]);
    assert_eq!(frame.cycle_counter, 0x1234);
    assert_eq!(frame.data_status, 0xA4);
    assert_eq!(frame.transfer_status, 0x00);
}

#[test]
fn rtframe_from_bytes_typical() {
    // 40-byte payload (minimum C_SDU).
    let mut data = vec![0xC0, 0x01];
    data.extend_from_slice(&[0u8; 40]);
    data.extend_from_slice(&[0x00, 0x42, 0xA4, 0x00]);
    let frame = RtFrame::from_bytes(&data).unwrap();
    assert_eq!(frame.frame_id, 0xC001);
    assert_eq!(frame.payload.len(), 40);
    assert_eq!(frame.cycle_counter, 0x0042);
}

// --- TestIOCRConfig (specific cycle/watchdog values) -------------------------

#[test]
fn iocr_cycle_time_1ms() {
    // 32 * 1 * 31.25us = 1000us = 1ms.
    let config = IocrConfig {
        reduction_ratio: 1,
        ..IocrConfig::new(IOCR_TYPE_OUTPUT, 1, 0xC000)
    };
    assert_eq!(config.cycle_time_us(), 1000);
    assert_eq!(config.cycle_time_ms(), 1.0);
}

#[test]
fn iocr_cycle_time_8ms() {
    let config = IocrConfig {
        reduction_ratio: 8,
        ..IocrConfig::new(IOCR_TYPE_OUTPUT, 1, 0xC000)
    };
    assert_eq!(config.cycle_time_us(), 8000);
    assert_eq!(config.cycle_time_ms(), 8.0);
}

#[test]
fn iocr_watchdog_time() {
    // 3 * 8000us = 24000us.
    let config = IocrConfig {
        reduction_ratio: 8,
        watchdog_factor: 3,
        ..IocrConfig::new(IOCR_TYPE_INPUT, 1, 0xC001)
    };
    assert_eq!(config.watchdog_time_us(), 24000);
}

// --- TestCyclicDataBuilder ---------------------------------------------------

#[test]
fn builder_set_and_get_data() {
    let config = builder_config(48, vec![data_object(1, 1, 0, 8, 8)]);
    let mut builder = CyclicDataBuilder::new(config);
    let test_data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    builder.set_data(1, 1, &test_data).unwrap();
    assert_eq!(builder.get_data(1, 1).unwrap(), test_data);
}

#[test]
fn builder_set_iops() {
    let config = builder_config(16, vec![data_object(1, 1, 0, 4, 4)]);
    let mut builder = CyclicDataBuilder::new(config);
    builder.set_iops(1, 1, IOXS_GOOD);
    builder.swap();
    assert_eq!(builder.build()[4], IOXS_GOOD);
}

#[test]
fn builder_build_returns_correct_length() {
    let mut builder = CyclicDataBuilder::new(builder_config(64, vec![]));
    builder.swap();
    assert_eq!(builder.build().len(), 64);
}

#[test]
fn builder_unknown_slot_raises() {
    let config = builder_config(48, vec![]);
    let mut builder = CyclicDataBuilder::new(config);
    let err = builder.set_data(99, 99, &[0x00]).unwrap_err();
    assert!(
        err.contains("Unknown slot/subslot"),
        "unexpected error: {err}"
    );
}

#[test]
fn builder_set_all_iops() {
    let config = builder_config(
        32,
        vec![data_object(0, 1, 0, 4, 4), data_object(1, 1, 8, 4, 12)],
    );
    let mut builder = CyclicDataBuilder::new(config);
    builder.set_all_iops(IOXS_GOOD);
    builder.swap();
    let payload = builder.build();
    assert_eq!(payload[4], IOXS_GOOD);
    assert_eq!(payload[12], IOXS_GOOD);
}

#[test]
fn builder_clear() {
    let config = builder_config(16, vec![data_object(1, 1, 0, 8, 8)]);
    let mut builder = CyclicDataBuilder::new(config);
    builder.set_data(1, 1, &[0xFF; 8]).unwrap();
    builder.clear();
    builder.swap();
    assert_eq!(builder.build(), vec![0u8; 16]);
}

#[test]
fn builder_load() {
    let config = IocrConfig {
        iocr_type: IOCR_TYPE_INPUT,
        frame_id: 0xC001,
        ..builder_config(16, vec![data_object(1, 1, 0, 8, 8)])
    };
    let mut builder = CyclicDataBuilder::new(config);
    let mut received = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x80];
    received.extend_from_slice(&[0u8; 7]);
    builder.load(&received);
    assert_eq!(
        builder.get_data(1, 1).unwrap(),
        vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );
}

#[test]
fn builder_double_buffer_isolation() {
    // Write-buffer changes don't reach the send buffer until swap.
    let config = builder_config(16, vec![data_object(1, 1, 0, 4, 4)]);
    let mut builder = CyclicDataBuilder::new(config);
    builder.set_data(1, 1, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    builder.swap();

    builder.set_data(1, 1, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    assert_eq!(&builder.build()[0..4], &[0x01, 0x02, 0x03, 0x04]);

    builder.swap();
    assert_eq!(&builder.build()[0..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn builder_swap_skips_when_not_dirty() {
    let config = builder_config(16, vec![data_object(1, 1, 0, 4, 4)]);
    let mut builder = CyclicDataBuilder::new(config);
    builder.set_data(1, 1, &[0x01, 0x02, 0x03, 0x04]).unwrap();
    builder.swap();
    assert!(!builder.is_dirty());
    // A second swap is a no-op (dirty stays clear).
    builder.swap();
    assert!(!builder.is_dirty());
}

// --- TestEthernetFrameHelpers ------------------------------------------------

#[test]
fn ethernet_parse_too_short_returns_none() {
    assert!(parse_ethernet_frame(&[0u8; 10]).is_none());
}
