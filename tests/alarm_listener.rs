//! Ports of profinet-py tests/test_alarm_listener.py against the Rust
//! `alarm_listener` module. The Rust listener removes callbacks by id (boxed
//! closures have no function identity) and exposes `callback_count()` in place
//! of the reference's `_callbacks` list; `endpoint` and `controller_mac` are
//! public fields. The Python `_running = True` poke has no Rust equivalent
//! (the flag is a private atomic set only by start/stop, exercised by the
//! env-gated live test in diag_alarms.rs), so is_running is checked on a fresh
//! listener only.

use profinet_rs::alarm_listener::{
    build_nack_frame, build_transport_ack_frame, AlarmEndpoint, AlarmListener, RtaAction,
    RtaHeader, RtaSequencer, ADD_FLAGS_TACK, ADD_FLAGS_WINDOW_1, FRAME_ID_ALARM_HIGH,
    FRAME_ID_ALARM_LOW, SEQ_NUM_INIT, SEQ_NUM_INIT_O,
};
use profinet_rs::util::skip_vlan_tags;

fn endpoint() -> AlarmEndpoint {
    AlarmEndpoint {
        interface: "lo".to_string(),
        controller_ref: 1,
        device_ref: 42,
        device_mac: [0u8; 6],
        transport: 0,
        ..Default::default()
    }
}

// --- TestAlarmEndpoint -------------------------------------------------------

#[test]
fn endpoint_default_transport() {
    // Layer 2 (transport 0) is the conventional default.
    let ep = AlarmEndpoint {
        interface: "eth0".to_string(),
        controller_ref: 1,
        device_ref: 42,
        device_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        transport: 0,
        ..Default::default()
    };
    assert_eq!(ep.transport, 0);
}

#[test]
fn endpoint_defaults_match_the_reference() {
    // The negotiated retransmit parameters default as the reference does:
    // RTATimeoutFactor 1 (x100 ms) and three retries.
    let ep = AlarmEndpoint::default();
    assert_eq!(ep.transport, 0);
    assert_eq!(ep.rta_timeout_factor, 1);
    assert_eq!(ep.rta_retries, 3);
}

#[test]
fn endpoint_all_fields() {
    let ep = AlarmEndpoint {
        interface: "eth0".to_string(),
        controller_ref: 100,
        device_ref: 200,
        device_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        transport: 1, // UDP
        ..Default::default()
    };
    assert_eq!(ep.interface, "eth0");
    assert_eq!(ep.controller_ref, 100);
    assert_eq!(ep.device_ref, 200);
    assert_eq!(ep.device_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(ep.transport, 1);
}

// --- TestAlarmListener -------------------------------------------------------

#[test]
fn listener_init() {
    let ep = endpoint();
    let listener = AlarmListener::new(ep.clone(), None);
    assert_eq!(listener.endpoint, ep);
    assert!(!listener.is_running());
    assert_eq!(listener.callback_count(), 0);
}

#[test]
fn listener_add_callback() {
    let mut listener = AlarmListener::new(endpoint(), None);
    listener.add_callback(|_alarm| {});
    assert_eq!(listener.callback_count(), 1);
}

#[test]
fn listener_remove_callback() {
    let mut listener = AlarmListener::new(endpoint(), None);
    let id = listener.add_callback(|_alarm| {});
    listener.remove_callback(id);
    assert_eq!(listener.callback_count(), 0);
}

#[test]
fn listener_remove_nonexistent_callback() {
    let mut listener = AlarmListener::new(endpoint(), None);
    // Removing an unknown id must not panic and leaves the set unchanged.
    listener.remove_callback(999);
    assert_eq!(listener.callback_count(), 0);
}

#[test]
fn listener_is_running_property() {
    // A fresh listener is not running (the running transition is covered by
    // the env-gated live listener test).
    let listener = AlarmListener::new(endpoint(), None);
    assert!(!listener.is_running());
}

#[test]
fn listener_controller_mac_default() {
    let listener = AlarmListener::new(endpoint(), None);
    assert_eq!(listener.controller_mac, [0u8; 6]);
}

#[test]
fn listener_controller_mac_custom() {
    let custom = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let listener = AlarmListener::new(endpoint(), Some(custom));
    assert_eq!(listener.controller_mac, custom);
}

// --- TestFrameIDConstants ----------------------------------------------------

#[test]
fn frame_id_alarm_high() {
    assert_eq!(FRAME_ID_ALARM_HIGH, 0xFC01);
}

#[test]
fn frame_id_alarm_low() {
    assert_eq!(FRAME_ID_ALARM_LOW, 0xFE01);
}

// ---------------------------------------------------------------------------
// RTA transport rules (pure state machine, no device needed)
// ---------------------------------------------------------------------------

fn data_pdu(send_seq: u16, ack_seq: u16, add_flags: u8) -> RtaHeader {
    RtaHeader {
        alarm_dst_endpoint: 1,
        alarm_src_endpoint: 42,
        pdu_type: RtaHeader::encode_pdu_type(RtaHeader::VERSION_1, RtaHeader::RTA_TYPE_DATA),
        add_flags,
        send_seq_num: send_seq,
        ack_seq_num: ack_seq,
        var_part_len: 0,
    }
}

fn pdu_of_kind(kind: u8, ack_seq: u16) -> RtaHeader {
    RtaHeader {
        pdu_type: RtaHeader::encode_pdu_type(RtaHeader::VERSION_1, kind),
        ack_seq_num: ack_seq,
        ..data_pdu(0, 0, ADD_FLAGS_WINDOW_1)
    }
}

#[test]
fn pdu_type_nibbles_are_version_high_type_low() {
    // Both orderings encode DATA/v1 as 0x11, which is why a swapped encoding
    // worked for exactly that one combination and nothing else.
    let data_v1 = RtaHeader::encode_pdu_type(RtaHeader::VERSION_1, RtaHeader::RTA_TYPE_DATA);
    assert_eq!(data_v1, 0x11);
    let ack_v1 = RtaHeader::encode_pdu_type(RtaHeader::VERSION_1, RtaHeader::RTA_TYPE_ACK);
    assert_eq!(ack_v1, 0x13);
    let header = RtaHeader {
        pdu_type: ack_v1,
        ..data_pdu(0, 0, 0)
    };
    assert_eq!(header.kind(), RtaHeader::RTA_TYPE_ACK);
    assert_eq!(header.version(), RtaHeader::VERSION_1);
}

#[test]
fn sequencer_starts_at_the_reference_values() {
    let seq = RtaSequencer::new();
    assert_eq!(seq.send_seq_num(), SEQ_NUM_INIT);
    assert_eq!(seq.ack_seq_pair(), (SEQ_NUM_INIT_O, SEQ_NUM_INIT_O));
}

#[test]
fn in_sequence_data_is_accepted_and_advances_the_counters() {
    let mut seq = RtaSequencer::new();
    let action = seq.on_pdu(&data_pdu(
        SEQ_NUM_INIT,
        0,
        ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
    ));
    assert_eq!(action, RtaAction::Accept);
    // The next transport ack reports the PDU just accepted.
    assert_eq!(seq.ack_seq_pair().1, SEQ_NUM_INIT);
}

#[test]
fn a_retransmitted_data_pdu_is_reacked_not_reprocessed() {
    let mut seq = RtaSequencer::new();
    let pdu = data_pdu(SEQ_NUM_INIT, 0, ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK);
    assert_eq!(seq.on_pdu(&pdu), RtaAction::Accept);
    // Same sequence number again: the device did not see our ack. Acking it a
    // second time is right; delivering the alarm twice is not.
    assert_eq!(seq.on_pdu(&pdu), RtaAction::ReAck);
}

#[test]
fn an_out_of_sequence_data_pdu_is_nacked() {
    let mut seq = RtaSequencer::new();
    assert_eq!(
        seq.on_pdu(&data_pdu(0x0005, 0, ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK)),
        RtaAction::SendNack
    );
}

#[test]
fn a_data_pdu_without_tack_is_ignored() {
    let mut seq = RtaSequencer::new();
    assert_eq!(
        seq.on_pdu(&data_pdu(SEQ_NUM_INIT, 0, ADD_FLAGS_WINDOW_1)),
        RtaAction::Ignore
    );
}

#[test]
fn another_protocol_version_is_ignored() {
    let mut seq = RtaSequencer::new();
    let header = RtaHeader {
        pdu_type: RtaHeader::encode_pdu_type(RtaHeader::VERSION_2, RtaHeader::RTA_TYPE_DATA),
        ..data_pdu(SEQ_NUM_INIT, 0, ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK)
    };
    assert_eq!(seq.on_pdu(&header), RtaAction::Ignore);
}

#[test]
fn a_transport_ack_for_our_data_clears_it_and_advances_the_send_counter() {
    let mut seq = RtaSequencer::new();
    assert_eq!(
        seq.on_pdu(&pdu_of_kind(RtaHeader::RTA_TYPE_ACK, SEQ_NUM_INIT)),
        RtaAction::OurDataAcked
    );
    // 0xFFFF + 1 wraps modulo 0x8000, so the next PDU we send is 0.
    assert_eq!(seq.send_seq_num(), 0);
    assert_eq!(seq.ack_seq_pair().0, SEQ_NUM_INIT);
}

#[test]
fn a_stale_transport_ack_changes_nothing() {
    let mut seq = RtaSequencer::new();
    assert_eq!(
        seq.on_pdu(&pdu_of_kind(RtaHeader::RTA_TYPE_ACK, 0x0007)),
        RtaAction::Ignore
    );
    assert_eq!(seq.send_seq_num(), SEQ_NUM_INIT);
}

#[test]
fn nack_and_err_are_reported_not_parsed_as_alarms() {
    let mut seq = RtaSequencer::new();
    assert_eq!(
        seq.on_pdu(&pdu_of_kind(RtaHeader::RTA_TYPE_NACK, 0)),
        RtaAction::DeviceNack
    );
    assert_eq!(
        seq.on_pdu(&pdu_of_kind(RtaHeader::RTA_TYPE_ERR, 0)),
        RtaAction::DeviceError
    );
}

#[test]
fn a_data_pdu_may_piggyback_the_ack_for_our_last_one() {
    let mut seq = RtaSequencer::new();
    let pdu = data_pdu(
        SEQ_NUM_INIT,
        SEQ_NUM_INIT,
        ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
    );
    assert_eq!(seq.on_pdu(&pdu), RtaAction::Accept);
    assert_eq!(seq.send_seq_num(), 0, "send counter should have advanced");
}

#[test]
fn transport_ack_and_nack_frames_carry_no_variable_part() {
    let ep = endpoint();
    let seq = RtaSequencer::new();
    let (send_seq, ack_seq) = seq.ack_seq_pair();
    for (frame, kind) in [
        (
            build_transport_ack_frame(&ep, &[0x11; 6], send_seq, ack_seq, false),
            RtaHeader::RTA_TYPE_ACK,
        ),
        (
            build_nack_frame(&ep, &[0x11; 6], send_seq, ack_seq, false),
            RtaHeader::RTA_TYPE_NACK,
        ),
    ] {
        let at = skip_vlan_tags(&frame) + 2 + 2;
        let header = RtaHeader::from_bytes(&frame[at..]).expect("RTA header");
        assert_eq!(header.kind(), kind);
        assert_eq!(header.version(), RtaHeader::VERSION_1);
        assert_eq!(header.var_part_len, 0);
        assert_eq!(header.send_seq_num, send_seq);
        assert_eq!(header.ack_seq_num, ack_seq);
        assert_eq!(frame.len(), at + RtaHeader::SIZE);
    }
}
