//! Ports of profinet-py tests/test_alarm_listener.py against the Rust
//! `alarm_listener` module. The Rust listener removes callbacks by id (boxed
//! closures have no function identity) and exposes `callback_count()` in place
//! of the reference's `_callbacks` list; `endpoint` and `controller_mac` are
//! public fields. The Python `_running = True` poke has no Rust equivalent
//! (the flag is a private atomic set only by start/stop, exercised by the
//! env-gated live test in diag_alarms.rs), so is_running is checked on a fresh
//! listener only.

use profinet_rs::alarm_listener::{
    AlarmEndpoint, AlarmListener, FRAME_ID_ALARM_HIGH, FRAME_ID_ALARM_LOW,
};

fn endpoint() -> AlarmEndpoint {
    AlarmEndpoint {
        interface: "lo".to_string(),
        controller_ref: 1,
        device_ref: 42,
        device_mac: [0u8; 6],
        transport: 0,
    }
}

// --- TestAlarmEndpoint -------------------------------------------------------

#[test]
fn endpoint_default_transport() {
    // Layer 2 (transport 0) is the conventional default; the Rust struct has
    // no field default, so this asserts the value the reference defaults to.
    let ep = AlarmEndpoint {
        interface: "eth0".to_string(),
        controller_ref: 1,
        device_ref: 42,
        device_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        transport: 0,
    };
    assert_eq!(ep.transport, 0);
}

#[test]
fn endpoint_all_fields() {
    let ep = AlarmEndpoint {
        interface: "eth0".to_string(),
        controller_ref: 100,
        device_ref: 200,
        device_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        transport: 1, // UDP
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
