#!/usr/bin/env python3
"""Golden-byte oracle for the diagnosis + alarms + alarm-listener modules.

Builds reference diagnosis records and alarm frames with profinet-py for
FIXED inputs and dumps them plus the expected parse results to
tests/golden/diag_alarms.json:

- Diagnosis record buffers (hand-assembled in the layouts diagnosis.py's
  parsers expect), parsed with parse_diagnosis_block / parse_diagnosis_simple
  to record the expected entries.
- Decode-table sweeps: decode_channel_error_type,
  decode_ext_channel_error_type, get_usi_name, get_alarm_type_name,
  get_pe_mode_name over representative inputs.
- AlarmNotification PDUs assembled with the protocol.py structs, parsed with
  alarms.parse_alarm_notification to record the expected fields/items.
- PNRTAHeader and PNAlarmAckPDU reference bytes, plus the complete Layer-2
  AlarmAck frame exactly as AlarmListener._send_layer2_ack composes it.

Run with the profinet-py venv active (needs the `construct` dep):
    cd ~/git/profinet-py && . .venv/bin/activate
    python ~/git/profinet-rs/tools/gen_diag_alarm_golden.py
"""

import json
import os
import struct
import sys

sys.path.insert(0, os.path.expanduser("~/git/profinet-py"))

from profinet import indices  # noqa: E402
from profinet.alarms import parse_alarm_notification  # noqa: E402
from profinet.diagnosis import (  # noqa: E402
    decode_channel_error_type,
    decode_ext_channel_error_type,
    parse_diagnosis_block,
    parse_diagnosis_simple,
)
from profinet.protocol import (  # noqa: E402
    PNAlarmAckPDU,
    PNBlockHeader,
    PNRTAHeader,
)

OUT = os.path.join(
    os.path.dirname(__file__), "..", "tests", "golden", "diag_alarms.json"
)

golden = {}


def be16(*vals):
    return b"".join(struct.pack(">H", v) for v in vals)


def be32(*vals):
    return b"".join(struct.pack(">I", v) for v in vals)


# --- Diagnosis entry serialization -------------------------------------------
def dump_props(p):
    return {
        "raw": p.raw,
        "channel_type": int(p.channel_type),
        "accumulative": int(p.accumulative),
        "maintenance_required": p.maintenance_required,
        "maintenance_demanded": p.maintenance_demanded,
        "specifier": int(p.specifier),
        "direction": int(p.direction),
    }


def dump_entry(e):
    out = {
        "kind": type(e).__name__,
        "api": e.api,
        "slot": e.slot,
        "subslot": e.subslot,
        "channel_number": e.channel_number,
        "channel_properties": dump_props(e.channel_properties),
        "error_type": e.error_type,
        "error_type_name": e.error_type_name,
        "is_submodule_level": e.is_submodule_level,
    }
    if hasattr(e, "ext_error_type"):
        out["ext_error_type"] = e.ext_error_type
        out["ext_error_type_name"] = e.ext_error_type_name
        out["ext_add_value"] = e.ext_add_value
    if hasattr(e, "qualifier"):
        out["qualifier"] = e.qualifier
    return out


def dump_diag(d):
    return {
        "api": d.api,
        "slot": d.slot,
        "subslot": d.subslot,
        "has_errors": d.has_errors,
        "has_maintenance_required": d.has_maintenance_required,
        "has_maintenance_demanded": d.has_maintenance_demanded,
        "entries": [dump_entry(e) for e in d.entries],
    }


def diag_case(name, desc, data, api=0, slot=0, subslot=0, simple=False):
    parse = parse_diagnosis_simple if simple else parse_diagnosis_block
    result = parse(data, api=api, slot=slot, subslot=subslot)
    golden[name] = {
        "desc": desc,
        "hex": data.hex(),
        "api": api,
        "slot": slot,
        "subslot": subslot,
        "expected": dump_diag(result),
    }


# ChannelProperties value used in most vectors:
# type=Specific(1), accumulative=MainFault(1<<2), maint_req(1<<5),
# specifier=Appears(1<<8), direction=Input(1<<11) = 0x0925.
PROPS = 0x0925

# Block header 0x0010 (DiagnosisData) + version 0100, then one
# ChannelDiagnosis entry (USI 0x8000).
diag_case(
    "diag_channel_single",
    "DiagnosisData block hdr + one ChannelDiagnosis USI 0x8000 (line break)",
    be16(0x0010, 0x000A, 0x0100)  # block header (type, length, version).
    + be16(0x0001, PROPS, 0x8000, 0x0006),  # ch 1, props, USI, error type.
)

# ExtChannelDiagnosis (USI 0x8002), remote mismatch / no peer detected.
diag_case(
    "diag_ext_channel",
    "block hdr + ExtChannelDiagnosis USI 0x8002 (remote mismatch/no peer)",
    be16(0x0010, 0x0012, 0x0100)
    + be16(0x8000, 0x2005, 0x8002, 0x8001, 0x8005)
    + be32(0xDEADBEEF),
)

# QualifiedChannelDiagnosis (USI 0x8003).
diag_case(
    "diag_qualified_channel",
    "block hdr + QualifiedChannelDiagnosis USI 0x8003 (sync mismatch)",
    be16(0x0010, 0x0016, 0x0100)
    + be16(0x0002, PROPS, 0x8003, 0x8003, 0x8000)
    + be32(0x00001234)
    + be32(0x00080000),
)

# Multiple mixed entries in one buffer (no location header: slot stays 0,
# but the location sniff sees ChannelNumber 0x0001... as API — build entries
# whose leading 8 bytes fail the api<0x10000/slot<0x8000 sniff by using
# channel 0x8001 (accumulative bit) so the "api" dword is >= 0x10000).
diag_case(
    "diag_mixed_entries",
    "block hdr + Channel + Ext entries, channel numbers with bit15 set so "
    "the location-header sniff never fires",
    be16(0x0010, 0x001C, 0x0100)
    + be16(0x8001, PROPS, 0x8000, 0x0001)  # short circuit on ch 0x8001.
    + be16(0x8002, 0x0965, 0x8002, 0x8000, 0x8001)  # ext, maint demanded.
    + be32(0x00000042),
)

# Location header (API/slot/subslot) before the entry, as the reference's
# heuristic expects: api=0, slot=3, subslot=1.
diag_case(
    "diag_with_location_header",
    "block hdr + API/slot/subslot location header + ChannelDiagnosis",
    be16(0x0010, 0x0012, 0x0100)
    + be32(0x00000000)  # API.
    + be16(0x0003, 0x0001)  # slot, subslot.
    + be16(0x8005, PROPS, 0x8000, 0x0010),  # parameterization fault.
)

# Unknown USI: parsed as a basic channel entry from the next 2 bytes.
diag_case(
    "diag_unknown_usi",
    "block hdr + unknown USI 0x9123 falls back to a basic channel entry",
    be16(0x0010, 0x000A, 0x0100) + be16(0x8007, PROPS, 0x9123, 0x0155),
)

# Truncated ext entry: header promises USI 0x8002 but only 4 body bytes.
diag_case(
    "diag_truncated_ext",
    "ext entry truncated after 4 body bytes -> no entries",
    be16(0x0010, 0x000E, 0x0100) + be16(0x8009, PROPS, 0x8002, 0x8001),
)

# Empty and too-short buffers.
diag_case("diag_empty", "empty buffer -> no entries", b"")
diag_case(
    "diag_short",
    "5-byte buffer -> no entries",
    bytes.fromhex("0010000a01"),
    slot=2,
    subslot=1,
)

# No block header: first word is not a known diagnosis block type, so
# parsing starts at offset 0 (channel 0x8123 defeats the location sniff).
diag_case(
    "diag_no_block_header",
    "no block header: entry parsed from offset 0",
    be16(0x8123, PROPS, 0x8000, 0x0009),
)

# Simple format: 6-byte header skipped, then flat 6-byte entries,
# terminated by an all-zero entry.
diag_case(
    "diag_simple",
    "parse_diagnosis_simple: hdr + two flat entries + all-zero terminator",
    be16(0x0010, 0x0010, 0x0100)
    + be16(0x0001, PROPS, 0x0002)
    + be16(0x8000, 0x1865, 0x8001)
    + be16(0x0000, 0x0000, 0x0000)
    + be16(0x0004, PROPS, 0x0005),  # after terminator: must be ignored.
    slot=1,
    subslot=2,
    simple=True,
)


# --- Decode-table sweeps ------------------------------------------------------
error_type_inputs = sorted(
    set(
        list(range(0x0000, 0x0020))
        + [0x0020, 0x00FF, 0x0100, 0x7FFF]
        + list(range(0x8000, 0x800E))
        + [0x800E, 0x8FFF, 0x9000, 0x9500, 0x9501, 0x9502, 0x9FFF, 0xA000, 0xFFFF]
    )
)
golden["decode_channel_error_type"] = {
    "desc": "decode_channel_error_type sweep",
    "cases": [[v, decode_channel_error_type(v)] for v in error_type_inputs],
}

ext_inputs = []
for cet in [0x0006, 0x8000, 0x8001, 0x8002, 0x8003, 0x8007, 0x8008, 0x8009, 0x800B]:
    for ext in [0x0000, 0x0001, 0x7FFF, 0x8000, 0x8001, 0x8005, 0x8009, 0x800A,
                0x8FFF, 0x9000, 0x9FFF, 0xA000, 0xFFFF]:
        ext_inputs.append([cet, ext])
golden["decode_ext_channel_error_type"] = {
    "desc": "decode_ext_channel_error_type sweep",
    "cases": [
        [cet, ext, decode_ext_channel_error_type(cet, ext)] for cet, ext in ext_inputs
    ],
}

usi_inputs = [
    0x0000, 0x1234, 0x7FFF, 0x8000, 0x8001, 0x8002, 0x8003, 0x8004, 0x8100,
    0x8200, 0x8201, 0x8300, 0x8301, 0x8302, 0x8310, 0x8320, 0x9000, 0x9FFF,
    0xA000, 0xFFFF,
]
golden["get_usi_name"] = {
    "desc": "get_usi_name sweep",
    "cases": [[v, indices.get_usi_name(v)] for v in usi_inputs],
}

alarm_type_inputs = list(range(0x0000, 0x0021)) + [0x0100, 0xFFFF]
golden["get_alarm_type_name"] = {
    "desc": "get_alarm_type_name sweep",
    "cases": [[v, indices.get_alarm_type_name(v)] for v in alarm_type_inputs],
}

pe_mode_inputs = [0x00, 0x01, 0x10, 0x1F, 0x20, 0xEF, 0xF0, 0xF1, 0xFE, 0xFF]
golden["get_pe_mode_name"] = {
    "desc": "get_pe_mode_name sweep",
    "cases": [[v, indices.get_pe_mode_name(v)] for v in pe_mode_inputs],
}


# --- AlarmNotification PDUs ---------------------------------------------------
def alarm_pdu(block_type, alarm_type, api, slot, subslot, module_ident,
              submodule_ident, alarm_specifier, payload=b""):
    # The reference consumes a 22-byte body (its 20-byte struct plus 2
    # skipped bytes) before the payload items, so pad accordingly.
    body = (
        be16(alarm_type)
        + be32(api)
        + be16(slot, subslot)
        + be32(module_ident, submodule_ident)
        + be16(alarm_specifier)
        + b"\x00\x00"
        + payload
    )
    hdr = bytes(PNBlockHeader(block_type, len(body) + 2, 0x01, 0x00))
    return hdr + body


def dump_item(item):
    out = {
        "kind": type(item).__name__,
        "user_structure_id": item.user_structure_id,
        "usi_name": item.usi_name,
    }
    for f in (
        "channel_number", "channel_properties", "channel_error_type",
        "ext_channel_error_type", "ext_channel_add_value",
        "qualified_channel_qualifier", "block_type", "block_length",
        "block_version", "maintenance_status", "ur_record_index",
        "ur_record_length", "pe_operational_mode", "rs_alarm_info",
        "pral_channel_properties", "pral_reason", "pral_ext_reason",
    ):
        if hasattr(item, f):
            out[f] = getattr(item, f)
    if hasattr(item, "pral_reason_add_value"):
        out["pral_reason_add_value"] = item.pral_reason_add_value.hex()
    if type(item).__name__ == "AlarmItem":
        out["raw_data"] = item.raw_data.hex()
    if hasattr(item, "maintenance_required"):
        out["props"] = {
            "maintenance_required": item.maintenance_required,
            "maintenance_demanded": item.maintenance_demanded,
        }
    if type(item).__name__ == "DiagnosisItem":
        out["props"] = {
            "channel_number_value": item.channel_number_value,
            "is_accumulative": item.is_accumulative,
            "channel_type": item.channel_type,
            "is_extended": item.is_extended,
            "is_qualified": item.is_qualified,
        }
    return out


def dump_alarm(a):
    return {
        "block_type": a.block_type,
        "block_version": list(a.block_version),
        "alarm_type": a.alarm_type,
        "alarm_type_name": a.alarm_type_name,
        "api": a.api,
        "slot_number": a.slot_number,
        "subslot_number": a.subslot_number,
        "module_ident_number": a.module_ident_number,
        "submodule_ident_number": a.submodule_ident_number,
        "alarm_sequence_number": a.alarm_sequence_number,
        "channel_diagnosis": a.channel_diagnosis,
        "manufacturer_specific": a.manufacturer_specific,
        "submodule_diagnosis_state": a.submodule_diagnosis_state,
        "ar_diagnosis_state": a.ar_diagnosis_state,
        "is_high_priority": a.is_high_priority,
        "is_low_priority": a.is_low_priority,
        "location": a.location,
        "raw_payload": a.raw_payload.hex(),
        "items": [dump_item(i) for i in a.items],
    }


def alarm_case(name, desc, data):
    golden[name] = {
        "desc": desc,
        "hex": data.hex(),
        "expected": dump_alarm(parse_alarm_notification(data)),
    }


# Diagnosis alarm (low priority) with one ChannelDiagnosis item.
alarm_case(
    "alarm_diag_channel",
    "low-prio Diagnosis alarm, one DiagnosisItem USI 0x8000",
    alarm_pdu(
        indices.BLOCK_ALARM_NOTIFICATION_LOW, indices.ALARM_TYPE_DIAGNOSIS,
        0, 1, 1, 0x00000030, 0x00000131,
        0x0800 | 0x0123,  # channel_diagnosis + seq 0x123.
        be16(0x8000, 0x0001, PROPS, 0x0006),
    ),
)

# High-priority process alarm with Ext + Qualified diagnosis items.
alarm_case(
    "alarm_ext_and_qualified",
    "high-prio alarm with Ext (0x8002) and Qualified (0x8003) items",
    alarm_pdu(
        indices.BLOCK_ALARM_NOTIFICATION_HIGH, indices.ALARM_TYPE_PROCESS,
        0, 2, 0x8001, 0x00000042, 0x00000043,
        0x4000 | 0x2000 | 0x0001,
        be16(0x8002, 0x8123, 0x2005, 0x8001, 0x8005) + be32(0x00000007)
        + be16(0x8003, 0x0002, PROPS, 0x8003, 0x8001) + be32(0x00000009)
        + be32(0x12345678),
    ),
)

# Maintenance item (USI 0x8100): BlockHeader + padding + status.
alarm_case(
    "alarm_maintenance",
    "Status alarm with MaintenanceItem USI 0x8100 (demanded)",
    alarm_pdu(
        indices.BLOCK_ALARM_NOTIFICATION_LOW, indices.ALARM_TYPE_STATUS,
        0, 0, 1, 0x00000010, 0x00000011, 0x0002,
        be16(0x8100)
        + bytes(PNBlockHeader(0x0F00, 0x0008, 0x01, 0x00))
        + be16(0x0000)  # padding.
        + be32(0x00000002),  # maintenance demanded.
    ),
)

# Upload & retrieval item (USI 0x8200) and iParameter USI 0x8201 (parsed as
# UploadRetrievalItem, like the reference).
alarm_case(
    "alarm_upload_retrieval",
    "UploadAndRetrieval alarm with USI 0x8200 + 0x8201 items",
    alarm_pdu(
        indices.BLOCK_ALARM_NOTIFICATION_LOW, indices.ALARM_TYPE_UPLOAD_RETRIEVAL,
        0, 0, 1, 0x00000001, 0x00000002, 0x0005,
        be16(0x8200)
        + bytes(PNBlockHeader(0x0900, 0x000C, 0x01, 0x00))
        + be16(0x0000)
        + be32(0x0000E050, 0x00000100)
        + be16(0x8201)
        + bytes(PNBlockHeader(0x0901, 0x000C, 0x01, 0x00))
        + be16(0x0000)
        + be32(0x0000E051, 0x00000200),
    ),
)

# RS alarm items (USI 0x8300/0x8301/0x8302).
alarm_case(
    "alarm_rs",
    "alarm with three RS_AlarmItems (0x8300..0x8302)",
    alarm_pdu(
        indices.BLOCK_ALARM_NOTIFICATION_HIGH, indices.ALARM_TYPE_DIAGNOSIS,
        0, 1, 2, 0x00000003, 0x00000004, 0x0007,
        be16(0x8300, 0x07FF) + be16(0x8301, 0x0801) + be16(0x8302, 0xFFFF),
    ),
)

# PE alarm item (USI 0x8310).
alarm_case(
    "alarm_pe",
    "alarm with PE_AlarmItem USI 0x8310 (EnergySaving mode 0x10)",
    alarm_pdu(
        indices.BLOCK_ALARM_NOTIFICATION_LOW, indices.ALARM_TYPE_STATUS,
        0, 0, 1, 0x00000001, 0x00000001, 0x0009,
        be16(0x8310) + bytes(PNBlockHeader(0x0602, 0x0003, 0x01, 0x00))
        + bytes([0x10]),
    ),
)

# PRAL alarm item (USI 0x8320) with add-value tail.
alarm_case(
    "alarm_pral",
    "Pull alarm with PRAL_AlarmItem USI 0x8320 + add value",
    alarm_pdu(
        indices.BLOCK_ALARM_NOTIFICATION_LOW, indices.ALARM_TYPE_PULL,
        0, 4, 1, 0x00000005, 0x00000006, 0x000B,
        be16(0x8320, 0x0003, 0x0925, 0x0002, 0x0001) + bytes([0xAA, 0xBB]),
    ),
)

# Unknown/manufacturer-specific USI: generic item swallows the rest.
alarm_case(
    "alarm_unknown_usi",
    "alarm with manufacturer-specific USI 0x1234 -> generic item",
    alarm_pdu(
        indices.BLOCK_ALARM_NOTIFICATION_LOW, indices.ALARM_TYPE_PLUG,
        0, 3, 1, 0x00000007, 0x00000008, 0x000D,
        be16(0x1234) + bytes([0x01, 0x02, 0x03]),
    ),
)

# No payload items at all.
alarm_case(
    "alarm_no_items",
    "ReturnOfSubmodule alarm without payload items",
    alarm_pdu(
        indices.BLOCK_ALARM_NOTIFICATION_LOW, indices.ALARM_TYPE_RETURN_OF_SUBMODULE,
        0, 1, 1, 0x00000030, 0x00000131, 0x0042,
    ),
)

# Truncated trailing item: parsed items stop at the bad one.
alarm_case(
    "alarm_truncated_item",
    "alarm with a valid RS item then a truncated maintenance item",
    alarm_pdu(
        indices.BLOCK_ALARM_NOTIFICATION_LOW, indices.ALARM_TYPE_DIAGNOSIS,
        0, 1, 1, 0x00000030, 0x00000131, 0x0001,
        be16(0x8300, 0x0005) + be16(0x8100) + bytes([0x00] * 4),
    ),
)


# --- RTA header / AlarmAck reference bytes -----------------------------------
rta = PNRTAHeader(
    alarm_dst_endpoint=0x0102,
    alarm_src_endpoint=0x0304,
    pdu_type=(PNRTAHeader.RTA_TYPE_DATA << 4) | PNRTAHeader.VERSION_1,
    add_flags=0x00,
    send_seq_num=0x0005,
    ack_seq_num=0x0006,
    var_part_len=0x0016,
    payload=b"",
)
golden["rta_header"] = {
    "desc": "PNRTAHeader reference bytes (DATA/v1, fixed fields)",
    "hex": bytes(rta).hex(),
    "alarm_dst_endpoint": 0x0102,
    "alarm_src_endpoint": 0x0304,
    "pdu_type": (PNRTAHeader.RTA_TYPE_DATA << 4) | PNRTAHeader.VERSION_1,
    "add_flags": 0x00,
    "send_seq_num": 0x0005,
    "ack_seq_num": 0x0006,
    "var_part_len": 0x0016,
}

# AlarmAck + full Layer-2 ack frame exactly as AlarmListener._send_ack /
# _send_layer2_ack compose them for the parsed "alarm_diag_channel" alarm.
_ack_alarm = parse_alarm_notification(
    bytes.fromhex(golden["alarm_diag_channel"]["hex"])
)
_ack_block_type = 0x8001 if _ack_alarm.is_high_priority else 0x8002
_ack_specifier = (
    (_ack_alarm.alarm_sequence_number & 0x07FF)
    | (0x0800 if _ack_alarm.channel_diagnosis else 0)
    | (0x1000 if _ack_alarm.manufacturer_specific else 0)
    | (0x2000 if _ack_alarm.submodule_diagnosis_state else 0)
    | (0x4000 if _ack_alarm.ar_diagnosis_state else 0)
)
ack = PNAlarmAckPDU(
    block_header=bytes(
        PNBlockHeader(_ack_block_type, PNAlarmAckPDU.fmt_size - 4, 0x01, 0x00)
    ),
    alarm_type=_ack_alarm.alarm_type,
    api=_ack_alarm.api,
    slot_number=_ack_alarm.slot_number,
    subslot_number=_ack_alarm.subslot_number,
    alarm_specifier=_ack_specifier,
    pnio_status=0x00000000,
)
ack_data = bytes(ack)
golden["alarm_ack"] = {
    "desc": "PNAlarmAckPDU for the alarm_diag_channel alarm (low prio)",
    "hex": ack_data.hex(),
}

DEVICE_MAC = bytes.fromhex("020000000002")
CONTROLLER_MAC = bytes.fromhex("020000000001")
_send_seq = 1  # listener increments 0 -> 1 before the first ack.
_recv_seq = 0x0005  # taken from the alarm's RTA send_seq_num.
ack_rta = PNRTAHeader(
    alarm_dst_endpoint=42,  # device_ref.
    alarm_src_endpoint=1,  # controller_ref.
    pdu_type=(PNRTAHeader.RTA_TYPE_DATA << 4) | PNRTAHeader.VERSION_1,
    add_flags=0,
    send_seq_num=_send_seq,
    ack_seq_num=_recv_seq,
    var_part_len=len(ack_data),
    payload=b"",
)
eth_frame = (
    DEVICE_MAC
    + CONTROLLER_MAC
    + struct.pack(">H", 0x8892)
    + struct.pack(">H", 0xFE01)  # low-priority ack frame ID.
    + bytes(ack_rta)
    + ack_data
)
golden["layer2_ack_frame"] = {
    "desc": "full L2 AlarmAck frame as _send_layer2_ack (low prio, "
    "device_ref 42, controller_ref 1, send_seq 1, recv_seq 5)",
    "hex": eth_frame.hex(),
    "device_mac": DEVICE_MAC.hex(),
    "controller_mac": CONTROLLER_MAC.hex(),
    "device_ref": 42,
    "controller_ref": 1,
    "send_seq_num": _send_seq,
    "ack_seq_num": _recv_seq,
}

# An inbound L2 alarm frame (device -> controller) for the listener-path
# parsing test: eth hdr + frame id 0xFE01 + RTA(dst=controller_ref 1) +
# the alarm_diag_channel notification.
_alarm_bytes = bytes.fromhex(golden["alarm_diag_channel"]["hex"])
in_rta = PNRTAHeader(
    alarm_dst_endpoint=1,
    alarm_src_endpoint=42,
    pdu_type=(PNRTAHeader.RTA_TYPE_DATA << 4) | PNRTAHeader.VERSION_1,
    add_flags=0,
    send_seq_num=0x0005,
    ack_seq_num=0xFFFF,
    var_part_len=len(_alarm_bytes),
    payload=b"",
)
inbound = (
    CONTROLLER_MAC
    + DEVICE_MAC
    + struct.pack(">H", 0x8892)
    + struct.pack(">H", 0xFE01)
    + bytes(in_rta)
    + _alarm_bytes
)
golden["layer2_inbound_alarm_frame"] = {
    "desc": "inbound L2 alarm frame (RTA dst ref 1) wrapping "
    "alarm_diag_channel",
    "hex": inbound.hex(),
    "controller_ref": 1,
    "device_mac": DEVICE_MAC.hex(),
    "rta_send_seq_num": 0x0005,
}

# AlarmCRBlockRes buffer for parse_alarm_cr_res: an unrelated block first,
# then the 0x8103 block with local_alarm_reference 0x002A.
alarm_cr_res = (
    bytes(PNBlockHeader(0x8101, 0x0006, 0x01, 0x00)) + be16(0x0000, 0x0001)
    + bytes(PNBlockHeader(0x8103, 0x0008, 0x01, 0x00))
    + be16(0x0001, 0x002A, 0x00C8)
)
golden["alarm_cr_res"] = {
    "desc": "block list with AlarmCRBlockRes 0x8103, local ref 0x002A",
    "hex": alarm_cr_res.hex(),
    "local_alarm_reference": 0x002A,
}

with open(OUT, "w") as f:
    json.dump(golden, f, indent=1, sort_keys=True)
print(f"wrote {os.path.abspath(OUT)} ({len(golden)} vectors)")
