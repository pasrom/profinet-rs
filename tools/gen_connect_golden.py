#!/usr/bin/env python3
"""Golden-byte oracle for the profinet-rs connect module.

Builds the Connect request PDU blocks (ARBlockReq 0x0101, IOCRBlockReq 0x0102,
AlarmCRBlock 0x0103, ExpectedSubmoduleBlockReq 0x0104) and the full Connect
RPC request with profinet-py (the reference implementation being ported),
using FIXED values for everything random/stateful, and dumps them as hex to
tests/golden/connect.json.

Pinned dynamic state (see RPCCon.__init__ / RPCCon.connect):
  - ar_uuid          = 00 01 .. 0f            (os.urandom in __init__)
  - activity_uuid    = 10 11 .. 1f            (os.urandom in __init__)
  - session_key      = 0x0001                 (os.urandom in __init__)
  - cm_mac (src_mac) = 02:00:00:00:00:01      (passed to connect())
  - remote object uuid: device 0x0007 / vendor 0x0abc (from DCP discovery)
  - RPC sequence number = 0                   (_sequence_number, first request)
  - input IOCR reference = 1, output = 2      (_iocr_ref_counter starts at 1)
  - local alarm reference = 1                 (_alarm_ref)
  - IOCRSetup: device io_slots (build_io_slots_from_device on the real slots),
    send_clock_factor=32, reduction_ratio=128, watchdog_factor=6,
    data_hold_factor=6 (same as cli.py cmd_cyclic)

The pure _build_* methods are invoked on an RPCCon created via
object.__new__ (no sockets bound); they only read self._alarm_ref.

The reference connect() hardcodes CMInitiatorStationName "tp" with
station_name_length=2 and block_length = PNARBlockRequest.fmt_size - 2 (only
correct for a 2-byte name). The port parameterizes the station name, so the
AR block length generalizes to fmt_size - 2 + (len(name) - 2); for "tp" that
is byte-identical to the literal connect() bytes (asserted by the
ar_block_iocr_tp vector).

Run with the profinet-py venv active (needs `construct`):
    cd ~/git/profinet-py && . .venv/bin/activate
    python ~/git/profinet-rs/tools/gen_connect_golden.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/git/profinet-py"))

from profinet.blocks import SlotInfo  # noqa: E402
from profinet.gsdml import load_gsdml  # noqa: E402
from profinet.rpc import NDR_ARGS_MAXIMUM  # noqa: E402
from profinet.protocol import (  # noqa: E402
    PNARBlockRequest,
    PNBlockHeader,
    PNNRDData,
    PNRPCHeader,
)
from profinet.rpc import IOCRSetup, RPCCon  # noqa: E402
from profinet.util import s2mac  # noqa: E402

HERE = os.path.dirname(__file__)
XML = os.path.join(HERE, "..", "tests", "data", "demo.gsdml.xml")
OUT = os.path.join(HERE, "..", "tests", "golden", "connect.json")

AR = bytes(range(16))  # fixed AR-UUID 00 01 02 ... 0f
ACT = bytes(range(16, 32))  # fixed activity-UUID 10 11 ... 1f
SESSION_KEY = 0x0001
CM_MAC = s2mac("02:00:00:00:00:01")
OBJ = PNRPCHeader.OBJECT_UUID_PREFIX + bytes([0x00, 0x01, 0x00, 0x07, 0x0A, 0xBC])
# CMInitiatorObjectUUID (RPCCon.local_object_uuid, a fixed constant)
LOCAL_OBJ = PNRPCHeader.OBJECT_UUID_PREFIX + bytes([0x00, 0x01, 0x76, 0x54, 0x32, 0x10])
SEQ = 0

# --- IOCRSetup from the GSDML (as cli.py cmd_cyclic assembles it) --------
device = load_gsdml(XML)
device_slots = [
    SlotInfo(
        slot=s.slot,
        subslot=s.subslot,
        module_ident=s.module_ident,
        submodule_ident=s.submodule_ident,
    )
    for s in device.build_io_slots()
]
io_slots = device.build_io_slots_from_device(device_slots)
setup = IOCRSetup(
    slots=io_slots,
    send_clock_factor=32,
    reduction_ratio=128,
    watchdog_factor=6,
    data_hold_factor=6,
)

# RPCCon without __init__ (no sockets); the _build_* methods are pure except
# for reading self._alarm_ref.
conn = object.__new__(RPCCon)
conn._alarm_ref = 1


def ar_block(ar_type: int, ar_properties: int, station_name: bytes) -> bytes:
    """ARBlockReq exactly as connect() builds it, parameterized station name."""
    block = PNBlockHeader(
        0x0101,
        PNARBlockRequest.fmt_size - 2 + (len(station_name) - 2),
        0x01,
        0x00,
    )
    return bytes(
        PNARBlockRequest(
            bytes(block),
            ar_type,
            AR,
            SESSION_KEY,
            CM_MAC,
            LOCAL_OBJ,
            ar_properties,
            100,  # Timeout factor
            0x8892,  # UDP RT port
            len(station_name),
            cm_initiator_station_name=station_name,
            payload=b"",
        )
    )


# Literal connect() AR blocks (station name "tp", block_length fmt_size - 2):
# IOCARSingle path (iocr_setup given): ar_type 0x0001, properties 0x00000011.
ar_iocr_tp = ar_block(0x0001, 0x00000011, b"tp")
# DeviceAccess path (no iocr_setup): ar_type 0x0006, properties 0x00000111.
ar_devaccess_tp = ar_block(0x0006, 0x00000111, b"tp")
# Parameterized name, as build_connect_request pins it.
ar_iocr_controller = ar_block(0x0001, 0x00000011, b"controller")

input_iocr = conn._build_iocr_block(iocr_type=1, iocr_reference=1, setup=setup)
output_iocr = conn._build_iocr_block(iocr_type=2, iocr_reference=2, setup=setup)
alarm_cr = conn._build_alarm_cr_block()
expected_submodule = conn._build_expected_submodule_block(setup)

# connect() body: AR -> input IOCR -> output IOCR -> AlarmCR -> ExpectedSubmod,
# concatenated without inter-block padding.
body = ar_iocr_controller + input_iocr + output_iocr + alarm_cr + expected_submodule

_args_max = max(NDR_ARGS_MAXIMUM, len(body))
nrd = bytes(PNNRDData(_args_max, len(body), _args_max, 0, len(body), payload=body))
rpc = bytes(
    PNRPCHeader(
        0x04, PNRPCHeader.REQUEST, 0x20, 0x00, bytes([0, 0, 0]), 0x00,
        OBJ, PNRPCHeader.IFACE_UUID_DEVICE, ACT, 0, 1, SEQ, PNRPCHeader.CONNECT,
        0xFFFF, 0xFFFF, len(nrd), 0, 0, 0, payload=nrd,
    )
)

golden = {
    "io_slots": [
        {
            "slot": s.slot,
            "subslot": s.subslot,
            "module_ident": s.module_ident,
            "submodule_ident": s.submodule_ident,
            "input_length": s.input_length,
            "output_length": s.output_length,
        }
        for s in io_slots
    ],
    "ar_block_iocr_tp": {
        "desc": "ARBlockReq, literal connect() IOCAR path: type 0x0001 props 0x11 name 'tp'",
        "hex": ar_iocr_tp.hex(),
    },
    "ar_block_device_access_tp": {
        "desc": "ARBlockReq, literal connect() DeviceAccess path: type 0x0006 props 0x111 name 'tp'",
        "hex": ar_devaccess_tp.hex(),
    },
    "ar_block_iocr_controller": {
        "desc": "ARBlockReq, IOCAR path with station name 'controller'",
        "hex": ar_iocr_controller.hex(),
    },
    "iocr_block_input": {
        "desc": "IOCRBlockReq input (type 1, ref 1, frame_id 0xC001), device slots",
        "hex": input_iocr.hex(),
    },
    "iocr_block_output": {
        "desc": "IOCRBlockReq output (type 2, ref 2, frame_id 0x8002), device slots",
        "hex": output_iocr.hex(),
    },
    "alarm_cr_block": {
        "desc": "AlarmCRBlockReq, transport L2, priority low, alarm_ref 1",
        "hex": alarm_cr.hex(),
    },
    "expected_submodule_block": {
        "desc": "ExpectedSubmoduleBlockReq for the device slots",
        "hex": expected_submodule.hex(),
    },
    "connect_body": {
        "desc": "connect() NRD payload: AR('controller') + IOCRs + AlarmCR + ExpSubmod",
        "hex": body.hex(),
    },
    "connect_request": {
        "desc": "full Connect RPC request: obj=dev0007/vendor0abc, act=10..1f, seq 0, op CONNECT",
        "hex": rpc.hex(),
    },
}

with open(OUT, "w") as f:
    json.dump(golden, f, indent=2)
    f.write("\n")

print(f"wrote {os.path.normpath(OUT)}")
for k, v in golden.items():
    if isinstance(v, dict) and "hex" in v:
        print(f"  {k:28s} {len(v['hex']) // 2:4d}B {v['hex']}")
