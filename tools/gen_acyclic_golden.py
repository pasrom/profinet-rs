#!/usr/bin/env python3
"""Golden-byte oracle for the acyclic services: IODWriteMultipleReq (0xE040),
the Release request, and the EPM (Endpoint Mapper) lookup.

Write-multiple and release bytes come straight from profinet-py's own
builders (IODWriteMultipleBuilder, PNIODReleaseBlock/PNNRDData/PNRPCHeader
composed exactly as RPCCon.write_multiple/disconnect do, with FIXED
uuids/keys/seq). The write-multiple response parse expectations come from
profinet.blocks.parse_write_multiple_response run on a synthetic response.

The EPM vectors are captured from the reference itself: profinet.rpc.socket
and os.urandom are monkeypatched so epm_lookup() runs against a fake socket
with a fixed activity UUID; the recorded sendto() bytes are the request
golden, and the endpoints it returns for a canned response datagram are the
response-parse golden.

Run with the profinet-py venv active (needs the `construct` dep):
    cd ~/git/profinet-py && . .venv/bin/activate
    python ~/git/profinet-rs/tools/gen_acyclic_golden.py
"""

import json
import os
import struct
import sys

sys.path.insert(0, os.path.expanduser("~/git/profinet-py"))

import profinet.rpc as prpc  # noqa: E402
from profinet.blocks import (  # noqa: E402
    IODWriteMultipleBuilder,
    parse_write_multiple_response,
)
from profinet.protocol import (  # noqa: E402
    PNBlockHeader,
    PNIODHeader,
    PNIODReleaseBlock,
    PNNRDData,
    PNRPCHeader,
)
from profinet.rpc import (  # noqa: E402
    UUID_PNIO_DEVICE,
    _string_to_uuid_bytes,
    epm_lookup,
)

OUT = os.path.join(os.path.dirname(__file__), "..", "tests", "golden", "acyclic.json")

# Fixed UUIDs/keys (mirror the other golden generators).
AR = bytes(range(16))  # ar-uuid 00 01 .. 0f
ACT = bytes(range(16, 32))  # activity-uuid 10 11 .. 1f
OBJ = bytes(range(32, 48))  # object-uuid 20 21 .. 2f
IFACE = PNRPCHeader.IFACE_UUID_DEVICE
SESSION_KEY = 0x1234


def rpc_request(opnum, seq, nrd_bytes):
    """RPC REQUEST header exactly as RPCCon._create_rpc packs it."""
    return bytes(
        PNRPCHeader(
            0x04,
            PNRPCHeader.REQUEST,
            0x20,
            0x00,
            bytes(3),
            0x00,
            OBJ,
            IFACE,
            ACT,
            0,
            1,
            seq,
            opnum,
            0xFFFF,
            0xFFFF,
            len(nrd_bytes),
            0,
            0,
            0,
            payload=nrd_bytes,
        )
    )


def nrd(payload):
    """NRD wrapper exactly as RPCCon._create_nrd packs it."""
    return bytes(PNNRDData(1500, len(payload), 1500, 0, len(payload), payload=payload))


# --- IODWriteMultipleReq (0xE040) -------------------------------------------
# Fixed writes; the 5-byte record forces the 4-byte inter-block padding path.
WRITES = [
    # (slot, subslot, index, data, api) as RPCCon.write_multiple takes them
    (0, 1, 0xAFF1, b"Function\x00\x00\x00\x00\x00\x00\x00\x00", 0),
    (0, 1, 0xAFF2, b"\xde\xad\xbe\xef\x05", 0),
    (2, 3, 0x1234, b"\x01\x02\x03\x04", 0),
]

builder = IODWriteMultipleBuilder(AR, seq_num=0)
for slot, subslot, index, data, api in WRITES:
    builder.add_write(slot, subslot, index, data, api)
wm_payload = builder.build()

# Full WRITE frame as RPCCon.write_multiple composes it (fixed seq 3).
wm_iod = bytes(
    PNIODHeader(
        bytes(PNBlockHeader(0x0008, 60, 0x01, 0x00)),
        0,
        AR,
        0xFFFFFFFF,
        0xFFFF,
        0xFFFF,
        0,
        IODWriteMultipleBuilder.INDEX,  # 0xE040
        len(wm_payload),
        bytes(16),
        bytes(8),
        payload=wm_payload,
    )
)
WM_SEQ = 3
wm_frame = rpc_request(PNRPCHeader.WRITE, WM_SEQ, nrd(wm_iod))

# Synthetic IODWriteMultipleRes NRD payload: outer 0x8008 IOD header (64
# bytes, record_data_length = entries) + one 60-byte block per write
# (block_length 56 => block_size 4+56 = 60, pad 0), statuses
# 0 / 0xDE80B0C0 / 0.
def wm_res_entry(seq, api, slot, subslot, index, status, av1, av2):
    return struct.pack(
        "!HHBBH16sIHHHHIHHI8s4s",
        0x8008,
        56,
        0x01,
        0x00,
        seq,
        AR,
        api,
        slot,
        subslot,
        0,
        index,
        0,
        av1,
        av2,
        status,
        bytes(8),
        bytes(4),  # tail of the 60-byte block beyond the parsed 56 bytes
    )


WM_STATUSES = [0, 0xDE80B0C0, 0]
entries = b"".join(
    wm_res_entry(i, api, slot, subslot, index, WM_STATUSES[i], i, 2 * i)
    for i, (slot, subslot, index, data, api) in enumerate(WRITES)
)
wm_response_nrd_payload = bytes(
    PNIODHeader(
        bytes(PNBlockHeader(0x8008, 60, 0x01, 0x00)),
        0,
        AR,
        0xFFFFFFFF,
        0xFFFF,
        0xFFFF,
        0,
        IODWriteMultipleBuilder.INDEX,
        len(entries),
        bytes(16),
        bytes(8),
        payload=entries,
    )
)
wm_results = parse_write_multiple_response(wm_response_nrd_payload)

# --- Release request --------------------------------------------------------
# Exactly as RPCCon.disconnect composes it (fixed seq 5).
release_block = bytes(
    PNIODReleaseBlock(
        bytes(PNBlockHeader(0x0114, 28, 0x01, 0x00)),  # ReleaseBlockReq
        0,
        AR,
        SESSION_KEY,
        0,
        0x0004,  # Terminate AR
        0,
        payload=b"",
    )
)
RELEASE_SEQ = 5
release_frame = rpc_request(PNRPCHeader.RELEASE, RELEASE_SEQ, nrd(release_block))

# --- EPM: capture the reference's own request/response handling -------------
EPM_ACTIVITY = bytes(range(0x40, 0x50))  # fixed activity uuid 40 41 .. 4f


class FakeSocket:
    """Stands in for profinet.rpc.socket inside epm_lookup."""

    sent = []
    response = None

    def __init__(self, *args):
        pass

    def settimeout(self, t):
        pass

    def sendto(self, data, addr):
        FakeSocket.sent.append(bytes(data))

    def recvfrom(self, bufsize):
        if FakeSocket.response is None:
            raise TimeoutError()
        return FakeSocket.response, ("192.168.0.199", 34964)

    def close(self):
        pass


def build_epm_response(entry_specs):
    """Canned EPM RESPONSE datagram in the layout epm_lookup parses."""
    body = bytes(4)  # entry_handle
    body += struct.pack("<I", len(entry_specs))  # num_ents
    body += struct.pack("<III", len(entry_specs), 0, len(entry_specs))  # array meta
    for uuid_str, annotation, tower in entry_specs:
        entry = _string_to_uuid_bytes(uuid_str)
        entry += struct.pack("<I", 1)  # tower pointer (reference id)
        entry += struct.pack("<I", len(annotation)) + annotation
        entry += bytes(-len(entry) % 4)  # align 4
        entry += struct.pack("<I", len(tower)) + tower
        entry += bytes(-len(entry) % 4)  # align 4
        body += entry
    hdr = struct.pack("!BBBB3sB", 0x04, 0x02, 0x00, 0x00, bytes([0x10, 0x00, 0x00]), 0)
    hdr += bytes(16) + _string_to_uuid_bytes(prpc.UUID_EPM_V4) + EPM_ACTIVITY
    hdr += struct.pack("<IIIHHHHHBB", 0, 3, 0, 0x02, 0xFFFF, 0xFFFF, len(body), 0, 0, 0)
    return hdr + body


def uuid_floor(uuid_str, major, minor):
    lhs = struct.pack("<B16sH", 0x0D, _string_to_uuid_bytes(uuid_str), major)
    return struct.pack("<H", len(lhs)) + lhs + struct.pack("<HH", 2, minor)


NDR_SYNTAX = "8a885d04-1ceb-11c9-9fe8-08002b104860"
tower = struct.pack("<H", 5)  # floor count
tower += uuid_floor(UUID_PNIO_DEVICE, 1, 0)  # floor 1: interface uuid
tower += uuid_floor(NDR_SYNTAX, 2, 0)  # floor 2: transfer syntax
tower += struct.pack("<HBH", 1, 0x0A, 2) + bytes(2)  # floor 3: ncadg
tower += struct.pack("<HBH", 1, 0x08, 2) + struct.pack("!H", 0x8894)  # floor 4: udp
tower += struct.pack("<HBH", 1, 0x09, 4) + bytes([192, 168, 0, 199])  # floor 5: ip

DEVICE_OBJ_UUID = "dea00000-6c97-11d1-8271-0001abcd1234"
epm_response = build_epm_response(
    [
        (DEVICE_OBJ_UUID, b"DEV-123\x00", tower),
        # 5-byte annotation exercises the align-to-4 path.
        (DEVICE_OBJ_UUID, b"X567\x00", tower),
    ]
)

os.urandom = lambda n: EPM_ACTIVITY[:n]
prpc.socket = FakeSocket

# Request golden: timeout path records the sendto bytes and returns [].
FakeSocket.response = None
assert epm_lookup("192.168.0.199") == []
epm_request_all = FakeSocket.sent[-1]
assert epm_lookup("192.168.0.199", interface_filter=UUID_PNIO_DEVICE) == []
epm_request_filtered = FakeSocket.sent[-1]

# Response golden: what the reference parses out of the canned datagram.
FakeSocket.response = epm_response
epm_endpoints = epm_lookup("192.168.0.199")
assert len(epm_endpoints) == 2, epm_endpoints

# Tower-level golden via the reference's own tower parser.
tower_ep = prpc._parse_epm_tower(tower)
assert tower_ep is not None
assert prpc._parse_epm_tower(tower[:3]) is None

golden = {
    "write_multiple_payload": {
        "desc": "IODWriteMultipleBuilder.build() for 3 fixed writes (one 5-byte record forcing padding)",
        "hex": wm_payload.hex(),
        "ar_uuid": AR.hex(),
        "writes": [
            {"slot": s, "subslot": ss, "index": idx, "data": d.hex(), "api": a}
            for s, ss, idx, d, a in WRITES
        ],
    },
    "write_multiple_frame": {
        "desc": "full RPC WRITE frame as RPCCon.write_multiple sends it (seq 3)",
        "hex": wm_frame.hex(),
        "seq": WM_SEQ,
    },
    "write_multiple_response": {
        "desc": "synthetic IODWriteMultipleRes NRD payload + reference parse results",
        "hex": wm_response_nrd_payload.hex(),
        "results": [
            {
                "seq_num": r.seq_num,
                "api": r.api,
                "slot": r.slot,
                "subslot": r.subslot,
                "index": r.index,
                "status": r.status,
                "additional_value1": r.additional_value1,
                "additional_value2": r.additional_value2,
                "success": r.success,
            }
            for r in wm_results
        ],
    },
    "release_frame": {
        "desc": "full RPC RELEASE frame as RPCCon.disconnect sends it (seq 5)",
        "hex": release_frame.hex(),
        "seq": RELEASE_SEQ,
        "session_key": SESSION_KEY,
        "release_block": release_block.hex(),
    },
    "epm_request_all": {
        "desc": "epm_lookup request datagram (no interface filter), fixed activity uuid",
        "hex": epm_request_all.hex(),
        "activity_uuid": EPM_ACTIVITY.hex(),
    },
    "epm_request_filtered": {
        "desc": "epm_lookup request datagram filtered by UUID_PNIO_DEVICE",
        "hex": epm_request_filtered.hex(),
        "activity_uuid": EPM_ACTIVITY.hex(),
        "interface_filter": UUID_PNIO_DEVICE,
    },
    "epm_response": {
        "desc": "canned EPM RESPONSE datagram + endpoints the reference extracts",
        "hex": epm_response.hex(),
        "endpoints": [
            {
                "interface_uuid": ep.interface_uuid,
                "interface_version_major": ep.interface_version_major,
                "interface_version_minor": ep.interface_version_minor,
                "object_uuid": ep.object_uuid,
                "protocol": ep.protocol,
                "port": ep.port,
                "address": ep.address,
                "annotation": ep.annotation,
                "interface_name": ep.interface_name,
            }
            for ep in epm_endpoints
        ],
    },
    "epm_tower": {
        "desc": "single EPM tower + reference _parse_epm_tower fields; first 3 bytes parse to None",
        "hex": tower.hex(),
        "interface_uuid": tower_ep.interface_uuid,
        "interface_version_major": tower_ep.interface_version_major,
        "interface_version_minor": tower_ep.interface_version_minor,
        "protocol": tower_ep.protocol,
        "port": tower_ep.port,
        "address": tower_ep.address,
    },
}

with open(OUT, "w") as f:
    json.dump(golden, f, indent=2)
    f.write("\n")

print(f"wrote {os.path.normpath(OUT)}")
for k, v in golden.items():
    if isinstance(v, dict) and "hex" in v:
        print(f"  {k:26s} {len(v['hex']) // 2:4d}B {v['hex'][:64]}...")
