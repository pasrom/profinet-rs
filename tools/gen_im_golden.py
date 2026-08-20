#!/usr/bin/env python3
"""Golden-byte oracle for the I&M / identification-record module.

Builds reference bytes with profinet-py for FIXED inputs and dumps them plus
the expected parse results to tests/golden/im.json:

- Full RPC READ request frames for I&M0..3, PDRealData, RealIdentificationData
  and I&M0FilterData (as RPCCon.read composes them, seq 0, fixed UUIDs).
- I&M0..3 RESPONSE record bytes built with the PNInM0..PNInM3 protocol
  structs, re-parsed with the same structs to record the expected fields.
- Hand-assembled PDRealData / RealIdentificationData / I&M0FilterData
  response buffers (the block layouts profinet-py's parsers expect), parsed
  with profinet-py's own parsers (blocks.parse_pd_real_data,
  blocks.parse_real_identification_data, RPCCon.read_inm0filter) to record
  the expected structures.

Run with the profinet-py venv active (needs the `construct` dep):
    cd ~/git/profinet-py && . .venv/bin/activate
    python ~/git/profinet-rs/tools/gen_im_golden.py
"""

import json
import os
import struct
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _golden_common import dump, nrd, use_reference  # noqa: E402

use_reference()

from profinet import blocks, indices  # noqa: E402
from profinet.protocol import (  # noqa: E402
    PNBlockHeader,
    PNInM0,
    PNInM1,
    PNInM2,
    PNInM3,
    PNIODHeader,
    PNNRDData,
    PNRPCHeader,
)
from profinet.rpc import RPCCon  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "tests", "golden", "im.json")

# Fixed UUIDs, mirroring gen_golden.py.
AR = bytes(range(16))  # ar-uuid 00 01 .. 0f
ACT = bytes(range(16, 32))  # activity-uuid 10 11 .. 1f
OBJ = PNRPCHeader.OBJECT_UUID_PREFIX + bytes([0x00, 0x01, 0x00, 0x07, 0x0A, 0xBC])

golden = {}


# --- READ request frames (rpc.py read(): IOD + NRD + RPC, seq 0) -------------


def _rpc_read(nrd: bytes) -> bytes:
    return bytes(
        PNRPCHeader(
            0x04, PNRPCHeader.REQUEST, 0x20, 0x00, bytes([0, 0, 0]), 0x00,
            OBJ, PNRPCHeader.IFACE_UUID_DEVICE, ACT, 0, 1, 0, PNRPCHeader.READ,
            0xFFFF, 0xFFFF, len(nrd), 0, 0, 0, payload=nrd,
        )
    )


def _read_request(slot: int, subslot: int, idx: int, length: int = 4096) -> bytes:
    block = PNBlockHeader(PNBlockHeader.IODReadRequestHeader, 60, 0x01, 0x00)
    iod = PNIODHeader(
        bytes(block), 0, AR, 0, slot, subslot, 0, idx, length,
        bytes(16), bytes(8), payload=b"",
    )
    return _rpc_read(nrd(bytes(iod)))


for name, slot, subslot, idx in [
    ("read_request_im0", 0, 1, indices.IM0),
    ("read_request_im1", 0, 1, indices.IM1),
    ("read_request_im2", 0, 1, indices.IM2),
    ("read_request_im3", 0, 1, indices.IM3),
    ("read_request_pd_real_data", 0, 1, indices.PD_REAL_DATA),
    ("read_request_real_identification_data", 0, 1, indices.REAL_ID_API),
    ("read_request_inm0_filter", 0, 0, indices.IM0_FILTER_DATA),
]:
    golden[name] = {
        "desc": f"full READ RPC request, slot{slot} subslot{subslot} "
        f"idx0x{idx:04X} len4096, seq0, fixed uuids",
        "slot": slot,
        "subslot": subslot,
        "idx": idx,
        "hex": _read_request(slot, subslot, idx).hex(),
    }


# --- I&M0..3 response records ------------------------------------------------
im0 = PNInM0(
    bytes(PNBlockHeader(indices.BLOCK_IM0, 56, 0x01, 0x00)),
    0x01,
    0x41,
    b"6ES7 155-6AU01-0BN0 ".ljust(20, b"\x00"),
    b"S C-EXAMPLE00001".ljust(16, b"\x00"),
    0x0007,
    ord("V"),
    4,
    2,
    1,
    0x000A,
    0x1234,
    0x5678,
    0x0101,
    0x001E,
)
im0_bytes = bytes(im0)
im0_parsed = PNInM0(im0_bytes)
golden["im0_response"] = {
    "desc": "I&M0 record, vendor 0x0141, order/serial padded with NULs",
    "hex": im0_bytes.hex(),
    "block_type": indices.BLOCK_IM0,
    "block_length": 56,
    "vendor_id": im0_parsed.vendor_id,
    "vendor_id_high": im0_parsed.vendor_id_high,
    "vendor_id_low": im0_parsed.vendor_id_low,
    "order_id_hex": im0_parsed.order_id.hex(),
    "order_id_str": im0_parsed.order_id.rstrip(b"\x00").decode("utf-8"),
    "serial_hex": im0_parsed.im_serial_number.hex(),
    "serial_str": im0_parsed.im_serial_number.rstrip(b"\x00").decode("utf-8"),
    "hardware_revision": im0_parsed.im_hardware_revision,
    "sw_revision_prefix": im0_parsed.sw_revision_prefix,
    "sw_enhancement": im0_parsed.im_sw_revision_functional_enhancement,
    "sw_bug_fix": im0_parsed.im_sw_revision_bug_fix,
    "sw_internal_change": im0_parsed.im_sw_revision_internal_change,
    "revision_counter": im0_parsed.im_revision_counter,
    "profile_id": im0_parsed.im_profile_id,
    "profile_specific_type": im0_parsed.im_profile_specific_type,
    "im_version": im0_parsed.im_version,
    "im_supported": im0_parsed.im_supported,
}

im1_bytes = bytes(
    PNInM1(
        bytes(PNBlockHeader(indices.BLOCK_IM1, 56, 0x01, 0x00)),
        b"Pump Control".ljust(32, b"\x00"),
        b"Building A".ljust(22, b"\x00"),
    )
)
im1_parsed = PNInM1(im1_bytes)
golden["im1_response"] = {
    "desc": "I&M1 record, tag function/location padded with NULs",
    "hex": im1_bytes.hex(),
    "tag_function_str": im1_parsed.im_tag_function.rstrip(b"\x00").decode("utf-8"),
    "tag_location_str": im1_parsed.im_tag_location.rstrip(b"\x00").decode("utf-8"),
}

im2_bytes = bytes(
    PNInM2(
        bytes(PNBlockHeader(indices.BLOCK_IM2, 18, 0x01, 0x00)),
        b"2024-01-15 10:30",
    )
)
im2_parsed = PNInM2(im2_bytes)
golden["im2_response"] = {
    "desc": "I&M2 record, installation date (16 chars, no padding)",
    "hex": im2_bytes.hex(),
    "date_str": im2_parsed.im_date.rstrip(b"\x00").decode("utf-8"),
}

im3_bytes = bytes(
    PNInM3(
        bytes(PNBlockHeader(indices.BLOCK_IM3, 56, 0x01, 0x00)),
        b"Line 4 distributed IO, maintained by OT".ljust(54, b"\x00"),
    )
)
im3_parsed = PNInM3(im3_bytes)
golden["im3_response"] = {
    "desc": "I&M3 record, descriptor padded with NULs",
    "hex": im3_bytes.hex(),
    "descriptor_str": im3_parsed.im_descriptor.rstrip(b"\x00").decode("utf-8"),
}


# --- PDRealData response -----------------------------------------------------
def block(block_type: int, body: bytes, ver=(1, 0)) -> bytes:
    return struct.pack("!HHBB", block_type, len(body) + 2, ver[0], ver[1]) + body


# PDInterfaceDataReal body; alignment is relative to the nested block start
# (6-byte header included), matching parse_pd_interface_data_real.
if_body = bytearray()
if_body += bytes([5]) + b"dev-1"  # chassis id (block offset 6 -> 12, aligned)
if_body += bytes.fromhex("0a1b2c3d4e5f")  # MAC (block offset 12 -> 18)
if_body += b"\x00\x00"  # pad to block offset 20
if_body += bytes([192, 168, 0, 50])  # IP
if_body += bytes([255, 255, 255, 0])  # subnet
if_body += bytes([192, 168, 0, 1])  # gateway
if_block = block(indices.BLOCK_PD_INTERFACE_DATA_REAL, bytes(if_body))

mbh1_body = b"\x00\x00" + struct.pack("!IHH", 0, 0, 0x8000) + if_block
buf = bytearray(block(indices.BLOCK_MULTIPLE_HEADER, mbh1_body))
assert len(buf) == 48

# Second MultipleBlockHeader with a PDPortDataReal. parse_pd_port_data_real
# aligns its first field on the ABSOLUTE offset, later paddings relative to
# the body start; the pad bytes here place every field where the parser looks.
mbh2_header_off = len(buf)
port_block_body_off = mbh2_header_off + 6 + 10 + 6  # nested body abs offset
port_body = bytearray()

pad = blocks.align4(port_block_body_off) - port_block_body_off
port_body += b"\x00" * pad  # absolute align4
port_body += struct.pack("!HH", 0, 0x8001)  # slot/subslot
port_body += bytes([2]) + b"p1"  # own port id
port_body += bytes([1])  # number of peers
cur = len(port_body)
port_body += b"\x00" * (blocks.align4(cur) - cur)  # align rel to body start
port_body += bytes([6]) + b"port-2"  # peer port id
port_body += bytes([5]) + b"dev-2"  # peer chassis id
cur = len(port_body)
port_body += b"\x00" * (blocks.align4(cur) - cur)
port_body += bytes.fromhex("aabbccddeeff")  # peer MAC
cur = len(port_body)
port_body += b"\x00" * (blocks.align4(cur) - cur)
port_body += struct.pack("!H", 16)  # MAU type (100BaseTXFD)
cur = len(port_body)
port_body += b"\x00" * (blocks.align4(cur) - cur)
port_body += struct.pack("!II", 0, 0)  # domain/multicast boundary
port_body += bytes([1, 1])  # link state port/link (up)
cur = len(port_body)
port_body += b"\x00" * (blocks.align4(cur) - cur)
port_body += struct.pack("!I", 1)  # media type (copper)

port_block = block(indices.BLOCK_PD_PORT_DATA_REAL, bytes(port_body))
mbh2_body = b"\x00\x00" + struct.pack("!IHH", 0, 0, 0x8001) + port_block
buf += block(indices.BLOCK_MULTIPLE_HEADER, mbh2_body)

pd_real_bytes = bytes(buf)
pd = blocks.parse_pd_real_data(pd_real_bytes)

# Sanity: the buffer must parse to exactly what was assembled.
assert pd.interface is not None
assert pd.interface.chassis_id == "dev-1"
assert pd.interface.ip_str == "192.168.0.50"
assert len(pd.ports) == 1 and pd.ports[0].port_id == "p1"
assert pd.ports[0].peers[0].chassis_id == "dev-2"
assert pd.ports[0].mau_type == 16 and pd.ports[0].media_type == 1

golden["pd_real_data_response"] = {
    "desc": "PDRealData: MBH(interface 0x0240) + MBH(port 0x020F w/ 1 peer)",
    "hex": pd_real_bytes.hex(),
    "slots": [
        {"api": s.api, "slot": s.slot, "subslot": s.subslot, "blocks": s.blocks}
        for s in pd.slots
    ],
    "interface": {
        "chassis_id": pd.interface.chassis_id,
        "mac": pd.interface.mac_str,
        "ip": pd.interface.ip_str,
        "subnet": pd.interface.subnet_str,
        "gateway": pd.interface.gateway_str,
    },
    "ports": [
        {
            "slot": p.slot,
            "subslot": p.subslot,
            "port_id": p.port_id,
            "mau_type": p.mau_type,
            "link_state_port": p.link_state_port,
            "link_state_link": p.link_state_link,
            "media_type": p.media_type,
            "domain_boundary": p.domain_boundary,
            "multicast_boundary": p.multicast_boundary,
            "peers": [
                {"port_id": peer.port_id, "chassis_id": peer.chassis_id, "mac": peer.mac_str}
                for peer in p.peers
            ],
        }
        for p in pd.ports
    ],
    "raw_blocks": [
        {"api": api, "slot": slot, "subslot": subslot, "hex": raw.hex()}
        for api, slot, subslot, raw in pd.raw_blocks
    ],
}


# --- RealIdentificationData responses ---------------------------------------
def real_id_slots_json(parsed):
    return [
        {
            "api": s.api,
            "slot": s.slot,
            "subslot": s.subslot,
            "module_ident": s.module_ident,
            "submodule_ident": s.submodule_ident,
        }
        for s in parsed.slots
    ]


# v1.1: two APIs.
v11_body = struct.pack("!H", 2)
v11_body += struct.pack("!IH", 0, 2)  # api 0, 2 slots
v11_body += struct.pack("!HIH", 0, 0x100, 2)  # slot 0, module 0x100, 2 subslots
v11_body += struct.pack("!HI", 1, 0x10001)
v11_body += struct.pack("!HI", 0x8000, 0x10002)
v11_body += struct.pack("!HIH", 1, 0x200, 1)  # slot 1, module 0x200, 1 subslot
v11_body += struct.pack("!HI", 1, 0x20001)
v11_body += struct.pack("!IH", 0x3E00, 1)  # api 0x3e00, 1 slot
v11_body += struct.pack("!HIH", 2, 0x300, 1)
v11_body += struct.pack("!HI", 1, 0x30001)
real_id_v11 = block(indices.BLOCK_REAL_IDENTIFICATION_DATA, v11_body, ver=(1, 1))
parsed_v11 = blocks.parse_real_identification_data(real_id_v11)
assert len(parsed_v11.slots) == 4 and parsed_v11.version == (1, 1)
golden["real_identification_data_v11"] = {
    "desc": "RealIdentificationData v1.1, 2 APIs / 3 slots / 4 subslots",
    "hex": real_id_v11.hex(),
    "version": list(parsed_v11.version),
    "slots": real_id_slots_json(parsed_v11),
}

# v1.0: no API level.
v10_body = struct.pack("!H", 1)
v10_body += struct.pack("!HIH", 4, 0x42, 2)
v10_body += struct.pack("!HI", 1, 0x420001)
v10_body += struct.pack("!HI", 2, 0x420002)
real_id_v10 = block(indices.BLOCK_REAL_IDENTIFICATION_DATA, v10_body, ver=(1, 0))
parsed_v10 = blocks.parse_real_identification_data(real_id_v10)
assert len(parsed_v10.slots) == 2 and parsed_v10.version == (1, 0)
golden["real_identification_data_v10"] = {
    "desc": "RealIdentificationData v1.0, 1 slot / 2 subslots",
    "hex": real_id_v10.hex(),
    "version": list(parsed_v10.version),
    "slots": real_id_slots_json(parsed_v10),
}

# v1.1 truncated mid-subslot: parser keeps what it got.
truncated = real_id_v11[: 6 + 2 + 6 + 8 + 6 + 3]
parsed_trunc = blocks.parse_real_identification_data(truncated)
golden["real_identification_data_truncated"] = {
    "desc": "v1.1 cut mid-subslot-entry; slots parsed so far are kept",
    "hex": truncated.hex(),
    "version": list(parsed_trunc.version),
    "slots": real_id_slots_json(parsed_trunc),
}


# --- I&M0FilterData response -------------------------------------------------
filter_body = struct.pack("!H", 1)  # 1 API
filter_body += struct.pack("!IH", 0, 2)  # api 0, 2 modules
filter_body += struct.pack("!HIH", 0, 0x100, 2)  # slot 0, module 0x100
filter_body += struct.pack("!HI", 1, 0x10001)
filter_body += struct.pack("!HI", 0x8000, 0x10002)
filter_body += struct.pack("!HIH", 1, 0x200, 1)  # slot 1, module 0x200
filter_body += struct.pack("!HI", 1, 0x20001)
inm0_filter_bytes = block(0x0030, filter_body)  # InM0FilterDataSubModul

# Run rpc.py's own read_inm0filter parse loop against the buffer by stubbing
# the record read on a bare RPCCon instance.
conn = RPCCon.__new__(RPCCon)
conn.read = lambda **kw: SimpleNamespace(payload=inm0_filter_bytes)
filter_parsed = conn.read_inm0filter()
assert filter_parsed == {0: {0: (0x100, {1: 0x10001, 0x8000: 0x10002}), 1: (0x200, {1: 0x20001})}}
golden["inm0_filter_response"] = {
    "desc": "I&M0FilterData: 1 API, 2 modules, 3 submodules",
    "hex": inm0_filter_bytes.hex(),
    # JSON keys must be strings; the Rust test parses them back to ints.
    "expected": {
        str(api): {
            str(slot): {"module_ident": mod, "subslots": {str(ss): sub for ss, sub in subs.items()}}
            for slot, (mod, subs) in mods.items()
        }
        for api, mods in filter_parsed.items()
    },
}


os.makedirs(os.path.dirname(OUT), exist_ok=True)
dump(OUT, golden)
