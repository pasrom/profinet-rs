#!/usr/bin/env python3
"""Golden-byte oracle for the profinet-rs port.

Builds reference PROFINET PDUs with profinet-py (the reference implementation
being ported) using FIXED inputs, and dumps them as hex to tests/golden/*.json.
The Rust port asserts byte-for-byte equality against these vectors, which
verifies the hard byte-exact framing without any hardware.

Run with the profinet-py venv active (needs the `construct` dep):
    cd ~/git/profinet-py && . .venv/bin/activate
    python ~/git/profinet-rs/tools/gen_golden.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/git/profinet-py"))

from profinet.protocol import (  # noqa: E402
    EthernetHeader,
    EthernetVLANHeader,
    PNBlockHeader,
    PNDCPBlock,
    PNDCPBlockRequest,
    PNDCPHeader,
    PNIODHeader,
    PNNRDData,
    PNRPCHeader,
)
from profinet.rt import (  # noqa: E402
    DATA_STATUS_PROVIDER_RUN,
    DATA_STATUS_STATE,
    DATA_STATUS_STATION_OK,
    DATA_STATUS_VALID,
    RTFrame,
    build_ethernet_frame,
)
from profinet.util import ip2s, s2mac  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "tests", "golden", "foundation.json")

AR = bytes(range(16))  # fixed AR-UUID 00 01 02 ... 0f

golden = {}

# --- util address conversions ------------------------------------------------
golden["s2mac"] = {"in": "01:02:03:04:05:06", "hex": s2mac("01:02:03:04:05:06").hex()}
golden["ip2s"] = {"in": "192.168.0.2", "hex": ip2s("192.168.0.2").hex()}

# --- PNBlockHeader: IODReadRequestHeader, block_length 60, version 1.0 -------
read_blk = PNBlockHeader(PNBlockHeader.IODReadRequestHeader, 60, 0x01, 0x00)
golden["block_iod_read_header"] = {
    "desc": "block_type=0x0009 block_length=60 version 1.0",
    "hex": bytes(read_blk).hex(),
}

# --- PNIODHeader: Read Record (api0 slot1 subslot1 idx4660 length8) ----------
read_iod = PNIODHeader(
    bytes(read_blk), 0, AR, 0, 1, 1, 0, 4660, 8, bytes(16), bytes(8), payload=b""
)
golden["iod_read_record"] = {
    "desc": "ar=00..0f seq0 api0 slot1 subslot1 idx4660 length8",
    "hex": bytes(read_iod).hex(),
}

# --- PNIODHeader: Write Record (idx5000 length1 payload=0x01) ----------------
write_blk = PNBlockHeader(0x0008, 60, 0x01, 0x00)  # IODWriteReqHeader
write_iod = PNIODHeader(
    bytes(write_blk), 0, AR, 0, 2, 1, 0, 5000, 1, bytes(16), bytes(8), payload=b"\x01"
)
golden["iod_write_5000"] = {
    "desc": "ar=00..0f seq0 api0 slot2 subslot1 idx5000 length1 payload=01",
    "hex": bytes(write_iod).hex(),
}

# --- DCE/RPC framing (fixed UUIDs for determinism) --------------------------
# Fixed activity-uuid 10 11 .. 1f; remote object uuid for device 0x0007 /
# vendor 0x0abc (the synthetic demo device).
ACT = bytes(range(16, 32))
OBJ = PNRPCHeader.OBJECT_UUID_PREFIX + bytes([0x00, 0x01, 0x00, 0x07, 0x0A, 0xBC])
golden["object_uuid_dev0007_vendor0abc"] = {
    "desc": "remote object uuid = OBJECT_UUID_PREFIX + 00 01 <dev_hi dev_lo> <ven_hi ven_lo>",
    "hex": OBJ.hex(),
}
golden["iface_uuid_device"] = {"desc": "PNIO device interface uuid", "hex": PNRPCHeader.IFACE_UUID_DEVICE.hex()}


def _nrd(payload: bytes) -> bytes:
    return bytes(PNNRDData(1500, len(payload), 1500, 0, len(payload), payload=payload))


def _rpc(operation: int, nrd: bytes) -> bytes:
    return bytes(
        PNRPCHeader(
            0x04, PNRPCHeader.REQUEST, 0x20, 0x00, bytes([0, 0, 0]), 0x00,
            OBJ, PNRPCHeader.IFACE_UUID_DEVICE, ACT, 0, 1, 0, operation,
            0xFFFF, 0xFFFF, len(nrd), 0, 0, 0, payload=nrd,
        )
    )


nrd_read = _nrd(bytes(read_iod))
golden["nrd_read_record"] = {"desc": "NRD wrapping the read IOD", "hex": nrd_read.hex()}
golden["rpc_read_record"] = {
    "desc": "full Read Record RPC request; obj=dev0007/vendor0abc, iface=device, act=10..1f, seq0, op=READ(2)",
    "hex": _rpc(PNRPCHeader.READ, nrd_read).hex(),
}
golden["rpc_write_5000"] = {
    "desc": "full Write Record RPC request; idx5000 payload01, op=WRITE(3)",
    "hex": _rpc(PNRPCHeader.WRITE, _nrd(bytes(write_iod))).hex(),
}

# --- DCP framing (fixed src MAC / XID instead of the random _generate_xid) --
# Replicates dcp.py send_discover / set_param / set_ip byte-for-byte.
DCP_SRC = s2mac("02:00:00:00:00:01")
DCP_DST = s2mac("0a:1b:2c:3d:4e:5f")  # fixed unicast target for Set requests
DCP_XID = 0x01020304

# send_discover: Identify-All multicast request (dst 01:0e:cf:00:00:00,
# response_delay 0x0080, one All/All block with empty payload).
_ident_block = PNDCPBlockRequest(0xFF, 0xFF, 0, payload=b"")
_ident_dcp = PNDCPHeader(
    0xFEFE,
    PNDCPHeader.IDENTIFY,
    PNDCPHeader.REQUEST,
    DCP_XID,
    0x0080,
    len(_ident_block),
    payload=_ident_block,
)
_ident_eth = EthernetHeader(s2mac("01:0e:cf:00:00:00"), DCP_SRC, 0x8892, payload=_ident_dcp)
golden["dcp_identify_all_request"] = {
    "desc": "Identify-All request; src 02:00:00:00:00:01 xid 0x01020304 delay 0x0080",
    "hex": bytes(_ident_eth).hex(),
}


def _dcp_set(option: int, suboption: int, value: bytes) -> bytes:
    """Build a DCP Set request frame exactly as set_param / set_ip do.

    Note: the value already carries the 2-byte block qualifier prefix; the DCP
    header length field counts a pad byte for odd values that set_param never
    actually appends to the frame (reference quirk, preserved as-is).
    """
    block = PNDCPBlockRequest(option, suboption, len(value) + 2, payload=b"\x00\x00" + value)
    padding = 1 if len(value) % 2 == 1 else 0
    dcp = PNDCPHeader(
        0xFEFD,
        PNDCPHeader.SET,
        PNDCPHeader.REQUEST,
        DCP_XID,
        0,
        len(value) + 6 + padding,
        payload=block,
    )
    return bytes(EthernetHeader(DCP_DST, DCP_SRC, 0x8892, payload=dcp))


golden["dcp_set_name_request"] = {
    "desc": "Set Name-of-Station 'device' (even length), qualifier 0x0000",
    "hex": _dcp_set(0x02, 0x02, b"device").hex(),
}
golden["dcp_set_name_request_odd"] = {
    "desc": "Set Name-of-Station 'plc-1' (odd length: DCP length counts an unsent pad byte)",
    "hex": _dcp_set(0x02, 0x02, b"plc-1").hex(),
}
golden["dcp_set_ip_request"] = {
    "desc": "Set IP 192.168.10.3/255.255.255.0 gw 192.168.10.1, qualifier temporary 0x0000",
    "hex": _dcp_set(
        0x01, 0x02, ip2s("192.168.10.3") + ip2s("255.255.255.0") + ip2s("192.168.10.1")
    ).hex(),
}

# Identify response: blocks as an IO device would answer them (6-byte block
# header incl. 2-byte BlockInfo, 2-byte aligned), parsed by read_response.
DCP_DEV_MAC = s2mac("00:1b:1b:aa:bb:cc")


def _resp_block(option: int, suboption: int, status: int, payload: bytes) -> bytes:
    out = bytes(PNDCPBlock(option, suboption, len(payload) + 2, status, payload=payload))
    if len(out) % 2 == 1:
        out += b"\x00"
    return out


_resp_blocks = b"".join(
    [
        _resp_block(0x02, 0x01, 0x0000, b"S7-1200"),  # DeviceType (odd -> padded)
        _resp_block(0x02, 0x02, 0x0000, b"device-io"),  # NameOfStation (odd -> padded)
        _resp_block(
            0x01,
            0x02,
            0x0001,  # BlockInfo: IP set
            ip2s("192.168.10.3") + ip2s("255.255.255.0") + ip2s("192.168.10.1"),
        ),
        _resp_block(0x02, 0x03, 0x0000, bytes([0x00, 0x2A, 0x01, 0x01])),  # DeviceID
        _resp_block(0x02, 0x04, 0x0000, bytes([0x01, 0x00])),  # Role: IO-Device
    ]
)
_resp_dcp = PNDCPHeader(
    0xFEFF,
    PNDCPHeader.IDENTIFY,
    PNDCPHeader.RESPONSE,
    DCP_XID,
    0,
    len(_resp_blocks),
    payload=_resp_blocks,
)
golden["dcp_identify_response"] = {
    "desc": "Identify response from 00:1b:1b:aa:bb:cc: type S7-1200, name device-io, "
    "ip 192.168.10.3, vendor 0x002A device 0x0101, role IO-Device",
    "hex": bytes(EthernetHeader(DCP_SRC, DCP_DEV_MAC, 0x8892, payload=_resp_dcp)).hex(),
}
golden["dcp_identify_response_vlan"] = {
    "desc": "same Identify response but 802.1Q-tagged (tpid 0x8100, tci 0)",
    "hex": bytes(
        EthernetVLANHeader(DCP_SRC, DCP_DEV_MAC, 0x8100, 0x0000, 0x8892, payload=_resp_dcp)
    ).hex(),
}

# --- RT_CLASS_1 cyclic frames (frame_id .. APDU trailer, no Ethernet header) -
_rt_input = RTFrame(
    frame_id=0xC001,
    cycle_counter=0x1234,
    data_status=DATA_STATUS_VALID
    | DATA_STATUS_PROVIDER_RUN
    | DATA_STATUS_STATION_OK
    | DATA_STATUS_STATE,
    transfer_status=0x00,
    payload=bytes(range(40)),
)
golden["rt_frame_c001"] = {
    "desc": "RT input frame id 0xC001, payload 00..27, cycle 0x1234, "
    "status VALID|RUN|OK|PRIMARY, transfer 0",
    "hex": _rt_input.to_bytes().hex(),
}

_rt_output = RTFrame(
    frame_id=0xC000,
    cycle_counter=0x0001,
    data_status=DATA_STATUS_VALID | DATA_STATUS_PROVIDER_RUN,
    transfer_status=0x00,
    payload=bytes([0xDE, 0xAD, 0xBE, 0xEF]),
)
golden["rt_frame_c000_small"] = {
    "desc": "RT output frame id 0xC000, payload deadbeef, cycle 1, "
    "status VALID|RUN, transfer 0",
    "hex": _rt_output.to_bytes().hex(),
}

golden["rt_ethernet_frame_c001"] = {
    "desc": "full Ethernet frame (dst 0a:1b:2c:3d:4e:5f, src 02:00:00:00:00:01, "
    "ethertype 0x8892) wrapping rt_frame_c001",
    "hex": build_ethernet_frame(DCP_DST, DCP_SRC, _rt_input).hex(),
}

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as f:
    json.dump(golden, f, indent=2)
    f.write("\n")

print(f"wrote {os.path.normpath(OUT)}")
for k, v in golden.items():
    print(f"  {k:24s} {v['hex']}")
