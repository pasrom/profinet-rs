#!/usr/bin/env python3
"""Golden-byte oracle for the transport module's response parsers.

Builds synthetic RPC RESPONSE / device-CControl packets with profinet-py's
structs (PNRPCHeader, PNNRDData, PNIODHeader, PNIOCRBlockRes, ...) using
FIXED inputs, and dumps them plus the expected parse results to
tests/golden/transport.json.

profinet-py only *builds* big-endian, so the little-endian (drep=0x10)
variants are packed here with struct.pack("<...") -- byte-for-byte what an
LE device puts on the wire for the RPC header fields.
The NRD/IOD/block payload stays big-endian in both variants, matching how
rpc.py parses responses (PNNRDData/PNIODHeader are always big-endian).

Run with the profinet-py venv active (needs the `construct` dep):
    cd ~/git/profinet-py && . .venv/bin/activate
    python ~/git/profinet-rs/tools/gen_transport_golden.py
"""

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _golden_common import dump, nrd, use_reference  # noqa: E402

use_reference()

from profinet.protocol import (  # noqa: E402
    PNAlarmCRBlockRes,
    PNBlockHeader,
    PNIOCRBlockRes,
    PNIODHeader,
    PNIODReleaseBlock,
    PNNRDData,
    PNRPCHeader,
)

OUT = os.path.join(os.path.dirname(__file__), "..", "tests", "golden", "transport.json")

# Fixed UUIDs/keys (mirror the other golden generators).
AR = bytes(range(16))  # ar-uuid 00 01 .. 0f
ACT = bytes(range(16, 32))  # activity-uuid 10 11 .. 1f
OBJ = bytes(range(32, 48))  # object-uuid 20 21 .. 2f
IFACE = PNRPCHeader.IFACE_UUID_DEVICE
SESSION_KEY = 0x1234

RECORD_PAYLOAD = bytes([0xDE, 0xAD, 0xBE, 0xEF])


def rpc_be(packet_type, opnum, seq, body, flags1=0x00):
    """RPC header via PNRPCHeader (big-endian, drep=00 00 00)."""
    return bytes(
        PNRPCHeader(
            0x04,
            packet_type,
            flags1,
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
            len(body),
            0,
            0,
            0,
            payload=body,
        )
    )


def rpc_le(packet_type, opnum, seq, body, flags1=0x00, serial=(0, 0)):
    """RPC header with drep=0x10: multi-byte fields little-endian."""
    hdr = struct.pack(
        "!BBBB3sB", 0x04, packet_type, flags1, 0x00, bytes([0x10, 0x00, 0x00]), serial[0]
    )
    hdr += OBJ + IFACE + ACT
    hdr += struct.pack(
        "<IIIHHHHHBB", 0, 1, seq, opnum, 0xFFFF, 0xFFFF, len(body), 0, 0, serial[1]
    )
    return hdr + body


# --- READ response: NRD(status 0) + IODReadResponse + record payload --------
iod = bytes(
    PNIODHeader(
        bytes(PNBlockHeader(PNBlockHeader.IODReadResponseHeader, 60, 0x01, 0x00)),
        0,  # sequence_number
        AR,
        0,  # api
        1,  # slot
        1,  # subslot
        0,  # padding1
        0xAFF0,  # index
        len(RECORD_PAYLOAD),
        bytes(16),
        bytes(8),
        payload=RECORD_PAYLOAD,
    )
)
nrd_ok = bytes(PNNRDData(0, len(iod), len(iod), 0, len(iod), payload=iod))

read_resp_be = rpc_be(PNRPCHeader.RESPONSE, PNRPCHeader.READ, 7, nrd_ok)
read_resp_le = rpc_le(PNRPCHeader.RESPONSE, PNRPCHeader.READ, 7, nrd_ok)

# --- error / skip / fault vectors -------------------------------------------
PNIO_STATUS = 0xDE80B0C0  # arbitrary non-zero PNIO args_status
nrd_err = bytes(PNNRDData(PNIO_STATUS, 0, 0, 0, 0, payload=b""))
error_resp = rpc_be(PNRPCHeader.RESPONSE, PNRPCHeader.READ, 8, nrd_err)

echoed_request = rpc_be(PNRPCHeader.REQUEST, PNRPCHeader.READ, 7, nrd_ok, flags1=0x20)
FAULT_CODE = 0x0155
fault_resp = rpc_be(PNRPCHeader.FAULT, FAULT_CODE, 9, b"")
reject_resp = rpc_be(PNRPCHeader.REJECT, 0, 10, b"")

# --- CONNECT response: ARBlockRes + IOCRBlockRes x2 + AlarmCRBlockRes -------
ar_res = bytes(PNBlockHeader(0x8101, 30, 0x01, 0x00)) + struct.pack(
    "!H16sH6sH", 0x0001, AR, SESSION_KEY, bytes(6), 0x8892
)
iocr_res_in = bytes(
    PNIOCRBlockRes(bytes(PNBlockHeader(0x8102, 8, 0x01, 0x00)), 1, 1, 0xC001)
)
iocr_res_out = bytes(
    PNIOCRBlockRes(bytes(PNBlockHeader(0x8102, 8, 0x01, 0x00)), 2, 2, 0x8002)
)
alarm_res = bytes(
    PNAlarmCRBlockRes(bytes(PNBlockHeader(0x8103, 8, 0x01, 0x00)), 1, 3, 200)
)
connect_blocks = ar_res + iocr_res_in + iocr_res_out + alarm_res
connect_nrd = bytes(
    PNNRDData(0, len(connect_blocks), len(connect_blocks), 0, len(connect_blocks), payload=connect_blocks)
)
connect_resp = rpc_be(PNRPCHeader.RESPONSE, PNRPCHeader.CONNECT, 0, connect_nrd)

# --- device CControl ApplicationReady request + expected DONE response ------
# Port of application_ready(): the device sends a REQUEST with opnum CONTROL
# whose NRD is in the device DREP byte order while the control block itself
# is big-endian; the controller answers with block 0x8112 / cmd DONE (0x0008)
# echoing DREP, UUIDs, sequence number and serials.
cc_block = bytes(
    PNIODReleaseBlock(
        bytes(PNBlockHeader(0x0112, 28, 0x01, 0x00)),
        0,
        AR,
        SESSION_KEY,
        0,
        0x0002,  # control_command = ApplicationReady
        0,
        payload=b"",
    )
)


def ccontrol_vectors(bo, drep0):
    nrd_req = struct.pack(f"{bo}IIIII", 1500, len(cc_block), 1500, 0, len(cc_block)) + cc_block
    req = struct.pack(
        "!BBBB3sB", 0x04, PNRPCHeader.REQUEST, 0x20, 0x00, bytes([drep0, 0x00, 0x00]), 0x2A
    )
    req += OBJ + IFACE + ACT
    req += struct.pack(
        f"{bo}IIIHHHHHBB", 0, 1, 5, PNRPCHeader.CONTROL, 0xFFFF, 0xFFFF, len(nrd_req), 0, 0, 0x2B
    )
    req += nrd_req

    # Expected response, packed exactly as application_ready() does.
    resp_control = bytes(
        PNIODReleaseBlock(
            bytes(PNBlockHeader(0x8112, 28, 0x01, 0x00)),
            0,
            AR,
            SESSION_KEY,
            0,
            0x0008,  # CONTROL_CMD_DONE
            0,
            payload=b"",
        )
    )
    n = len(resp_control)
    # maximum_count echoes the capacity the request advertised, not the size of
    # our own answer: the device sized its receive buffer from what it asked
    # for. flags1 0x0A (LASTFRAG | NOFACK) is what real controllers send.
    nrd_max_count = struct.unpack_from(f"{bo}I", nrd_req, 8)[0]
    resp_nrd = struct.pack(f"{bo}IIIII", 0, n, nrd_max_count, 0, n) + resp_control
    resp = struct.pack(
        "!BBBB3sB", 0x04, PNRPCHeader.RESPONSE, 0x0A, 0x00, bytes([drep0, 0x00, 0x00]), 0x2A
    )
    resp += OBJ + IFACE + ACT
    resp += struct.pack(
        f"{bo}IIIHHHHHBB", 0, 1, 5, PNRPCHeader.CONTROL, 0xFFFF, 0xFFFF, len(resp_nrd), 0, 0, 0x2B
    )
    resp += resp_nrd
    return req, resp


cc_req_le, cc_resp_le = ccontrol_vectors("<", 0x10)
cc_req_be, cc_resp_be = ccontrol_vectors(">", 0x00)

golden = {
    "read_response_be": {
        "desc": "RPC RESPONSE (drep BE) wrapping NRD(status 0) + IODReadRes + payload",
        "hex": read_resp_be.hex(),
        "opnum": PNRPCHeader.READ,
        "seq": 7,
        "body": nrd_ok.hex(),
        "record_payload": RECORD_PAYLOAD.hex(),
    },
    "read_response_le": {
        "desc": "same response but drep=0x10: RPC header fields little-endian",
        "hex": read_resp_le.hex(),
        "opnum": PNRPCHeader.READ,
        "seq": 7,
        "body": nrd_ok.hex(),
        "record_payload": RECORD_PAYLOAD.hex(),
    },
    "error_response": {
        "desc": "RESPONSE whose NRD args_status is a non-zero PNIO error",
        "hex": error_resp.hex(),
        "args_status": PNIO_STATUS,
    },
    "echoed_request": {
        "desc": "our own REQUEST looped back; _send_receive must skip it",
        "hex": echoed_request.hex(),
    },
    "fault_response": {
        "desc": "FAULT packet; opnum field carries the fault code",
        "hex": fault_resp.hex(),
        "fault_code": FAULT_CODE,
    },
    "reject_response": {
        "desc": "REJECT packet",
        "hex": reject_resp.hex(),
    },
    "connect_response": {
        "desc": "CONNECT RESPONSE: ARBlockRes + IOCRBlockRes(in,out) + AlarmCRBlockRes",
        "hex": connect_resp.hex(),
        "nrd_payload": connect_blocks.hex(),
        "input_frame_id": 0xC001,
        "output_frame_id": 0x8002,
    },
    "ccontrol_request_le": {
        "desc": "device CControl ApplicationReady REQUEST, drep=0x10 (LE NRD)",
        "hex": cc_req_le.hex(),
        "block_type": 0x0112,
        "control_command": 0x0002,
        "nrd_body": cc_block.hex(),
    },
    "ccontrol_response_le": {
        "desc": "expected controller DONE response for ccontrol_request_le",
        "hex": cc_resp_le.hex(),
        "ar_uuid": AR.hex(),
        "session_key": SESSION_KEY,
    },
    "ccontrol_request_be": {
        "desc": "device CControl ApplicationReady REQUEST, drep BE",
        "hex": cc_req_be.hex(),
        "block_type": 0x0112,
        "control_command": 0x0002,
        "nrd_body": cc_block.hex(),
    },
    "ccontrol_response_be": {
        "desc": "expected controller DONE response for ccontrol_request_be",
        "hex": cc_resp_be.hex(),
        "ar_uuid": AR.hex(),
        "session_key": SESSION_KEY,
    },
}

os.makedirs(os.path.dirname(OUT), exist_ok=True)
dump(OUT, golden)
for k, v in golden.items():
    if isinstance(v, dict) and "hex" in v:
        print(f"  {k:28s} {len(v['hex']) // 2:4d}B {v['hex'][:64]}...")
