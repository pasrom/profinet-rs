"""Shared plumbing for the golden-vector generators.

Every generator uses profinet-py as the oracle: it builds the reference bytes
with the reference's own structs and records what the reference's parsers make
of them. Three things follow from that and belong in one place rather than in
seven copies:

- which checkout is the oracle (PROFINET_PY, else ~/git/profinet-py),
- the NDR wrapper, whose ArgsMaximum comes from the reference's own constant,
- which revision a vector set was generated from, stamped into the JSON.

The oracle must be a revision that has NDR_ARGS_MAXIMUM (profinet-py 0.6.3 or
newer); an older checkout fails the import rather than silently producing
vectors with the previous value.
"""

import json
import os
import subprocess
import sys


def reference_path() -> str:
    """Path of the profinet-py checkout used as the oracle."""
    return os.environ.get("PROFINET_PY", os.path.expanduser("~/git/profinet-py"))


def use_reference() -> str:
    """Put the oracle on sys.path and return its location."""
    path = reference_path()
    sys.path.insert(0, path)
    return path


def reference_revision() -> str:
    """Short revision of the oracle checkout, or "unknown" outside a repo."""
    try:
        out = subprocess.run(
            ["git", "-C", reference_path(), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def nrd(payload: bytes) -> bytes:
    """NRD wrapper exactly as RPCCon._create_nrd packs it.

    ArgsMaximum advertises the largest response we accept and must be >=
    ArgsLength of the request, so it tracks the reference's receive buffer
    rather than a fixed number.
    """
    from profinet.protocol import PNNRDData
    from profinet.rpc import NDR_ARGS_MAXIMUM

    args_max = max(NDR_ARGS_MAXIMUM, len(payload))
    return bytes(
        PNNRDData(args_max, len(payload), args_max, 0, len(payload), payload=payload)
    )


def dump(out_path: str, golden: dict) -> None:
    """Write a golden file, stamped with the oracle revision it came from."""
    stamped = {
        "_meta": {
            "reference": "f0rw4rd/profinet-py",
            "revision": reference_revision(),
        },
        **golden,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(stamped, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {os.path.normpath(out_path)} ({len(golden)} vectors)")
