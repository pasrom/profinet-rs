#!/usr/bin/env python3
"""Structural golden oracle for the profinet-rs gsdml module.

Loads tests/data/demo.gsdml.xml with profinet-py (the reference implementation
being ported) and dumps the parsed device model plus the IOSlot lists derived
from it into tests/golden/gsdml.json as plain JSON. The Rust gsdml parser
asserts structural equality against this dump.

Run with the profinet-py venv active:
    cd ~/git/profinet-py && . .venv/bin/activate
    python ~/git/profinet-rs/tools/gen_gsdml_golden.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/git/profinet-py"))

from profinet.blocks import SlotInfo  # noqa: E402
from profinet.gsdml import load_gsdml  # noqa: E402

HERE = os.path.dirname(__file__)
XML = os.path.join(HERE, "..", "tests", "data", "demo.gsdml.xml")
OUT = os.path.join(HERE, "..", "tests", "golden", "gsdml.json")


def dump_submodule(sub):
    return {
        "id": sub.id,
        "submodule_ident": sub.submodule_ident,
        "input_length": sub.input_length,
        "output_length": sub.output_length,
    }


def dump_refs(useable, fixed, allowed):
    """Serialize the three parallel ref dicts as one list in document order."""
    return [
        {"target": target, "fixed": fixed.get(target, []), "allowed": allowed.get(target, [])}
        for target in useable
    ]


def dump_dap(dap):
    return {
        "id": dap.id,
        "module_ident": dap.module_ident,
        "submodules": [dump_submodule(s) for s in dap.submodules],
        "system_submodules": [
            {"subslot_number": s.subslot_number, "submodule_ident": s.submodule_ident}
            for s in dap.system_submodules
        ],
        "useable_modules": dump_refs(dap.useable_modules, dap.fixed_slots, dap.allowed_slots),
    }


def dump_module(mod):
    return {
        "id": mod.id,
        "module_ident": mod.module_ident,
        "submodules": [dump_submodule(s) for s in mod.submodules],
        "useable_submodules": dump_refs(
            mod.useable_submodules, mod.fixed_subslots, mod.allowed_subslots
        ),
    }


def dump_io_slot(s):
    return {
        "slot": s.slot,
        "subslot": s.subslot,
        "module_ident": s.module_ident,
        "submodule_ident": s.submodule_ident,
        "input_length": s.input_length,
        "output_length": s.output_length,
    }


device = load_gsdml(XML)

# build_io_slots with the GSDML defaults (FixedInSlots assignment).
io_slots = device.build_io_slots()

# build_io_slots_from_device: feed the discovered-slot view of the same device
# (as slot discovery against the real device would report it) and let the GSDML
# catalog fill in the IO lengths.
device_slots = [
    SlotInfo(
        slot=s.slot,
        subslot=s.subslot,
        module_ident=s.module_ident,
        submodule_ident=s.submodule_ident,
    )
    for s in io_slots
]
# Plus one slot unknown to the GSDML: lengths must fall back to 0.
device_slots.append(SlotInfo(slot=9, subslot=1, module_ident=0xDEAD, submodule_ident=0xBEEF))

golden = {
    "device": {
        "vendor_id": device.vendor_id,
        "device_id": device.device_id,
        "daps": [dump_dap(d) for d in device.daps],
        "modules": [dump_module(m) for m in device.modules.values()],
        "submodule_catalog": [dump_submodule(s) for s in device.submodule_catalog.values()],
    },
    "io_slots": [dump_io_slot(s) for s in io_slots],
    "io_slots_from_device": [
        dump_io_slot(s) for s in device.build_io_slots_from_device(device_slots)
    ],
}

with open(OUT, "w") as f:
    json.dump(golden, f, indent=2)
    f.write("\n")

print(f"wrote {os.path.normpath(OUT)}")
print(json.dumps(golden, indent=2))
