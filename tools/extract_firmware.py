#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Stage the HackRF One firmware image and derive this device's addr map.

The vendor ships a **raw .bin** (no ELF, no symbols), so there is nothing to
flatten: this tool copies the release binary into ``configs/`` and then proves,
from the bytes themselves, that the config's assumptions hold. It HARD-FAILS
rather than letting a wrong image or a wrong load base boot into nonsense.

What it checks, and why each check exists
-----------------------------------------

``sha256``
    The pinned release artifact (v2026.01.3 ``firmware-bin/hackrf_one_usb.bin``).

vector table
    ``init_sp`` and the reset vector must match what the config hardcodes.

**the reset vector must land on code** (playbook trap 2.81/2.84)
    A raw ``.bin`` says nothing about where it is loaded. Under the correct base
    (0x00000000, the LPC43xx boot shadow region) the reset vector 0x000080d1
    resolves to file offset 0x80d0; we require the Thumb bit and that the
    halfword there is not obviously data.

**the USB0 vector must be the only live IRQ entry**
    Every IRQ slot in this image points at one shared blocking handler except
    IRQ 8, which is ``usb0_isr``. That is the single strongest structural fact
    about this firmware -- USB is its whole interface -- and the device's
    interrupt plumbing (a deterministic tick on IRQ 8) depends on it. If a
    future release moves it, this fails loudly.

``firmware_info``
    The ``struct firmware_info_t`` at file offset 0x400 carries the magic
    ``HACKRFFW``, the supported-platform bitmap and the **version string** --
    which is the exact byte sequence the attack's oracle predicts
    (``PROVENANCE.md`` §2). We re-derive it here so the prediction is generated
    from the image rather than transcribed by hand.

It writes ``configs/hackrf_one.bin`` (git-ignored -- firmware bytes are never
committed) and ``configs/hackrf_one_addrs.yaml`` (synthetic symbol names for the
handful of addresses the config intercepts; a stripped image has no real ones,
so every name is unique-by-construction per playbook trap 2.26).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys

#: The LPC43xx boots the M4 out of the *shadow* region at 0x00000000, which the
#: boot ROM points at SPIFI. The linker script says so too
#: (``LPC4320_M4_memory.ld``: ``rom (rx) : ORIGIN = 0x00000000``).
LOAD_BASE = 0x00000000

EXPECT_SHA256 = "1d5f36c702677bc47086403c8e8c8a650d47d892a3c791e2dc9a7fa2bab1d72b"
EXPECT_SIZE = 45720
EXPECT_INIT_SP = 0x10087FE0          # top of LPC4320 local SRAM bank 2
EXPECT_RESET = 0x000080D1            # Thumb

#: IRQ 8 on the LPC43xx M4 is USB0. In this image it is the ONLY IRQ vector
#: that is not the shared blocking handler.
USB0_IRQ = 8
EXPECT_USB0_ISR = 0x00000D1D         # Thumb; the handler body is at 0xD1C

#: ``struct firmware_info_t`` is placed by the linker in its own section, which
#: lands immediately after the 0x400-byte vector table region.
FIRMWARE_INFO_OFF = 0x400
EXPECT_MAGIC = b"HACKRFFW"
#: PLATFORM_HACKRF1_OG (1<<1) | PLATFORM_HACKRF1_R9 (1<<3)
EXPECT_SUPPORTED_PLATFORM = 0x0000000A

OUT_BIN = "hackrf_one.bin"
OUT_ADDRS = "hackrf_one_addrs.yaml"

#: Addresses this device intercepts, with SYNTHETIC names (the image is
#: stripped). Keep every name unique -- two symbols at one address silently
#: collapse in the generated map and the second intercept is dropped.
SYMBOLS = {
    EXPECT_RESET & ~1: "hackrf_reset_vector",
    EXPECT_USB0_ISR & ~1: "hackrf_usb0_isr",
}


def fail(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "bin", nargs="?",
        default="/Users/user/Development/firmware-incoming/W2d-rf-rfid/"
                "hackrf/hackrf_one_usb.bin",
        help="path to the vendor's hackrf_one_usb.bin")
    ap.add_argument("--outdir", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "src", "rehostry_hackrf_one", "configs"))
    ap.add_argument("--allow-sha-mismatch", action="store_true",
                    help="stage a different build (everything else still checked)")
    args = ap.parse_args()

    try:
        raw = open(args.bin, "rb").read()
    except OSError as exc:
        return fail(f"cannot read {args.bin}: {exc}")

    digest = hashlib.sha256(raw).hexdigest()
    print(f"image      {args.bin}")
    print(f"size       {len(raw)} bytes")
    print(f"sha256     {digest}")
    if digest != EXPECT_SHA256 and not args.allow_sha_mismatch:
        return fail(f"sha256 mismatch (expected {EXPECT_SHA256})")
    if len(raw) != EXPECT_SIZE and not args.allow_sha_mismatch:
        return fail(f"size mismatch (expected {EXPECT_SIZE})")

    # --- the vector table --------------------------------------------------
    init_sp, reset = struct.unpack_from("<II", raw, 0)
    print(f"init_sp    0x{init_sp:08x}")
    print(f"reset      0x{reset:08x}")
    if init_sp != EXPECT_INIT_SP:
        return fail(f"init_sp 0x{init_sp:08x} != 0x{EXPECT_INIT_SP:08x}")
    if reset != EXPECT_RESET:
        return fail(f"reset 0x{reset:08x} != 0x{EXPECT_RESET:08x}")
    if not reset & 1:
        return fail("reset vector has no Thumb bit -- wrong image or wrong base")

    # The reset vector must resolve to CODE under LOAD_BASE. If the base were
    # wrong the offset would land in data (or off the end) and the run would
    # die somewhere unrelated to the mistake.
    off = (reset & ~1) - LOAD_BASE
    if not (0 <= off < len(raw) - 2):
        return fail(f"reset vector 0x{reset:08x} is outside the image under "
                    f"load base 0x{LOAD_BASE:08x}")
    op = struct.unpack_from("<H", raw, off)[0]
    if op in (0x0000, 0xFFFF):
        return fail(f"reset vector points at 0x{op:04x} -- that is data, not "
                    f"code; the load base is wrong")
    print(f"reset op   0x{op:04x} at file offset 0x{off:04x}  (code, ok)")

    # --- the USB0 vector: the device's entire reason for existing -----------
    nvec = 16 + 64
    vec = struct.unpack_from(f"<{nvec}I", raw, 0)
    usb_isr = vec[16 + USB0_IRQ]
    if usb_isr != EXPECT_USB0_ISR:
        return fail(f"IRQ{USB0_IRQ} vector 0x{usb_isr:08x} != "
                    f"0x{EXPECT_USB0_ISR:08x}")
    others = {v for i, v in enumerate(vec[16:]) if i != USB0_IRQ and v}
    if len(others) != 1:
        return fail(f"expected every non-USB0 IRQ vector to share one blocking "
                    f"handler, found {len(others)}: "
                    f"{sorted(hex(v) for v in others)}")
    blocking = others.pop()
    print(f"IRQ{USB0_IRQ} vector 0x{usb_isr:08x}  = usb0_isr  (the ONLY live IRQ)")
    print(f"other IRQs 0x{blocking:08x}  (one shared blocking handler)")

    # --- firmware_info: the attack's static prediction ----------------------
    magic = raw[FIRMWARE_INFO_OFF:FIRMWARE_INFO_OFF + 8]
    if magic != EXPECT_MAGIC:
        return fail(f"firmware_info magic {magic!r} != {EXPECT_MAGIC!r} at "
                    f"offset 0x{FIRMWARE_INFO_OFF:x}")
    struct_version, dfu_mode = struct.unpack_from("<HH", raw,
                                                  FIRMWARE_INFO_OFF + 8)
    supported, = struct.unpack_from("<I", raw, FIRMWARE_INFO_OFF + 12)
    vs_field = raw[FIRMWARE_INFO_OFF + 16:FIRMWARE_INFO_OFF + 48]
    version = vs_field.split(b"\x00")[0]
    print(f"firmware_info @ file 0x{FIRMWARE_INFO_OFF:x} (guest "
          f"0x{LOAD_BASE + FIRMWARE_INFO_OFF:08x}):")
    print(f"  magic              {magic.decode()}")
    print(f"  struct_version     {struct_version}")
    print(f"  dfu_mode           {dfu_mode}")
    print(f"  supported_platform 0x{supported:08x}")
    print(f"  version_string     {version.decode()!r}  "
          f"len={len(version)}  hex={version.hex()}")
    if supported != EXPECT_SUPPORTED_PLATFORM:
        return fail(f"supported_platform 0x{supported:08x} != "
                    f"0x{EXPECT_SUPPORTED_PLATFORM:08x}")
    if dfu_mode != 0:
        return fail("this is a DFU-mode image; the USB API is not present")

    # --- write ---------------------------------------------------------------
    os.makedirs(args.outdir, exist_ok=True)
    out_bin = os.path.join(args.outdir, OUT_BIN)
    with open(out_bin, "wb") as fh:
        fh.write(raw)
    print(f"wrote {out_bin}  ({len(raw)} bytes)")

    out_addrs = os.path.join(args.outdir, OUT_ADDRS)
    with open(out_addrs, "w") as fh:
        fh.write("# Copyright 2026 Christopher Wright\n")
        fh.write("# SPDX-License-Identifier: AGPL-3.0-or-later\n")
        fh.write("#\n")
        fh.write("# GENERATED by tools/extract_firmware.py -- do not hand-edit.\n")
        fh.write("# The vendor image is STRIPPED, so these are synthetic names\n")
        fh.write("# for the addresses this device intercepts. Recovered from\n")
        fh.write("# the vector table, not from a symbol table.\n")
        fh.write("symbols:\n")
        for addr, name in sorted(SYMBOLS.items()):
            fh.write(f"  {addr}: {name}\n")
        fh.write("\n# For humans:\n")
        for addr, name in sorted(SYMBOLS.items()):
            fh.write(f"#   0x{addr:08x}  {name}\n")
        fh.write(f"# version_string: {version.decode()!r} "
                 f"({len(version)} bytes, {version.hex()})\n")
    print(f"wrote {out_addrs}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
