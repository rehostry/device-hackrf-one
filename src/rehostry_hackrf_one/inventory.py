# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The M8 inventory for `device-hackrf-one`, derived from the GUEST'S OWN BYTES.

RULES.md Rule 1 forbids grading parity against "the interfaces we implemented":
that denominator shrinks when we implement less. So the denominator here is
**this image's own USB vendor-request dispatch array**, and both of its
dimensions -- where it starts and how far it reaches -- are read out of the
firmware's own instructions rather than written down by us.

The dispatcher is seven instructions and it is the whole specification::

    0x0430  43 78        ldrb    r3, [r0, #1]        ; setup.bRequest
    0x0432  3a 2b        cmp     r3, #0x3a           ; <-- THE BOUND
    0x0434  04 d8        bhi     0x440               ;     out of range -> STALL
    0x0436  03 4a        ldr     r2, [pc, #0xc]      ; <-- THE TABLE BASE
    0x0438  52 f8 23 30  ldr.w   r3, [r2, r3, lsl #2]
    0x043c  03 b1        cbz     r3, 0x440           ;     NULL slot  -> STALL
    0x043e  18 47        bx      r3
    0x0440  01 20        movs    r0, #1              ; USB_REQUEST_STATUS_STALL
    0x0442  70 47        bx      lr

`cmp #0x3a` + `bhi` means bRequest 0..0x3a is in range, so the array has
**0x3a + 1 = 59 slots**; `cbz r3` means a **NULL slot is a request this build
does not implement**. RULES.md §1d is explicit that the inventory is of the
image under test, so the 59 protocol-declared slots are the declared surface
and the non-NULL subset is what *this* image implements. Both numbers are
reported; parity is graded against the non-NULL subset, and the NULL indices
are named so a reader can re-derive either number.

⚠ Nothing here is hardcoded except the *shape* of those instructions. The
dispatcher's address, the bound and the table base are all searched for and
decoded, so a different build moves them and this still finds them -- and if it
finds none, or more than one, it raises rather than guessing.

⚠ THE SHRINK GUARD. `PREREGISTERED` below was committed to
`PREDICTIONS-M8.md` before the graded runs. `check_guard()` compares the
freshly parsed inventory against it and **a mismatch in EITHER direction voids
parity** -- a denominator that grew is as much a reason to stop and look as one
that shrank (RULES.md §1a's 2026-09-29 ruling: growing is the correct
direction, but it must be noticed, not absorbed).
"""
from __future__ import annotations

import hashlib
from typing import Callable, Dict, List, Optional

#: Where to start looking for the dispatcher. The LPC43xx M4 executes out of
#: the boot shadow region at 0 (see the config), and this image is 45 720 B.
SEARCH_LO = 0x0000_0000
SEARCH_HI = 0x0000_C000

#: `ldr.w r3, [r2, r3, lsl #2]` -- a register-scaled word load with shift 2 is
#: the instruction that turns a request number into a function pointer. Encoded
#: T2 `LDR (register)`: first halfword 0xF850 | Rn, second 0x0000 | Rt<<12 |
#: Rm | shift<<4. We search for the *class*, not one encoding.
_LDR_REG_HI = 0xF850


class InventoryError(RuntimeError):
    """The dispatch table could not be derived. Never guess; never fall back."""


def _u16(buf: bytes, off: int) -> int:
    return buf[off] | (buf[off + 1] << 8)


def _u32(buf: bytes, off: int) -> int:
    return (buf[off] | (buf[off + 1] << 8)
            | (buf[off + 2] << 16) | (buf[off + 3] << 24))


def _find_dispatchers(code: bytes, base: int) -> List[Dict]:
    """Every site matching the seven-instruction dispatcher shape.

    Decoded by hand rather than with capstone so this runs inside the emulator
    process with no extra dependency, and so every field that ends up in the
    inventory is traceable to named bits of a named instruction.
    """
    out: List[Dict] = []
    for off in range(0, len(code) - 16, 2):
        # ldr.w Rt, [Rn, Rm, lsl #2]
        hw1 = _u16(code, off)
        if (hw1 & 0xFFF0) != _LDR_REG_HI:
            continue
        hw2 = _u16(code, off + 2)
        # bits 11..6 must be zero and imm2 (bits 5..4) must be 2, i.e. lsl #2.
        if (hw2 & 0x0FF0) != 0x0020:
            continue
        rn = hw1 & 0xF
        rt = (hw2 >> 12) & 0xF
        rm = hw2 & 0xF
        # ... immediately followed by cbz Rt / bx Rt
        cbz = _u16(code, off + 4)
        if (cbz & 0xFD00) != 0xB100:          # cbz/cbnz
            continue
        if (cbz & 0x0007) != rt:
            continue
        if _u16(code, off + 6) != (0x4700 | (rt << 3)):   # bx Rt
            continue
        # ... and preceded by  cmp Rm, #imm8 ; b<cond> ; ldr Rn, [pc, #imm8]
        cmp_hw = _u16(code, off - 6)
        if (cmp_hw & 0xF800) != 0x2800:       # cmp (immediate), T1
            continue
        if ((cmp_hw >> 8) & 0x7) != rm:
            continue
        bound = cmp_hw & 0xFF
        br = _u16(code, off - 4)
        if (br & 0xF000) != 0xD000:           # conditional branch, T1
            continue
        ldr_lit = _u16(code, off - 2)
        if (ldr_lit & 0xF800) != 0x4800:      # ldr Rt, [pc, #imm8*4], T1
            continue
        if ((ldr_lit >> 8) & 0x7) != rn:
            continue
        # PC for a T1 literal load is (addr of ldr + 4) & ~3
        lit_addr = (((base + off - 2) + 4) & ~3) + (ldr_lit & 0xFF) * 4
        lit_off = lit_addr - base
        if not (0 <= lit_off <= len(code) - 4):
            continue
        out.append({
            "bound_check_addr": base + off - 6,   # the `cmp Rm, #imm8` site
            "index_reg": rm,
            "bound_imm": bound,
            "slots": bound + 1,
            "literal_addr": lit_addr,
            "table_addr": _u32(code, lit_off),
        })
    return out


def derive(read_bytes: Callable[[int, int], bytes],
           table_offset: int = 0) -> Dict:
    """Parse the dispatch inventory out of memory reachable by `read_bytes`.

    `read_bytes(addr, size)` is the GUEST's memory when this runs inside the
    emulator. `table_offset` exists ONLY so the shrink guard can be
    deliberately falsified by reading the array off by a few bytes -- the
    failure mode a sibling lane hit for real on ICP DAS, where a 4-byte slip
    turned `(0,1,10,33)` into `[0,9,32,39]`.
    """
    code = read_bytes(SEARCH_LO, SEARCH_HI - SEARCH_LO)
    sites = _find_dispatchers(code, SEARCH_LO)
    if len(sites) != 1:
        raise InventoryError(
            "expected exactly one vendor-request dispatcher, found %d: %r"
            % (len(sites), [hex(s["bound_check_addr"]) for s in sites]))
    site = dict(sites[0])
    n = site["slots"]
    tab_addr = site["table_addr"] + table_offset
    raw = read_bytes(tab_addr, n * 4)
    if len(raw) < n * 4:
        raise InventoryError("short read of the dispatch array at 0x%08x"
                             % tab_addr)
    slots = [_u32(raw, i * 4) for i in range(n)]
    nulls = [i for i, w in enumerate(slots) if w == 0]
    impl = [i for i, w in enumerate(slots) if w != 0]
    # Every implemented slot must look like a Thumb code pointer inside the
    # image. If one does not, we are not reading the array -- say so loudly
    # rather than counting garbage as a capability.
    bad = [i for i in impl
           if not (slots[i] & 1) or not (SEARCH_LO < (slots[i] & ~1) < SEARCH_HI)]
    site.update({
        "table_addr_read": tab_addr,
        "table_offset": table_offset,
        "slots_declared": n,
        "null_indices": nulls,
        "implemented_indices": impl,
        "implemented": len(impl),
        "nulls": len(nulls),
        "non_pointer_slots": bad,
        "slot_words": ["0x%08x" % w for w in slots],
        "table_sha256": hashlib.sha256(raw).hexdigest(),
    })
    return site


# ---------------------------------------------------------------------------
# THE SHRINK GUARD
#
# Pre-registered in PREDICTIONS-M8.md and committed BEFORE the graded runs.
# These are tokens to compare against, not a source of truth: the inventory is
# always re-parsed, and this only decides whether to BELIEVE the parse.
PREREGISTERED = {
    "bound_imm": 0x3A,
    "slots_declared": 59,
    "null_indices": [0, 13, 22, 49, 50, 51, 52, 53, 54, 55],
    "implemented": 49,
    "table_addr": 0x0000_8524,
    "bound_check_addr": 0x0000_0432,
}


def check_guard(inv: Dict) -> Dict:
    """Compare a parse against the pre-registered token set.

    Returns `{"ok": bool, "mismatches": [...]}`. `ok` false VOIDS parity --
    it does not lower it, and it does not silently re-base the denominator on
    whatever was parsed.
    """
    bad = []
    for key, want in PREREGISTERED.items():
        got = inv.get(key)
        if isinstance(want, list):
            same = list(got or []) == want
        else:
            same = got == want
        if not same:
            bad.append({"field": key, "preregistered": want, "parsed": got})
    if inv.get("non_pointer_slots"):
        bad.append({"field": "non_pointer_slots", "preregistered": [],
                    "parsed": inv["non_pointer_slots"]})
    return {"ok": not bad, "mismatches": bad}


#: The log line the guest-memory parse emits, so a parity run can prove its
#: denominator came out of THAT run's guest memory and not off the disk.
LOG_TAG = "M8-INVENTORY"


def log_line(inv: Dict) -> str:
    import json
    return "%s %s" % (LOG_TAG, json.dumps(inv, sort_keys=True))


def parse_log_line(text: str) -> Optional[Dict]:
    import json
    for line in text.splitlines():
        i = line.find(LOG_TAG + " ")
        if i < 0:
            continue
        try:
            return json.loads(line[i + len(LOG_TAG) + 1:])
        except ValueError:
            continue
    return None
