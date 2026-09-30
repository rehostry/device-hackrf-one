<!--
Copyright 2026 Christopher Wright
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# PREDICTIONS — M8 interface parity, `device-hackrf-one`

**Committed BEFORE any graded parity run of this session** (lane `s0929-laneL`,
2026-09-29). Every number below is derived from *static* analysis of the image
the config loads; nothing here has been measured live yet. The point is that a
run can falsify it.

Firmware under test: `src/rehostry_hackrf_one/configs/hackrf_one.bin`,
45 720 B, sha256
`1d5f36c702677bc47086403c8e8c8a650d47d892a3c791e2dc9a7fa2bab1d72b`.

---

## 1. Why this row's M8 stops being UNDEFINED

`attack.py` says, in the comment above `LADDER_RUNGS`:

> *M5/M8 are NOT in this tuple. This image's entire command surface is vendor
> control transfers on USB0 EP0 — one endpoint, one framing layer, one peer —
> which RULES.md §1a settles as ONE interface, so M5 is undefined and the
> inventory has one entry, which §1b's boundary puts at M8-undefined.*

The **M5 half of that is still right and is not being touched.** The M8 half is
overturned by RULES.md §1a's ruling of 2026-09-29: *an M8 inventory entry is a
DECLARED CAPABILITY on a seam the firmware exposes, not a §1a-independent
interface*, and the fleet already grades `vesc-bms` at 16 COMM packets over one
CAN link on exactly that reading. The inventory therefore does **not** have one
entry; it has as many entries as this image's dispatch array has live slots.

⚠ This makes the number **worse**, not better, and that is the correct
direction (§1a: *"a parity number that fell because the inventory grew is a
better number"*).

## 2. The denominator, and where it comes from

Not from libhackrf, not from a header, not from `strings`, and not from "the
requests we implemented". From **the firmware's own dispatcher**, seven
instructions at 0x00000430:

```
0x0430  43 78        ldrb    r3, [r0, #1]        ; setup.bRequest
0x0432  3a 2b        cmp     r3, #0x3a           ; THE BOUND
0x0434  04 d8        bhi     0x440               ;   out of range -> STALL
0x0436  03 4a        ldr     r2, [pc, #0xc]      ; -> literal at 0x444 = 0x8524
0x0438  52 f8 23 30  ldr.w   r3, [r2, r3, lsl #2]
0x043c  03 b1        cbz     r3, 0x440           ;   NULL slot  -> STALL
0x043e  18 47        bx      r3
0x0440  01 20        movs    r0, #1              ; USB_REQUEST_STATUS_STALL
```

`cmp #0x3a` + `bhi` ⇒ bRequest 0..0x3a is in range ⇒ **59 declared slots**.
`cbz r3` ⇒ **a NULL slot is a request this build does not implement.**

`inventory.py` does not hardcode any of that. It searches guest memory for the
*shape* (`ldr.w Rt,[Rn,Rm,lsl #2]` + `cbz Rt` + `bx Rt`, preceded by
`cmp Rm,#imm8` + cond-branch + `ldr Rn,[pc,#imm]`), requires **exactly one**
match, and decodes the bound from the `cmp` and the base from the literal pool.
Zero matches or two matches raise rather than guess.

### PREDICTION 1 — the parse

| token | predicted |
|---|---|
| `bound_check_addr` | `0x00000432` |
| `bound_imm` | `0x3A` |
| `slots_declared` | **59** |
| `table_addr` | `0x00008524` |
| `null_indices` | `[0, 13, 22, 49, 50, 51, 52, 53, 54, 55]` |
| `implemented` | **49** |
| `non_pointer_slots` | `[]` (empty) |
| `table_sha256` | `20c8322b84ef0fc4d0a2429fc0c94a8186175ca6c563de807bbdae1c91e446f3` |

That table is the **SHRINK GUARD** (`inventory.PREREGISTERED`). A mismatch in
**either** direction VOIDS parity — it does not re-base the denominator on
whatever was parsed.

### PREDICTION 2 — §1d: declared vs implemented

**59 slots declared, 49 implemented by this image.** The 10 removals are
justified from the independent source itself — a NULL slot is the firmware
saying so — and never from "we did not implement it". Parity is graded against
**49**. Both numbers are reported; the header says which is which.

Cross-check against the published HackRF vendor-request set (host-side
`hackrf_vendor_request`): the gaps at 13 and 22 are the two requests upstream
retired (`write_cpld`, `set_if_freq`), which is independent corroboration that
this is the vendor-request array and not some other pointer table. ⚠ The
published set is a **cross-check only**; the graded denominator is the image's.

## 3. Predicted live behaviour

### PREDICTION 3 — the agreement control
All **10** NULL slots and both out-of-range requests (59, 255) are refused by
the firmware's own `usb_endpoint_stall()` — i.e. **12 of 12 refusals**, and
`ENDPTCTRL0 STALL set by the firmware (0x00010001)` appears in the log.
Counted as REPLIES, not shapes.

### PREDICTION 4 — parity, stated as a range because it is not yet measured
`STATUS.md`'s own header records, from the 2026-09-17 M6/M7 work, that *"the
seam stops answering after request 38 with the guest still executing
UNEXPLAINED"*. If that is still true, requests **39..48 and 56..58** cannot
complete, so:

* **Predicted: parity is NOT met.** Expected `passed` ≈ **34–38 of 49**
  (slots 1..12, 14..21, 23..38 = 36 entries, ± the boundary).
* Predicted rung: **M4**, with **M8 DEFINED and UNMET**.
* Predicted `guard_ok = true`, `agreement_ok = true`, `parity_void = false`.

⚠ I am predicting my own row falls short. If it comes back 49/49 that is a
result I must explain, not accept.

### PREDICTION 5 — the falsification knob binds
`--control bound-patch-0` rewrites the firmware's own `cmp` immediate to 0 at
the reset vector, *after* the inventory is parsed. Predicted: the guard still
PASSES (denominator untouched, 49), `passed` collapses to **0**, rung drops to
**M3** (no round trip at all). If `passed` does not collapse, the verdict was
never gated on the firmware's dispatcher and the claim is void.

### PREDICTION 6 — the shrink guard bites
`--control guard-offset` slides the array read by 4 bytes. Predicted parse:
`null_indices = [12, 21, 48, 49, 50, 51, 52, 53, 54]`, `implemented = 50` —
i.e. a denominator that **grew by one and moved every index**, exactly the
shape a sibling lane hit on ICP DAS (`[0,9,32,39]` for `(0,1,10,33)`).
Predicted `guard_ok = false`, `parity_void = true`, rung ≤ M4.

## 4. What is NOT predicted, because it is not being measured

* No claim about M5. One EP0 control seam, one peer: **M5 stays UNDEFINED**,
  and §1b says that sits together with a graded M8 without tension.
* No claim that the 10 NULL slots are absent from *other* HackRF builds. §1d:
  applicability is a property of the BUILD.
* No re-measurement of M6 or M7 in this session.
* Wall-clock numbers: the box carried load average 15–18 and eight other lanes
  during this session. Every latency below is **provisional** and the silence
  bound is derived per run from that run's own canary, not fixed.
