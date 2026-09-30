<!-- rehostry-census: milestone=M7 landed=true verdict=M4-OK verified=2026-09-17 method=live-run n=none note=M8-UNDEFINED-to-DEFINED:inventory=the-images-own-59-slot-USB-vendor-request-dispatch-array-parsed-from-GUEST-MEMORY-every-run-bound-from-its-own-cmp-0x3a-and-membership-from-its-non-NULL-slots;59-declared-49-implemented-by-this-build-the-10-NULL-slots-are-the-firmware-saying-so;DENOMINATOR-FINISHED-and-control-gated-both-ways-bound-patch-0-gives-0of49-M3-and-guard-offset-VOIDS-at-50;agreement-12of12-REFUSED-on-a-healthy-seam;NUMERATOR-NOT-COMPLETELY-MEASURED-neither-graded-arm-finished-BOUND-n-in-6-to-40-of-49-NOT-a-parity-fraction;every-failure-is-OUT_STAGE-our-host-model-cannot-drive-a-host-to-device-data-stage-and-ZERO-non-NULL-slots-were-STALLed-so-the-shortfall-is-OUR-harness-NOT-the-firmware;M5-still-undefined-one-EP0-control-seam-one-peer;verified-date-is-the-M6-M7-run-of-2026-09-17-which-THIS-session-did-NOT-re-run;M1-to-M4-re-measured-live-2026-09-29-lane-s0929-laneL;the-post-request-38-deaf-seam-is-still-UNEXPLAINED -->
<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# STATUS — device-hackrf-one

**Milestone reached: M4** — a real USB vendor control transfer round-trip into
the firmware's own USB device stack, with the reply read back out of the
transfer descriptor the firmware itself built, plus a negative control the
firmware refuses.

| | |
|---|---|
| Device | Great Scott Gadgets **HackRF One** (NXP LPC4320, Cortex-M4 / ARMv7E-M) |
| Firmware | stock **v2026.01.3**, `hackrf_one_usb.bin`, 45 720 B, stripped |
| Seam | **USB0 EP0** — `hackrf_*` vendor-specific control transfers |
| Core | installed `halucinator@dev` (Bucket A — **no core change**) |
| Bridge / panel | tcp/**21209** · http/**9019** · ZMQ 6118/6119 |

---

## M6 / M7 — measured live 2026-09-17 (lane `s0917-laneG`)

**Milestone: M7.** This row has argued M1, M2 and M3 in English since it was
written, while the code could not emit any of them. `milestone` took exactly
**two** values:

```python
res["milestone"] = ("M4" if res["usb_vendor_round_trip"]
                    else "unproven (no protocol round trip observed)")
```

and on the boot-failure path the key was **absent entirely**. The negative value
is a prose string no milestone parser can read: the fleet guard's
`_milestone_num` turns it into `-` and the row scores a bare `WALL` with no rung
at all. Enumerated, that is **384 of 512 assignments** landing in one
undifferentiated `WALL` bucket.

### The ladder, enumerated over all 512 assignments (`tools/enumerate_ladder.py`)

|  | BEFORE (`4d7c7ed`) | AFTER (imported) |
|---|---|---|
| PRINTABLE | `<absent>`, `M4`, `unproven (no protocol round trip observed)` | `M0,M1,M2,M3,M4,M6,M7` |
| WRITTEN (`ast` over `_ladder`) | n/a — no `_ladder` existed | `M0,M1,M2,M3,M4,M6,M7` |
| DECLARED (`LADDER_RUNGS`) | n/a | `M0,M1,M2,M3,M4,M6,M7` |
| PRINTABLE == WRITTEN == DECLARED | — | **True** |
| dead branches | — | **none** |
| credited `M4-OK` | 64 of 512 | 32 of 512 |
| `DEFECT-landed-without-M4` | 0 | 0 |
| assignments gaining a NEW `M4-OK` credit | — | 16 |
| … of which **UNEARNED** (no round trip) | — | **0** |
| … of which **REALISABLE** | — | **0** |
| false floor **UP** (printed > entitled) | 96 | **0** |
| … of which printed a rung with `guest_executed` false | 64 | **0** |
| false floor **DOWN** (M6/M7 earned, printed lower) | 8 | **0** |
| guard histogram BEFORE | `WALL: 384`, `M4-OK: 64`, `WALL-M4: 64` | |
| guard histogram AFTER | | `WALL-M0: 256, WALL-M1: 128, WALL-M2: 64, WALL-M3: 32, M4-OK: 32` |

⚠ **The 16 "new credits" are an artefact of the enumeration's fact model, and
that is stated rather than papered over.** `neg_stalled` is a free boolean here
because in the old code it was independent of the rung. In the new code it is a
**component** of `round_trip` (§1c: a discriminating round trip needs valid
accepted *and* invalid rejected), so `round_trip → neg_stalled` and every one of
those 16 assignments is unreachable in a real run. Restricted to realisable
assignments the gain is **0**, and the enumerator prints both numbers.

### M6 — stateful, and the pair was CHOSEN BY MEASUREMENT

The firmware's own dispatch table was swept live (requests 0..38, each bracketed
by a known-good canary, PORTBASE 33410). It STALLs at 0, 13, 22, 25, 26 and
answers elsewhere. Three write/read pairs could carry state, and all three were
tried (PORTBASE 33420):

| pair | requests | read answers |
|---|---|---|
| MAX2837 | 2 / 3 | a **constant** `0x0150` on every round |
| SI5351C | 4 / 5 | `0` on every round |
| **RFFC5071** | **8 / 9** | **reads back exactly what was written** |

**That two of the three do NOT hold state is what makes the third evidence
rather than an echo.** A harness or a bus model reflecting writes would have
made all three pass.

Each write is an **ACK-only** vendor request carrying its payload entirely in
`wValue`/`wIndex` with no data stage, so it is issued with `wLength = 0`. A
non-zero length leaves the host waiting for a data stage the firmware never
starts — which is exactly why the first sweep mis-read every write slot as
"timeout".

M6 then writes **three** registers (0, 5, 11) with three **different** values
drawn at run time and reads all three back. An echo of "the last value written"
answers all three the same and fails. **5 of 5 rounds on each of three live
arms.**

### Where the state lives — answered by the knob, not by argument

With `HAL_HRF_M6_NO_WRITE=1` the writes are withheld and nothing else changes.
The three registers then return **three different constants, stable across all
five rounds**:

```
reg 0  -> 0xfffa      reg 5  -> 0xb0bf      reg 11 -> 0x0400
```

Those are the firmware's own reset defaults for those registers, out of its own
table. So the read path is **per-register** and returns firmware state — not an
echo, and not a single reflected value.

### M7 — 6 of 6 classes, 0 VOID

| class | input | verdict |
|---|---|---|
| H1 | request 13 — NULL in the firmware's own dispatch table | STALL, TOLERATED |
| H2 | request 0 — NULL | STALL, TOLERATED |
| H3 | request 25 — NULL | STALL, TOLERATED |
| H4 | `RFFC5071_READ` for register index `0x00ff` | refused, TOLERATED |
| H5 | `RFFC5071_WRITE` value `0xffff` to register `0x00ff` | refused, TOLERATED |
| H6 | a supported read asked for `wLength = 0xffff` | TOLERATED |

Every class is **pre**-probed as well as post-probed.

⚠ **H6 was pre-registered as the highest risk of a manufactured class on this
row** — a large `wLength` is the exact shape that has wedged a host USB model on
this fleet before, producing a wall of timeouts indistinguishable from a
firmware that went deaf. It is ordered **last** so the classes before it are
already recorded if it takes the seam down. Measured: it did **not** wedge
anything; the canary answered immediately before and immediately after.

### Falsification knobs — two, both demonstrably non-inert

| arm | PORTBASE | milestone | IRQ events | M6 | M7 |
|---|---|---|---|---|---|
| live | 33430 | **M7** | 19 | 5/5 | 6/6 |
| live | 33480 | **M7** | 19 | 5/5 | 6/6 |
| live | 33490 | **M7** | 21 | 5/5 | 6/6 |
| `HAL_HRF_M6_NO_WRITE=1` | 33440 | **M4** | 19 | **0/5** | 6/6 |
| `HAL_HRF_CPLD_CORRUPT=1` | 33460 | **M1** | **2847** | — | — |
| **no firmware** | 33470 | **M0** | **0** | — | — |

`HAL_HRF_M6_NO_WRITE` is **surgical**: M6 falls to 0/5 while M4 and all six M7
classes are untouched. `HAL_HRF_CPLD_CORRUPT` is the stronger shape — the
modelled CPLD readback returns **one bit wrong**, so the firmware's own
`cpld_xc2c64a_jtag_sram_verify()` refuses its own configuration and it never
programs the USB controller. **No firmware byte is edited.**

The bottom three rows are the point: **M1 with 2847 IRQ events is a different
thing from M0 with 0**, and the run says which. That distinction did not exist
before today — see below.

### A downward false floor found on the knob arm itself

The first `HAL_HRF_CPLD_CORRUPT` run printed `milestone: M0` with
`guest_executed: false`, because the M1/M2/M3 witnesses were measured **after**
the enumeration gate and the knob returns before it. A run that booted,
executed, and bit-banged CPLD configuration rows before its own verify refused
was therefore reporting the **same rung as a run with no firmware on disk** —
and it landed on exactly the arm whose purpose is to show the low rungs are
reachable with the guest running. The witnesses are now measured on every path.

### One real gap in the client

`_Rehost.vendor_request` hardcoded `wValue` and `wIndex` to 0, even though the
bridge's own line protocol has always accepted them. Every HackRF register write
carries its payload in those two fields and has no data stage, so with both
pinned to 0 **half this firmware's command surface was undrivable from the
attack** — only the handful of parameterless reads could be exercised. And
`spawn.BRIDGE_PORT` was a bare constant while the child was given
`HAL_HRF_USB_PORT`, so relocating the port moved the guest's listener and left
the client dialling 21209.

### ⚠ NOT CLAIMED, and open

* **The seam stops answering after request 38, with the guest still executing.**
  The sweep wedged there: the backend went on reporting exception returns inside
  the SPI transfer loop while every subsequent request, canary included,
  returned nothing. Whether that is the firmware or our host USB model is
  **unresolved**, and it is why the M7 classes are confined to requests ≤ 33.
  **An unexplored region is not a tolerance claim** — it is unfinished work.
* **M5 is UNDEFINED.** This image's entire command surface is vendor control
  transfers on USB0 EP0 — one endpoint, one framing layer, one peer — which
  §1a settles as one interface. M6/M7 do not require M5 (§1a ruling, 2026-09-02).
* **M8 is NO LONGER UNDEFINED.** §1a's ruling of 2026-09-29 makes an M8 entry a
  **declared capability on a seam**, not a §1a-independent interface, so this
  image's dispatch array supplies **49** of them. The denominator is finished and
  control-gated; the **numerator is not measured to completion** — see "M8
  interface parity" below, which reports a BOUND and says so. A graded M8 and an
  undefined M5 sit together without tension (§1b).

---

## The milestones, and the alternative explanation ruled out for each

### M1 — boots without faulting

**Evidence.** Zero `UC_ERR`, zero `Traceback`, zero `FETCH-DERAIL` across every
run in this repo's history, including the 260-second falsification run below.
The reset vector, the load base and the vector table are proved from the image
by `tools/extract_firmware.py`, which hard-fails on any mismatch.

**Alternative ruled out — "it is not faulting because it is not executing."**
It is: the PC histogram (`HAL_PC_SAMPLE=1`) attributes millions of executions
per window to named, disassembled firmware routines (`adc_read` at 0x6c48,
`cpu_clock_init`'s PLL waits at 0x4adc, `ipc_halt_m0` at 0x8076,
`spi_ssp_transfer_byte` at 0x607c), and each wall below was cleared by
modelling a register, not by relaxing a check.

### M2 — drivers initialise

**Evidence, all from the firmware's own behaviour:**

* **The CPLD is configured and verified.** The firmware bit-bangs a JTAG port
  over GPIO, writes **98 rows of 274 bits** into the XC2C64A's configuration
  SRAM, then reads all 98 back and compares them against the array it just
  programmed. It proceeds — so its own `cpld_xc2c64a_jtag_sram_verify()`
  returned true.
* **The serial flash identifies itself.** `w25q80bv_setup()` retries
  `get_device_id()` in an unbounded loop until it sees `0x13`; the boot passes
  it.
* **The board identifies itself.** `detect_hardware_platform()` probes the
  strap resistors through the GPIO model and latches `BOARD_ID_HACKRF1_OG`,
  which it later reports over USB as `0x02`.
* **`usb_run()` is reached**: `USBCMD.RS set -- the device controller is
  RUNNING`, and the firmware published its own queue-head array with
  `ENDPOINTLISTADDR = 0x10081000`.

**Alternative ruled out — "the CPLD/flash models are being bypassed, not
satisfied."** See the falsification control below: corrupting one bit of the
CPLD readback makes the boot stop before `usb_run()` entirely.

### M3 — the firmware's own control loop runs

**Evidence.** After `usb_run()` the PC histogram collapses onto three
instructions at **0x1b54–0x1b58**, which disassemble to `off_mode()`'s
`while (transceiver_request.seq == seq) {}` — the transceiver idle loop of
`main()`. The device is sitting in its main loop waiting for a USB command,
which is exactly what an idle HackRF One does.

**Alternative ruled out — "that is a hang, not an idle."** It answers. Every
vendor request below is serviced from the USB interrupt while the main loop
spins, and `SET_CONFIGURATION` drives the firmware's own
`usb_configuration_changed()` callback.

### M4 — real protocol round-trip

The host writes **eight bytes** (a SETUP packet) and reads back bytes the
firmware composed. See the measurements below.

**Alternative ruled out — "the harness produced the reply."** Three
independent reasons:

1. The reply is read from guest RAM **at the address the firmware wrote into
   `dTD.buffer_pointer_page[0]`, for the length the firmware wrote into
   `dTD.total_bytes`**. Both are reported as `provenance` in the attack's
   result. Measured: buffer `0x100019dc`, dTD `0x10083c00`, token `0x00098000`
   → length **9**, all chosen by the firmware.
2. `tests/test_structure.py::test_no_module_contains_the_reply_the_firmware_must_produce`
   asserts that no module in this device contains the expected string in any
   encoding. The attack validates it by **shape**, not equality.
3. The **negative control** (below) uses the identical harness and gets nothing.

---

## Static prediction vs. measurement

`PROVENANCE.md` §2 was written **before the firmware was booted even once** and
is committed in the initial release commit ahead of any result. All four
predictions matched **byte for byte**.

| | predicted (pre-boot) | measured | |
|---|---|---|---|
| **A** — vendor request 15, `VERSION_STRING_READ` | 9 bytes `32 30 32 36 2e 30 31 2e 33` = `2026.01.3` | `32 30 32 36 2e 30 31 2e 33`, length 9 | ✅ exact |
| **B** — vendor request 14, `BOARD_ID_READ` | one byte `0x02` (`BOARD_ID_HACKRF1_OG`) | `02` | ✅ exact |
| **C** — `GET_DESCRIPTOR(device)` | 18 bytes beginning `12 01 00 02 00 00 00 40 50 1d 89 60 10 01` | `12 01 00 02 00 00 00 40 50 1d 89 60 10 01 01 02 04 01` | ✅ exact |
| **D** — vendor request 13 (**negative control**) | no data; `ENDPTCTRL0 = RXS\|TXS = 0x00010001` | STALLED, 0 bytes, `ENDPTCTRL0 STALL set by the firmware (0x00010001)` | ✅ exact |

Two further requests were not predicted in advance and are reported as
corroboration rather than as prediction: request 45 (`BOARD_REV_READ`) → `00`
(`BOARD_REV_HACKRF1_OLD`, which follows from the modelled ADC reading
"nothing fitted" on the revision straps), and request 46
(`SUPPORTED_PLATFORM_READ`) → `00 00 00 0a`, the big-endian form of
`firmware_info.supported_platform` (`PLATFORM_HACKRF1_OG | PLATFORM_HACKRF1_R9`)
which the extractor independently reads out of the image.

### Firmware-side evidence, verbatim

```
HAL_LOG|INFO|  Xc2c64aJtag: CPLD SRAM row 98/98 written (addr 0x45)
HAL_LOG|INFO|  Xc2c64aJtag: CPLD SRAM row 99 read back for verify (addr 0x45, 98 rows stored)
HAL_LOG|INFO|  LpcBootRom: IAP entry read -> 0x12345678 ("not implemented", which is the truth for a flashless LPC4320)
HAL_LOG|INFO|  Lpc43xxUsb0: ENDPOINTLISTADDR = 0x10081000 (the firmware's own dQH array)
HAL_LOG|INFO|  Lpc43xxUsb0: USBCMD.RS set -- the device controller is RUNNING (usb_run() reached)
HAL_LOG|INFO|  UsbHost: host: driving a bus reset
HAL_LOG|INFO|  UsbHost: host: SETUP 80 06 00 01 00 00 12 00  [GET_DESCRIPTOR(device)]
HAL_LOG|INFO|  UsbHost: host: 18 byte(s) IN  12 01 00 02 00 00 00 40 50 1d 89 60 10 01 01 02 04 01
HAL_LOG|INFO|  UsbHost: host: device descriptor -- VID:PID = 1d50:6089
HAL_LOG|INFO|  UsbHost: host: SETUP 00 05 07 00 00 00 00 00  [SET_ADDRESS(7)]
HAL_LOG|INFO|  UsbHost: host: SETUP 80 06 00 02 00 00 20 00  [GET_DESCRIPTOR(config)]
HAL_LOG|INFO|  UsbHost: host: 32 byte(s) IN  09 02 20 00 01 01 03 80 fa 09 04 00 00 02 ff ff ff 00 07 05 81 02 40 00 00 07 05 02 02 40 00 00
HAL_LOG|INFO|  UsbHost: host: SETUP 00 09 01 00 00 00 00 00  [SET_CONFIGURATION(1)]
HAL_LOG|INFO|  UsbHost: host: device ENUMERATED and CONFIGURED
HAL_LOG|INFO|  Lpc43xxUsb0: ENDPTCTRL0 STALL set by the firmware (0x00010001)
HAL_LOG|INFO|  UsbHost: host: EP0 STALLed by the firmware  [bridge:vendor(13)]
```

and the attack's own output:

```
[boot] msg=booting the LPC4320 rehost
[enumerated] vid_pid=1d50:6089
[attack] request=15 msg=unauthenticated vendor request VERSION_STRING_READ
[reply] request=15 data=32 30 32 36 2e 30 31 2e 33 text=2026.01.3
[reply] request=14 data=02
[reply] request=46 data=00 00 00 0a
[negative_control] request=13 msg=the same harness, a request the firmware must reject
[negative_control_result] request=13 stalled=True data= endptctrl0_stall_logged=True no_data=True
[verdict] landed=True
version_string : 2026.01.3
version_bytes  : 32 30 32 36 2e 30 31 2e 33
board_id       : 2
provenance     : {"dtd": 268965056, "dqh": 268963904, "buffer": 268960348, "token": 622720, "length_from_firmware": 9}
neg control    : {"request": 13, "stalled": true, "data": "", "endptctrl0_stall_logged": true, "no_data": true}
RESULT: {"booted": true, "landed": true}
```

---

## Adversarial checks

| check | result |
|---|---|
| **Negative control** — vendor request 13 (a `NULL` slot in the firmware's own dispatch table), identical harness | firmware **STALLs**: 0 bytes and `ENDPTCTRL0 = 0x00010001` written by the firmware. `landed` is false unless this holds. |
| **3× cold re-run** from a clean process | identical every time: `2026.01.3`, board id `2`, same dTD/buffer provenance, `landed: true`. Not flaky. |
| **Polluted env** (`HALUCINATOR_SRC=/nonexistent/x PYTHONPATH=/nonexistent/x`) | identical result, exit 0 — `spawn_env()` strips both. |
| **Prediction written before first boot** | yes. `PROVENANCE.md` §2 was authored from the vendor source and the image bytes before the first emulator run and is committed unchanged. |
| **CPLD falsification control** (`HAL_HRF_CPLD_CORRUPT=1`) | see below. |

### The CPLD verify **does** gate the USB command loop — measured, not argued

The question is worth stating plainly because it decides how much of an
LPC43xx/HackRF bring-up you can skip: **is the CPLD on the path to USB?**

*From the source*, yes: `main()` runs `cpld_jtag_sram_load()` and, on failure,
`halt_and_flash(6000000)` — an infinite blink loop — **before** it ever calls
`usb_device_init()` or `usb_run()`.

*Measured*, also yes. `HAL_HRF_CPLD_CORRUPT=1` makes the CPLD model flip one
bit of every row it shifts back, so the firmware's own verify must fail:

| | clean | one bit corrupted |
|---|---|---|
| CPLD rows written | 98 | 98 |
| `USBCMD.RS set` (i.e. `usb_run()` reached) | **1** | **0** |
| device enumerated | **yes, ~6 s after start** | **never, in 240 s** |
| faults in the log | 0 | 0 |

Note the last row: the failure is **completely silent**. No error, no fault, no
diagnostic — the firmware simply blinks LEDs nobody is watching. A rehost that
answered TDO with a constant would look like "USB never comes up on this
device" and give no hint that a CPLD was involved.

So for anyone bringing up a HackRF One (or the PortaPack/Mayhem firmware on the
same board): **you cannot reach the USB vendor-request surface without
satisfying the CPLD's readback.** The good news is that satisfying it needs no
bitstream knowledge at all — the firmware verifies against the array it just
programmed, so a TAP state machine plus a 98×274-bit row store passes.

---

## What is modelled

| block | treatment |
|---|---|
| **USB0 device controller** (`0x40006000`) | full Chipidea-style model: dQH/dTD bus mastering out of guest RAM, `ENDPTPRIME`/`ENDPTSTAT`/`ENDPTCOMPLETE`/`ENDPTSETUPSTAT`/`ENDPTFLUSH`, `ENDPTCTRL` enable+stall, `USBSTS`/`USBINTR`, controller reset, bus reset |
| **USB host** | bus reset, `GET_DESCRIPTOR`, `SET_ADDRESS`, `SET_CONFIGURATION`, then vendor control transfers; a line-oriented TCP bridge on 21209 |
| **XC2C64A CPLD** over bit-banged JTAG | IEEE 1149.1 TAP, IR capture, IDCODE, and the 98×274-bit ISC SRAM array |
| **GPIO** (`0x400F4000`) | byte/word/port register files, direction-aware readback, board straps, JTAG pins, flash chip select, LEDs |
| **W25Q80BV serial flash** on SSP0 | device id, JEDEC id, status, unique id, and `READ DATA` served **out of the image itself** through the SPIFI window |
| **CGU / CCU / RGU** | PLL `LOCK` mirrored from each PLL's own power-down bit; `RESET_ACTIVE_STATUS` as the inverse of `RESET_CTRL`; CCU branch `STAT` mirrored from `CFG` |
| **ADC0/1** | conversion completes immediately, reporting the **channel the firmware selected** and a mid-scale sample |
| **I²C0/1** | transfers complete; `i2c_probe()` gets "no acknowledge", i.e. no PortaPack and no Operacake fitted — which is the truth for a bare board |
| **Boot ROM / IAP** (`0x10400000`) | `0x12345678` = "IAP not implemented", which is what a flashless LPC4320 really reports (NXP errata ES_LPC43X0_A §3.5) |
| everything else in `0x40000000–0x401FFFFF` | `AutoPeripheral` catch-all (recording + busy-wait breaker) |

## Known limitations

* **The Cortex-M0 baseband core does not run.** `ipc_start_m0()` is accepted and
  ignored. The M0 shuttles IQ samples between SGPIO and the USB bulk buffers; it
  is not on the control path, and no vendor request in this device's evidence
  depends on it. **Bulk streaming (RX/TX) is therefore out of scope** — this is
  a control-plane rehost.
* **No RF.** MAX2837, RFFC5071, Si5351C and MAX5864 are not modelled; their
  buses read zeros. `SET_FREQ`, `SET_SAMPLE_RATE` and the gain requests are
  *accepted and parsed by the firmware* — which is the attack surface — but
  nothing is tuned, because there is no radio.
* **The unique id is synthetic and says so.** A real unit's serial number is a
  property of its die and cannot be recovered from a firmware image. The
  modelled W25Q80BV returns the ASCII `REHOSTRY`, which is why the USB
  serial-number string descriptor is deterministic and obviously not a real
  unit's.
* **Guest time is not calibrated.** The USB interrupt is paced by instruction
  count (`HAL_DET_TICK=8:20`), not by wall-clock or a modelled timer. Ordering
  is deterministic and reproducible; rates are not meaningful.
* **Speed.** A cold boot to enumeration takes roughly a minute, dominated by
  ~55 000 bit-banged JTAG clocks through Python MMIO callbacks.
* **`iap_cmd_call` reports "not implemented".** This is faithful to the
  flashless LPC4320 (and is the path the firmware's own errata comment
  describes), but it means `BOARD_PARTID_SERIALNO_READ` returns the OTP/flash
  fallback values rather than a real part id.

## Core changes

**None.** Bucket A: `cortex-m3` in `_ARCH_MAP` decodes ARMv7E-M, and the FPU is
reached with the existing `HAL_CORTEXM_CPU_MODEL` knob. Nothing in the shared
`halucinator@dev` core was modified for this device.

## Reproducing

```bash
python3 tools/extract_firmware.py                 # stages + verifies the image
pip install -e .
rehostry-hackrf-one-attack                        # RESULT: {"booted": true, "landed": true}
rehostry-hackrf-one probe 15 14 45 46 13          # ask it things directly
rehostry-hackrf-one-panel                         # http://127.0.0.1:9019
python3 -m pytest tests/ -q                       # 29 structural tests, no emulator
```

---

## M8 interface parity — DEFINED at 49, UNMET, and the numerator is NOT COMPLETELY MEASURED

Lane `s0929-laneL`, 2026-09-29/30. `PREDICTIONS-M8.md` was committed **before** any
graded run (`2513848`, 22:57:41 −0500). **No number here was improved by removing
an entry.** The denominator went from an undefined 1 to a measured **49**, which
§1a's ruling of 2026-09-29 says is the correct direction.

⚠ **Read the honest shape of this result first.** The **denominator is finished**:
derived from the guest's own bytes every run, pre-registered, and control-gated in
both directions. The **numerator is not**: neither graded arm completed inside the
session, so what is reported below is a **BOUND**, `n ∈ [6, 40] of 49`, and
it is labelled as a bound wherever it appears. **It is not a parity fraction and
must not be quoted as one.**

### What changed, and what did NOT

`attack.py`'s own comment said *"the inventory has one entry, which §1b's boundary
puts at M8-undefined"*. The **M5 half still stands** — one EP0 control seam, one
framing layer, one peer, so **M5 remains UNDEFINED**. The M8 half is overturned by
§1a's 2026-09-29 ruling: an entry is a **declared capability on a seam the
firmware exposes**, not a §1a-independent interface, and the fleet already grades
`vesc-bms` at 16 COMM packets over one CAN link on exactly that reading.

### The denominator: 59 declared slots, 49 implemented by THIS image

Seven instructions, and they are the whole specification:

```
0x0430  43 78        ldrb    r3, [r0, #1]        ; setup.bRequest
0x0432  3a 2b        cmp     r3, #0x3a           ; THE BOUND -> 0..58 = 59 slots
0x0434  04 d8        bhi     0x440               ;   out of range -> STALL
0x0436  03 4a        ldr     r2, [pc, #0xc]      ; literal @0x444 = 0x00008524
0x0438  52 f8 23 30  ldr.w   r3, [r2, r3, lsl #2]
0x043c  03 b1        cbz     r3, 0x440           ;   NULL slot  -> STALL
0x043e  18 47        bx      r3
0x0440  01 20        movs    r0, #1              ; USB_REQUEST_STATUS_STALL
```

`inventory.py` hardcodes none of that. It searches **guest memory** for the
*shape* (`ldr.w Rt,[Rn,Rm,lsl #2]` + `cbz Rt` + `bx Rt`, preceded by
`cmp Rm,#imm8` + cond-branch + `ldr Rn,[pc,#imm]`), requires **exactly one**
match, and decodes the bound from the `cmp` and the base from the literal pool.
Zero or two matches **raise** rather than guess. It runs at the reset vector,
before the CPU has executed anything, so every run scrapes its denominator out of
**that run's own guest** (`M8-INVENTORY` in the log) and not off the disk.

* `slots_declared` = **59**, `bound_imm` = `0x3A`, `table_addr` = `0x00008524`
* `null_indices` = `[0, 13, 22, 49, 50, 51, 52, 53, 54, 55]` — **10 slots this build does not implement**
* `implemented` = **49** — the graded denominator
* `table_sha256` = `20c8322b84ef0fc4d0a2429fc0c94a8186175ca6c563de807bbdae1c91e446f3`

**§1d: the 10 removals are justified from the independent source itself.** A NULL
slot is the firmware saying it does not serve that request; never "we did not
implement it". Both numbers are reported so a reader can re-derive either.
Cross-check against the published `hackrf_vendor_request` set: the gaps at **13**
and **22** are the two requests upstream retired (`write_cpld`, `set_if_freq`) —
independent corroboration that this is the vendor-request array. ⚠ The published
set is a cross-check only; the graded denominator is the image's.

⚠ **49 IS A FLOOR, not a ceiling.** This counts the *vendor*-request
dispatcher. The firmware has a second, separate dispatcher for USB **standard**
requests; a stricter future reading could count some of those too. Enumeration is
arguably substrate (the ARP/ICMP analogy), which is why they are excluded here —
but that judgement is stated rather than assumed, and a re-derivation that grows
this number is the correct direction.

⚠ **On RULES.md §1a's quarantine of batch `s0929`:** the ruling says s0929
denominators "were derived under the narrower reading, so they are floors" and
that a fleet-wide re-derivation is a separate job, *"not retrofitted per row"*.
That protects rows that **already had** a narrower denominator; a sibling lane
correctly declined to grow its 14 on those grounds. **This row had none — M8 was
UNDEFINED** — so defining one is not a retrofit.

### The denominator IS control-gated, in both directions

| control | what moved | result |
|---|---|---|
| `--control bound-patch-0` | the firmware's own `cmp r3,#0x3a` rewritten **in guest memory, after the parse** — `M8-BOUND-PATCH at 0x00000432: 3a2b -> 002b` | guard still **PASS**, denominator still **49**, every entry fails, `parity 0/49`, rung **M3**, `landed false` |
| `--control guard-offset` | the array read slid 4 bytes | `M8-INVENTORY-GUARD VOID`: `null_indices` parsed as `[12, 21, 48, 49, 50, 51, 52, 53, 54]` and `implemented` as **50** — a denominator that **grew by one and moved every index** |

The second is the same shape a sibling lane hit on ICP DAS, where a 4-byte slip
turned `(0,1,10,33)` into `[0,9,32,39]`, and `PREDICTIONS-M8.md` PREDICTION 6
named those exact values **before** the run. ⚠ In the bound-patch arm the canary
is itself a vendor request, so no latency could be measured and the silence bound
fell to its 15 s floor — stated, because a floor is not a calibration. ⚠ The
guard-offset arm was **reaped early by explicit pid** once its verdict was in the
log; the control's whole claim is settled at the reset vector.

### The agreement control counts REPLIES, and silence is not refusal

All 10 NULL slots plus two out-of-range requests (59, 255), on a seam the
calibration had just proven healthy: **12 of 12 REFUSED, 0 answered, 0
unmeasured**, with `ENDPTCTRL0 STALL set by the firmware (0x00010001)` in the log
— the firmware's own write. That is PREDICTION 3.

⚠ **This control was wrong the first time and a run showed it.** It read
`refused = got is not None and got["stalled"]`, so a probe that got **no reply**
counted as not-refused; and it ran only *after* the 49-entry sweep, by which time
this seam has gone deaf. The nonce arm therefore reported **0 of 12** refusals on
a firmware that had written its own stall bit earlier in the same run — **a run
budget was classifying.** Each probe is now REFUSED / ANSWERED / **UNMEASURED**,
an UNMEASURED probe **VOIDS** the control rather than failing it, and it runs
before the entry sweep as well as after.

### The numerator: a BOUND, from two arms neither of which finished

| | arm A | arm B |
|---|---|---|
| per-transfer poll budget | written-down `STALL_STEPS = 400` | **derived**: 20 × its own worst successful transfer (**2** polls) → **60** |
| entries fully measured | **13** | 12 (+1 partial) |
| `DRIVEN` 3 of 3 | `[3, 5, 9, 12, 14, 15]` | `[3, 5, 9, 12, 14]` |
| not driven, all rounds seen | `[1, 2, 4, 6, 7, 8, 10, 11, 16]` | `[1, 2, 4, 6, 7, 8, 10, 11]` |
| emulator log lines per transfer | ~310 | **~65** |
| reached | entry 24 of 49 in ~57 min | entry 15 of 49 in ~7 min |

**`n ∈ [6, 40] of 49`** — lower bound = entries `DRIVEN` 3 of 3; upper bound
adds every entry not yet reached. ⚠ **Not a parity number.**

⭐ **The two arms agree on 13 of 13 entries both fully measured.** The only
variable between them is the poll budget, so the reduction from 400 to 60
**changed no verdict** — which is the check RULES.md §2a asks for before
believing a harness change. The 400 was 200× the worst observed good transfer and
cost ~5× the emulation work for nothing.

### ⚠⚠ THE SHORTFALL IS IN THIS HARNESS, NOT IN THE FIRMWARE

With benign parameters (`wValue = wIndex = 0`) the firmware **STALLed zero**
non-NULL slots across both graded arms. Every single failure is `OUT_STAGE` — *no
reply*, because the handler wants a **host→device** data stage that this row's USB
host model does not drive. That is a limitation of **our model**, and those
entries are **NOT MEASURED at M4 — they are not refused by the firmware.**

⚠ **And part of it is a mis-probe, not even a model gap.** The probe sends
`wLength = 0x20`, which forces a data stage on requests that carry their whole
payload in `wValue`/`wIndex` and have **no data stage at all**. Those would
complete as `ROUTED` at `wLength = 0`. The probe should try `0x20` and fall back
to `0`; it does not. **Extending the host model to drive an OUT data stage, and
fixing the `wLength` fallback, are the two highest-value changes for this row's
parity** — and neither is a firmware fact.

### The nonce-parameter arm, kept as a negative control

The graded rounds use `wValue = wIndex = 0`. They originally carried a per-run
nonce, and measured live that made the firmware's **own handlers** STALL **9 of
the first 12** entries — `write_max2837(reg=garbage)`, `read_si5351c(reg=garbage)`
and so on. A random register address *is* an invalid register address: those
refusals were correct firmware behaviour and a **defect in the probe**. The arm is
kept because it is a real negative control — *plausible but wrong parameters must
be refused by the firmware's own checker* — and it was: **14 stalls and 10
no-replies of 49**. ⚠ It also predates the Rule 2 fix and was credited M4 off
`--rounds 1`; it carries no claim.

### Defects in this lane's own code

1. **Rule 2 was not enforced.** Per-entry `ok` was `npass == rounds and rounds >
   0` — satisfied by **one** exchange. Fixed to `rounds > 1`. Caught by this
   lane's own check 3 at the observation layer, and re-scoring this row's
   `--rounds 1` arm through the fixed predicate turns **M4 / 7-of-49** into
   **M3 / 0-of-49** (`scratch-batch-s0929-laneL/RESCORE-prefix-artifacts.txt`).
2. **The agreement control let a budget classify** (above).
3. **`STALL_STEPS = 400` was a written-down harness constant** doing the job of a
   measurement (above).
4. **`checks.py` itself produced one FALSE hit** against `bound-patch-0`: it
   proxied "drives its own interface" with canary latencies, and the canary is a
   *vendor* request that arm exists to break. The row's M3 was right and the
   instrument was wrong. Recorded rather than quietly corrected.
5. **The log directory name does not distinguish arms** — `hackrf-parity-<pid>-
   default` for the graded, agreement-only and nonce arms alike. Unique per run
   (the hard requirement), but not attributable by eye.
6. **The per-run seed is not what its comment claims.** `abs(hash(<pkg name>))`
   is randomised per process, so it is a fresh random seed every run (recorded in
   each JSON: 450683804, 784049394, 880815053), not a stable per-row value. It does guarantee the three
   rows never share one, and with benign parameters it no longer feeds the verdict.

All of these, and the check-3 adjudication, are written up in
`scratch-batch-s0929-laneL/CHECK3-ADJUDICATION.md`.

### RULES.md §1a, ruling of 2026-09-30 — and this row had the worst version of the hole it names

The ruling says a fault after the boot does not un-boot the guest, but that it
*"bars every rung whose evidence comes after it, and must be recorded rather than
absorbed"*; it warns that a row reporting a bare `faults=0` while faulting after
its round trip is **hiding** the fault.

⚠⚠ **This row was worse than that: it reported no fault count AT ALL.** The
ladder had no fault term and the RESULT line had no `faults` key, so there was
nothing to hide behind and nothing to read. Fixed: `FAULT_MARKERS`
(`UC_ERR` / `Traceback` / `FETCH-DERAIL`) are scanned out of the child's own log
**after the emulator is down** — deliberately, because a fault in the last of
~160 transfers is not in the text scanned at boot — and reported as `faults`,
`fault_markers`, `fault_before_round_trip`, `fault_after_round_trip`. A fault now
bars **M8** explicitly and `landed` is gated on `fault_before_round_trip` only.

**Re-run after the change (`--agreement-only`, the cheap arm): nothing moved.**
`milestone M3`, `landed false`, guard PASS, agreement **12 of 12 REFUSED, 0
answered, 0 unmeasured**, and now `faults 0`, `fault_markers []`, both fault
fields `false`. ⚠ The expensive graded arms were **not** re-run — neither had
completed before the ruling, so there is no verdict of theirs to re-verify, and
the bound below is unaffected.

### Not measured in this session

* **M5 stays UNDEFINED.** One EP0 control seam, one peer.
* M6 and M7 were not re-run; those rungs stand on 2026-09-17.
* **The numerator.** 34 of 49 entries were never reached. Both arms were
  **reaped by explicit pid** (client, then the emulator child explicitly, because
  a SIGTERM to the client skips its `finally` — which is how the guard-offset arm
  orphaned a listener earlier in this session). Ports confirmed released,
  firmware sha256 unchanged before and after.
* `STATUS.md` already records that *"the seam stops answering after request 38
  with the guest still executing"*. This session **reproduced deaf-seam behaviour**
  — the agreement control measured 0 of 12 at the end of a 49-entry sweep while
  the same firmware answered 12 of 12 at the start — but did **not** explain it,
  and did not reach request 38 in a graded arm. Still UNEXPLAINED.
* Box load 11.7–18.5 with eight other lanes. Every wall-clock figure is
  **provisional**; the silence bound is derived per run and the poll budget from
  the run's own worst successful transfer, so neither is a device constant.
