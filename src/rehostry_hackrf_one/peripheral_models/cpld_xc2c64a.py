# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The HackRF One's Xilinx **XC2C64A CoolRunner-II CPLD**, on the far end of a
bit-banged JTAG port.

WHY THIS IS NOT OPTIONAL. ``main()`` runs, before it ever touches USB::

    if (!cpld_jtag_sram_load(&jtag_cpld)) { halt_and_flash(6000000); }

and ``cpld_jtag_sram_load`` writes the CPLD's configuration SRAM over JTAG and
then **reads it back and compares**::

    cpld_xc2c64a_jtag_sram_write(jtag, &cpld_hackrf_program_sram);
    return cpld_xc2c64a_jtag_sram_verify(jtag, &cpld_hackrf_program_sram,
                                         &cpld_hackrf_verify);

So a device that answers TDO with a constant never boots: the verify fails and
the firmware parks in ``halt_and_flash`` forever, blinking LEDs nobody can see.
Crucially the verify compares against **the same array it just programmed**, so
a *faithful* model -- one that actually stores the rows and shifts them back --
passes without any knowledge of the bitstream. That is what this is.

WHAT IS MODELLED
----------------

* The full IEEE 1149.1 **TAP state machine** (16 states), clocked from the
  firmware's own TCK edges on GPIO3[0].
* An 8-bit instruction register, captured as ``0x05`` -- the CoolRunner-II
  pattern: bits[1:0] = ``01`` (mandatory), bit 2 = ISC_DONE, bit 3 clear
  (not read/write protected). The firmware's ``cpld_xc2c_jtag_is_done()``
  (``(ir ^ 0x05) & 0x07 == 0``) and ``..._read_write_protect()``
  (``(ir ^ 0x01) & 0x03 == 0``) both read that value.
* IDCODE ``0x06E58093``, which satisfies the firmware's own mask test
  ``((idcode ^ 0xf6e5f093) & 0x0fff8fff) == 0``.
* The **ISC SRAM array**: 98 rows of 274 bits, addressed by a 7-bit field.
  Under ``ISC_WRITE`` and ``ISC_SRAM_READ`` the data register is
  ``274 + 7 = 281`` bits wide with the address in the high field, exactly the
  shape the firmware shifts (``cpld_xc2c64a_jtag_sram_write_row`` shifts 274
  data bits then 7 address bits; ``..._sram_read_row`` does the same and reads
  TDO out of the data field). ``Update-DR`` latches the address; the next
  ``Capture-DR`` loads that row.

TIMING. The firmware's ``cpld_xc2c_jtag_clock()`` drives TDI and TMS, pulls TCK
**low**, then **high**, then reads TDO. On real silicon TDO changes on the
falling edge and is sampled by the master while TCK is high -- so the bit read
in cycle *i* is the one presented *before* that cycle's shift. This model does
the same: ``tck_fall()`` latches ``sr & 1`` into the TDO pin, ``tck_rise()``
samples TMS/TDI and advances the TAP. Get that backwards and every row reads
back rotated by one bit, the verify fails, and it looks like a bitstream
problem.

FALSIFICATION KNOB. ``HAL_HRF_CPLD_CORRUPT=1`` flips one bit on every row read
back. It exists so the claim "the CPLD gates USB" can be *tested* rather than
argued: with it set the firmware's own verify must fail, `halt_and_flash()` must
run, and the device must never enumerate. See STATUS.md for the measured result.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional

from halucinator import hal_log

log = hal_log.getHalLogger()

_CORRUPT = os.environ.get("HAL_HRF_CPLD_CORRUPT") == "1"

# --- TAP states -------------------------------------------------------------
(TLR, RTI, SEL_DR, CAP_DR, SHIFT_DR, EX1_DR, PAUSE_DR, EX2_DR, UPD_DR,
 SEL_IR, CAP_IR, SHIFT_IR, EX1_IR, PAUSE_IR, EX2_IR, UPD_IR) = range(16)

STATE_NAMES = [
    "Test-Logic-Reset", "Run-Test/Idle", "Select-DR", "Capture-DR", "Shift-DR",
    "Exit1-DR", "Pause-DR", "Exit2-DR", "Update-DR", "Select-IR", "Capture-IR",
    "Shift-IR", "Exit1-IR", "Pause-IR", "Exit2-IR", "Update-IR",
]

#: next_state[state][tms]
NEXT = {
    TLR: (RTI, TLR),
    RTI: (RTI, SEL_DR),
    SEL_DR: (CAP_DR, SEL_IR),
    CAP_DR: (SHIFT_DR, EX1_DR),
    SHIFT_DR: (SHIFT_DR, EX1_DR),
    EX1_DR: (PAUSE_DR, UPD_DR),
    PAUSE_DR: (PAUSE_DR, EX2_DR),
    EX2_DR: (SHIFT_DR, UPD_DR),
    UPD_DR: (RTI, SEL_DR),
    SEL_IR: (CAP_IR, TLR),
    CAP_IR: (SHIFT_IR, EX1_IR),
    SHIFT_IR: (SHIFT_IR, EX1_IR),
    EX1_IR: (PAUSE_IR, UPD_IR),
    PAUSE_IR: (PAUSE_IR, EX2_IR),
    EX2_IR: (SHIFT_IR, UPD_IR),
    UPD_IR: (RTI, SEL_DR),
}

# --- XC2C64A instructions (firmware's own enum, cpld_xc2c.c) ----------------
IR_EXTEST = 0x00
IR_IDCODE = 0x01
IR_ISC_ENABLE = 0xE8
IR_ISC_SRAM_READ = 0xE7
IR_ISC_WRITE = 0xE6
IR_ISC_DISABLE = 0xC0
IR_ISC_INIT = 0xF0
IR_BYPASS = 0xFF

ROWS = 98
BITS_IN_ROW = 274
ADDR_BITS = 7
DR_BITS_ISC = BITS_IN_ROW + ADDR_BITS          # 281
ROW_MASK = (1 << BITS_IN_ROW) - 1

#: XC2C64A JTAG IDCODE. The firmware masks off the revision and package
#: nibbles before comparing, so only the part-identifying bits matter.
IDCODE = 0x06E58093

#: What Capture-IR loads. CoolRunner-II: bits[1:0]="01" (IEEE 1149.1 mandates
#: bit0=1), bit2 = ISC_DONE, bit3 = read/write-protect (clear = unprotected).
IR_CAPTURE = 0x05


class Xc2c64aJtag:
    """A CoolRunner-II XC2C64A reachable only through TCK/TMS/TDI/TDO."""

    def __init__(self) -> None:
        self.state = TLR
        self.ir = IR_BYPASS
        self.sr = 0                     # shift register (int)
        self.sr_bits = 1
        self.tdo = 0
        self.tck = 0
        #: The configuration SRAM: address -> 274-bit row value.
        self.sram: Dict[int, int] = {}
        self.addr = 0
        #: Bookkeeping for the panel / STATUS evidence (never an oracle).
        self.clocks = 0
        self.rows_written = 0
        self.rows_read = 0
        self.ir_writes: List[int] = []

    # -- the pins -----------------------------------------------------------
    def tck_fall(self) -> None:
        """TCK 1->0. TDO becomes valid: the LSB of the shift register."""
        self.tck = 0
        if self.state in (SHIFT_DR, SHIFT_IR):
            self.tdo = self.sr & 1

    def tck_rise(self, tms: int, tdi: int) -> None:
        """TCK 0->1. The TAP samples TMS/TDI, shifts, and advances."""
        self.tck = 1
        self.clocks += 1
        tms = 1 if tms else 0
        tdi = 1 if tdi else 0

        if self.state == SHIFT_DR or self.state == SHIFT_IR:
            # The shift happens on this edge whether or not TMS moves us out.
            self.sr = (self.sr >> 1) | (tdi << (self.sr_bits - 1))

        nxt = NEXT[self.state][tms]
        self._enter(nxt)
        self.state = nxt

    def read_tdo(self) -> int:
        return self.tdo

    # -- state entry actions ------------------------------------------------
    def _enter(self, state: int) -> None:
        if state == TLR:
            self.ir = IR_IDCODE          # IEEE 1149.1: TLR loads IDCODE
        elif state == CAP_IR:
            self.sr_bits = 8
            self.sr = IR_CAPTURE
        elif state == UPD_IR:
            self.ir = self.sr & 0xFF
            self.ir_writes.append(self.ir)
        elif state == CAP_DR:
            self._capture_dr()
        elif state == UPD_DR:
            self._update_dr()

    def _capture_dr(self) -> None:
        if self.ir == IR_IDCODE:
            self.sr_bits = 32
            self.sr = IDCODE
        elif self.ir in (IR_ISC_SRAM_READ, IR_ISC_WRITE):
            self.sr_bits = DR_BITS_ISC
            # The data field is loaded from the addressed row; the address
            # field's capture value is don't-care (the firmware overwrites it).
            self.sr = self.sram.get(self.addr, 0) & ROW_MASK
            if _CORRUPT:
                # Deliberate falsification: see the module docstring.
                self.sr ^= 1
            if self.ir == IR_ISC_SRAM_READ:
                self.rows_read += 1
                if self.rows_read in (1, ROWS + 1):
                    log.info("Xc2c64aJtag: CPLD SRAM row %d read back for "
                             "verify (addr 0x%02x, %d rows stored)%s",
                             self.rows_read, self.addr, len(self.sram),
                             "  [CORRUPTED ON PURPOSE]" if _CORRUPT else "")
        elif self.ir == IR_BYPASS:
            self.sr_bits = 1
            self.sr = 0
        else:
            self.sr_bits = 32
            self.sr = 0

    def _update_dr(self) -> None:
        if self.ir == IR_ISC_WRITE:
            data = self.sr & ROW_MASK
            self.addr = (self.sr >> BITS_IN_ROW) & ((1 << ADDR_BITS) - 1)
            self.sram[self.addr] = data
            self.rows_written += 1
            if self.rows_written in (1, ROWS):
                log.info("Xc2c64aJtag: CPLD SRAM row %d/%d written "
                         "(addr 0x%02x)", self.rows_written, ROWS, self.addr)
        elif self.ir == IR_ISC_SRAM_READ:
            self.addr = (self.sr >> BITS_IN_ROW) & ((1 << ADDR_BITS) - 1)

    # -- diagnostics --------------------------------------------------------
    def summary(self) -> dict:
        return {
            "clocks": self.clocks,
            "rows_written": self.rows_written,
            "rows_read": self.rows_read,
            "rows_stored": len(self.sram),
            "state": STATE_NAMES[self.state],
            "ir": self.ir,
        }


_CPLD: Optional[Xc2c64aJtag] = None


def get_cpld() -> Xc2c64aJtag:
    """The single CPLD on this board (models are constructed more than once --
    playbook trap 2.3 -- so the state must not live on the model instance)."""
    global _CPLD
    if _CPLD is None:
        _CPLD = Xc2c64aJtag()
        log.info("Xc2c64aJtag: CPLD attached to the bit-banged JTAG port "
                 "(TCK=GPIO3[0] TMS=GPIO3[4] TDI=GPIO3[1] TDO=GPIO5[18])")
    return _CPLD
