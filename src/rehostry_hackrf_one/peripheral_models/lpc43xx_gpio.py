# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The LPC43xx GPIO block, and the board wired to the other side of it.

This is more than a register file, because on a HackRF One the GPIO pins carry
two things the firmware *reasons about*:

1. **The board-identity strap resistors.** ``detect_hardware_platform()``
   (``firmware/common/platform_detect.c``) works out which board it is running
   on by enabling an internal pull-down, tri-stating, and seeing whether the pin
   rose -- then the same with a pull-up. A HackRF One (pre-r9) has an external
   pull-**up** on ``P5_0`` (GPIO2[9]) and a pull-**down** on ``P6_10``
   (GPIO3[6]). Get this wrong and the firmware calls
   ``halt_and_flash(1000000)`` and never reaches USB. The board ID it derives
   is also the answer to vendor request 14 -- see PROVENANCE.md prediction B.

2. **The CPLD's JTAG port**, bit-banged on GPIO3[0] (TCK), GPIO3[4] (TMS),
   GPIO3[1] (TDI) and GPIO5[18] (TDO). Edges on TCK are handed to the CPLD
   model.

Note that GPIO3[4] is *both* the P6_5 strap input and TMS. That is not a
conflict to paper over -- it is why the model must respect **direction**: an
input reads the external level (the strap / the CPLD's TDO), an output reads
back the level the pad is driving. Playbook trap 2.72: firmware leans on reading
back its own outputs constantly.

Register map (UM10503 §19, mirrored by ``firmware/common/gpio_lpc.h``), all
relative to ``0x400F4000``::

    +0x0000 + port*0x20 + pin        byte pin registers
    +0x1000 + port*0x80 + pin*4      word pin registers  <- gpio_read/gpio_write
    +0x2000 + port*4                 DIR
    +0x2080 + port*4                 MASK
    +0x2100 + port*4                 PIN
    +0x2180 + port*4                 MPIN
    +0x2200 + port*4                 SET
    +0x2280 + port*4                 CLR
    +0x2300 + port*4                 NOT
"""
from __future__ import annotations

import os
from typing import Dict, Optional, Tuple

from halucinator import hal_log

from .cpld_xc2c64a import get_cpld
from .spi_flash import get_flash

log = hal_log.getHalLogger()

GPIO_BASE = 0x400F4000
NPORTS = 8

# JTAG pin assignment for HACKRF_ONE (firmware/common/hackrf_core.c).
JTAG_TCK = (3, 0)
JTAG_TMS = (3, 4)
JTAG_TDI = (3, 1)
JTAG_TDO = (5, 18)

#: Chip select for the W25Q80BV serial flash on SSP0 (active low). It is the
#: FRAME DELIMITER for that bus -- playbook trap 2.88.
FLASH_CS = (5, 11)

# LEDs (firmware/common/hackrf_core.h): LED1..LED3 on GPIO2[1], [2], [8].
LEDS = {(2, 1): "LED1", (2, 2): "LED2", (2, 8): "LED3"}

#: Board straps for a **HackRF One (pre-r9)**, as levels an input pin reads
#: once the internal pull is released:
#:   P5_0  (GPIO2[9]) external pull-UP   -> reads 1 in both probe phases
#:   P6_10 (GPIO3[6]) external pull-DOWN -> reads 0 in both probe phases
#:   P6_5  (GPIO3[4]) nothing fitted     -> reads 1 in the pull-up phase
#: which decodes to HACKRF1_OG_RESISTORS = BOARD_ID_HACKRF1_OG (2).
STRAPS_HACKRF1_OG = {(2, 9): 1, (3, 6): 0, (3, 4): 1}

#: The r9 pattern, for the test that proves the decode is not a magic constant.
STRAPS_HACKRF1_R9 = {(2, 9): 0, (3, 6): 1, (3, 4): 1}


def decode_board_straps(p5_0: int, p6_10: int, p6_5: int) -> int:
    """Reproduce ``detect_hardware_platform()``'s resistor decode.

    Returns the ``board_id_t`` the firmware would latch. This exists so a test
    can assert the strap levels this model presents really do decode to
    ``BOARD_ID_HACKRF1_OG`` -- and that the r9 pattern decodes to something
    different -- rather than the board id being an unexplained constant.

    Phase 1 drives an internal pull-DOWN then tri-states: a pin that reads high
    must have an external pull-up. Phase 2 drives an internal pull-UP then
    tri-states: a pin that reads low must have an external pull-down. Both
    phases read the same steady level here, which is what a real fitted
    resistor produces.
    """
    P5_0_PUP, P5_0_PDN, P6_10_PUP, P6_10_PDN, P6_5_PDN = 1, 2, 4, 8, 16
    r = 0
    r |= P5_0_PUP if p5_0 else 0
    r |= P6_10_PUP if p6_10 else 0
    r |= 0 if p5_0 else P5_0_PDN
    r |= 0 if p6_10 else P6_10_PDN
    r |= 0 if p6_5 else P6_5_PDN
    return {
        P6_10_PDN: 1,                                 # BOARD_ID_JAWBREAKER
        P6_10_PDN | P5_0_PDN: 3,                      # BOARD_ID_RAD1O
        P6_10_PDN | P5_0_PUP: 2,                      # BOARD_ID_HACKRF1_OG
        P6_10_PUP | P5_0_PDN: 4,                      # BOARD_ID_HACKRF1_R9
        P6_5_PDN: 5,                                  # BOARD_ID_PRALINE
    }.get(r, 0xFE)                                    # BOARD_ID_UNRECOGNIZED


class Lpc43xxGpio:
    """Eight 32-bit GPIO ports with direction, plus the board on the pins."""

    def __init__(self) -> None:
        self.dir = [0] * NPORTS          # 1 = output
        self.out = [0] * NPORTS          # the level a pad is driving
        self.mask = [0] * NPORTS
        self.straps: Dict[Tuple[int, int], int] = dict(STRAPS_HACKRF1_OG)
        if os.environ.get("HAL_HRF_BOARD", "").lower() in ("r9", "hackrf1_r9"):
            self.straps = dict(STRAPS_HACKRF1_R9)
            log.info("Lpc43xxGpio: board straps set to the HackRF One r9 pattern")
        self.cpld = get_cpld()
        self.flash = get_flash()
        self.led_state: Dict[str, int] = {n: 0 for n in LEDS.values()}
        self.writes = 0
        self.reads = 0

    # -- pin level ----------------------------------------------------------
    def external(self, port: int, pin: int) -> int:
        """The level the outside world is holding an *input* pin at."""
        if (port, pin) == JTAG_TDO:
            return self.cpld.read_tdo()
        return self.straps.get((port, pin), 0)

    def pin_level(self, port: int, pin: int) -> int:
        if self.dir[port] >> pin & 1:
            return self.out[port] >> pin & 1
        return self.external(port, pin)

    def port_level(self, port: int) -> int:
        v = 0
        for pin in range(32):
            if self.pin_level(port, pin):
                v |= 1 << pin
        return v

    # -- driving ------------------------------------------------------------
    def _set_out(self, port: int, value: int) -> None:
        """Apply a new driven-level word for ``port`` and service TCK edges."""
        old = self.out[port]
        if old == value:
            return
        self.out[port] = value & 0xFFFFFFFF
        changed = old ^ self.out[port]
        for (p, pin), name in LEDS.items():
            if p == port and changed >> pin & 1:
                self.led_state[name] = self.out[port] >> pin & 1
        if port == JTAG_TCK[0] and changed >> JTAG_TCK[1] & 1:
            self._tck_edge()
        if port == FLASH_CS[0] and changed >> FLASH_CS[1] & 1:
            self.flash.select(not (self.out[port] >> FLASH_CS[1] & 1))

    def _tck_edge(self) -> None:
        tck = self.out[JTAG_TCK[0]] >> JTAG_TCK[1] & 1
        if tck:
            self.cpld.tck_rise(
                tms=self.out[JTAG_TMS[0]] >> JTAG_TMS[1] & 1,
                tdi=self.out[JTAG_TDI[0]] >> JTAG_TDI[1] & 1)
        else:
            self.cpld.tck_fall()

    # -- the register file --------------------------------------------------
    def hw_read(self, addr: int, size: int) -> Optional[int]:
        off = addr - GPIO_BASE
        self.reads += 1
        if off < 0x1000:                                   # byte pin registers
            port, pin = off >> 5, off & 0x1F
            if port < NPORTS:
                return self.pin_level(port, pin)
            return 0
        if off < 0x2000:                                   # word pin registers
            rel = off - 0x1000
            port, pin = rel >> 7, (rel & 0x7F) >> 2
            if port < NPORTS:
                # The word registers read all-ones/zero on real silicon; the
                # firmware only ever tests for non-zero (gpio_read returns bool).
                return 0xFFFFFFFF if self.pin_level(port, pin) else 0
            return 0
        rel = off - 0x2000
        port = (rel & 0x7F) >> 2
        which = rel & ~0x7F
        if port >= NPORTS:
            return 0
        if which == 0x000:
            return self.dir[port]
        if which == 0x080:
            return self.mask[port]
        if which == 0x100:
            return self.port_level(port)
        if which == 0x180:
            return self.port_level(port) & ~self.mask[port]
        # SET/CLR/NOT read back the driven value on this part.
        return self.out[port]

    def hw_write(self, addr: int, size: int, value: int) -> bool:
        off = addr - GPIO_BASE
        self.writes += 1
        value &= 0xFFFFFFFF
        if off < 0x1000:                                   # byte pin registers
            port, pin = off >> 5, off & 0x1F
            if port < NPORTS:
                bit = 1 << pin
                self._set_out(port, (self.out[port] | bit) if value & 1
                              else (self.out[port] & ~bit))
            return True
        if off < 0x2000:                                   # word pin registers
            rel = off - 0x1000
            port, pin = rel >> 7, (rel & 0x7F) >> 2
            if port < NPORTS:
                bit = 1 << pin
                self._set_out(port, (self.out[port] | bit) if value
                              else (self.out[port] & ~bit))
            return True
        rel = off - 0x2000
        port = (rel & 0x7F) >> 2
        which = rel & ~0x7F
        if port >= NPORTS:
            return True
        if which == 0x000:
            self.dir[port] = value
        elif which == 0x080:
            self.mask[port] = value
        elif which == 0x100:
            self._set_out(port, value)
        elif which == 0x180:
            self._set_out(port, (self.out[port] & self.mask[port])
                          | (value & ~self.mask[port]))
        elif which == 0x200:
            self._set_out(port, self.out[port] | value)
        elif which == 0x280:
            self._set_out(port, self.out[port] & ~value)
        elif which == 0x300:
            self._set_out(port, self.out[port] ^ value)
        return True

    # -- diagnostics --------------------------------------------------------
    def summary(self) -> dict:
        return {
            "reads": self.reads,
            "writes": self.writes,
            "leds": dict(self.led_state),
            "straps": {"P5_0": self.straps.get((2, 9), 0),
                       "P6_10": self.straps.get((3, 6), 0),
                       "P6_5": self.straps.get((3, 4), 0)},
            "expected_board_id": decode_board_straps(
                self.straps.get((2, 9), 0), self.straps.get((3, 6), 0),
                self.straps.get((3, 4), 0)),
        }


_GPIO: Optional[Lpc43xxGpio] = None


def get_gpio() -> Lpc43xxGpio:
    global _GPIO
    if _GPIO is None:
        _GPIO = Lpc43xxGpio()
    return _GPIO
