# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""One region for the whole LPC43xx peripheral band, routing to sub-models.

HALucinator requires every peripheral region to be a 4 kB-aligned multiple of
4 kB and forbids overlaps -- and declaring a modelled page *inside* a catch-all's
range leaves the overlap mapped by neither (playbook traps 2.36/2.39/2.61). The
LPC43xx spreads its blocks from 0x40000000 to 0x40110000, so expressing "a
catch-all plus four modelled pages" as eight non-overlapping regions is both
fiddly and easy to get silently wrong.

So this is the router pattern: **one** region covering 0x40000000..0x401FFFFF,
dispatching by absolute address to the real models and falling through to
``AutoPeripheral`` (recording + busy-wait breaker) for everything else. It also
mirrors what the SoC's own bus bridge does.

Deliberately *not* modelled, and why that is honest here:

* **SSP0/SSP1 and I2C0/I2C1** carry the RF front end (MAX2837 transceiver,
  RFFC5071 mixer, Si5351C clock generator, MAX5864 codec) and the serial flash.
  Nothing is on the far end of those buses in this rehost, so reads return 0 --
  the deliberate choice from playbook trap 2.90: with 0xFF every "wait for the
  device to clear this bit" spins forever, whereas with 0x00 an absent part
  fails fast and the firmware says so itself.
* **SGPIO / GPDMA** move IQ samples. They are the RF datapath, not the control
  path, and the M0 that drives them is not run.

``HAL_HRF_MMIO_TRACE=1`` logs the first read of every ``(pc, address)`` pair
that falls through to the catch-all -- the cheapest way to find what an
unmodelled block is being asked for.
"""
from __future__ import annotations

import os
from typing import Any, Set, Tuple

from halucinator import hal_log
from halucinator.peripheral_models.auto_model import AutoPeripheral

from . import lpc43xx_gpio, lpc43xx_usb0, spi_flash

log = hal_log.getHalLogger()

_TRACE = os.environ.get("HAL_HRF_MMIO_TRACE") == "1"
_seen: Set[Tuple[int, int]] = set()

GPIO_LO, GPIO_HI = 0x400F4000, 0x400F8000
USB0_LO, USB0_HI = 0x40006000, 0x40007000
SCU_LO, SCU_HI = 0x40086000, 0x40087000
ADC0_LO, ADC1_HI = 0x400E3000, 0x400E5000

#: SSP0 / SSP1 (the SPI controllers). SSP0 carries the serial flash and the
#: MAX5864 codec; SSP1 the MAX2837 transceiver.
SSP0_BASE = 0x40083000
SSP_BASES = (SSP0_BASE, 0x400C5000)
#: I2C0 / I2C1. I2C0 carries the Si5351C clock generator and (if fitted) a
#: PortaPack; I2C1 the Operacake antenna switches.
I2C_BASES = (0x400A1000, 0x400E0000)

# SSP status register (+0x0C) bits, UM10503 §22.6.4.
SSP_SR_TFE = 1 << 0      # transmit FIFO empty
SSP_SR_TNF = 1 << 1      # transmit FIFO not full
SSP_SR_RNE = 1 << 2      # receive FIFO not empty
SSP_SR_RFF = 1 << 3      # receive FIFO full
SSP_SR_BSY = 1 << 4      # busy

# I2C control-set register (+0x00) bits, UM10503 §21.7.1.
I2C_CONSET_SI = 1 << 3
I2C_CONSET_I2EN = 1 << 6
#: STAT after SLA+W with **no** acknowledge -- i.e. nothing on the bus. That is
#: the truth here, and it is what `i2c_probe()` tests (it wants 0x18 = ACKed).
I2C_STAT_SLAW_NAK = 0x20

#: Clock Generation Unit, the two Clock Control Units, the Reset Generation
#: Unit and the Configuration Registers block.
CGU_BASE = 0x40050000
CCU1_BASE = 0x40051000
CCU2_BASE = 0x40052000
RGU_BASE = 0x40053000
CREG_BASE = 0x40043000

#: CGU PLL status registers (bit 0 = LOCK) and the CTRL register each one
#: belongs to (bit 0 = PD, power down). UM10503 §13.6.
CGU_PLL_STAT_CTRL = {
    0x1C: 0x20,      # PLL0USB_STAT   <- PLL0USB_CTRL
    0x2C: 0x30,      # PLL0AUDIO_STAT <- PLL0AUDIO_CTRL
    0x40: 0x44,      # PLL1_STAT      <- PLL1_CTRL
}
#: Reset value of every PLL CTRL register: powered down.
CGU_CTRL_PD = 0x01

#: RGU. RESET_ACTIVE_STATUS{0,1} read **1 for a block that is NOT in reset**,
#: which is the opposite polarity from RESET_CTRL{0,1} (write 1 to assert).
RGU_ACTIVE_STATUS0 = 0x150
RGU_ACTIVE_STATUS1 = 0x154

#: The ADC value the pin-strap probe averages. ``check_pin_strap()`` classifies
#: a reading as ABSENT when 2 <= x <= 1022, which is the "nothing fitted"
#: verdict for a pre-r6 HackRF One and yields BOARD_REV_HACKRF1_OLD.
#: Mid-scale is the honest choice for an unconnected 10-bit input with the
#: internal divider: it is neither rail.
ADC_MIDSCALE = 512


class Lpc43xxSoc(AutoPeripheral):
    """The LPC43xx peripheral band. Named so it does NOT trip ``skip_svc``."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.gpio = lpc43xx_gpio.get_gpio()
        self.usb = lpc43xx_usb0.get_usb()
        #: SCU pinmux is write-only in practice; keep it as plain storage so a
        #: read-back never sees the busy-wait breaker's escalating garbage.
        self._scu: dict = {}
        #: ADCR.SEL per ADC block, so ADGDR can report the right channel.
        self._adc_sel: dict = {}
        self._ssp_regs: dict = {}
        self._ssp_rx: dict = {}
        self._i2c_regs: dict = {}
        self._clock: dict = {}
        self.flash = spi_flash.get_flash()

    def hw_read(self, offset: int, size: int, pc: int = 0xBAADBAAD,
                **kwargs: Any) -> int:
        addr = self.address + offset
        if GPIO_LO <= addr < GPIO_HI:
            v = self.gpio.hw_read(addr, size)
            return 0 if v is None else v
        if USB0_LO <= addr < USB0_HI:
            return self.usb.hw_read(addr, size)
        if SCU_LO <= addr < SCU_HI:
            return self._scu.get(addr, 0)
        if ADC0_LO <= addr < ADC1_HI:
            return self._adc_read(addr)
        base = addr & ~0xFFF
        if base in SSP_BASES:
            return self._ssp_read(base, addr & 0xFFF)
        if base in I2C_BASES:
            return self._i2c_read(base, addr & 0xFFF)
        if base in (CGU_BASE, CCU1_BASE, CCU2_BASE, RGU_BASE, CREG_BASE):
            return self._clock_read(base, addr & 0xFFF)
        value = super().hw_read(offset, size, pc=pc, **kwargs)
        if _TRACE:
            key = (pc, addr)
            if key not in _seen:
                _seen.add(key)
                log.info("Lpc43xxSoc: READ pc=0x%08x addr=0x%08x -> 0x%08x",
                         pc, addr, value)
        return value

    def hw_write(self, offset: int, size: int, value: int,
                 pc: int = 0xBAADBAAD, **kwargs: Any) -> bool:
        addr = self.address + offset
        if GPIO_LO <= addr < GPIO_HI:
            return self.gpio.hw_write(addr, size, value)
        if USB0_LO <= addr < USB0_HI:
            return self.usb.hw_write(addr, size, value)
        if SCU_LO <= addr < SCU_HI:
            self._scu[addr] = value
            return True
        if ADC0_LO <= addr < ADC1_HI:
            self._adc_write(addr, value)
            return True
        base = addr & ~0xFFF
        if base in SSP_BASES:
            return self._ssp_write(base, addr & 0xFFF, value)
        if base in I2C_BASES:
            return self._i2c_write(base, addr & 0xFFF, value)
        if base in (CGU_BASE, CCU1_BASE, CCU2_BASE, RGU_BASE, CREG_BASE):
            self._clock[(base, addr & 0xFFF)] = value
            return True
        return super().hw_write(offset, size, value, pc=pc, **kwargs)

    # -- clocks and resets --------------------------------------------------
    #
    # Three registers here are polled in a loop and none of them can be left to
    # the busy-wait breaker:
    #
    #   CGU PLL1_STAT / PLL0USB_STAT bit 0 -- `cpu_clock_init()` waits for LOCK.
    #   CCU  <branch>_STAT bit 0           -- waits for a branch clock to RUN.
    #   RGU  RESET_ACTIVE_STATUS{0,1}      -- `usb_peripheral_reset()` waits for
    #                                         USB0 to come **out** of reset, and
    #                                         `ipc_start_m0()` for the M0::
    #
    #     80b0: ldr.w r3, [r2, #340]   ; RESET_ACTIVE_STATUS1
    #     80b8: lsls  r3, r3, #7       ; test bit 24 (M0APP)
    #     80ba: bpl.n 0x80a4           ;   ...and keep de-asserting until set
    #
    # Reporting every block out of reset and every PLL locked is what the part
    # reports once the firmware's own sequence has run; the *writes* still land
    # in storage, so nothing is being skipped, only answered.
    def _clock_read(self, base: int, off: int) -> int:
        if base == CGU_BASE:
            ctrl_off = CGU_PLL_STAT_CTRL.get(off)
            if ctrl_off is not None:
                # LOCK is the INVERSE of the PLL's own power-down bit. Nailing
                # LOCK high instead makes the *unlock* wait unsatisfiable:
                #
                #   4ad8: str  r3, [r4, #32]   ; PLL0USB_CTRL |= PD
                #   4adc: ldr  r2, [r3, #28]   ; PLL0USB_STAT
                #   4ade: lsls r1, r2, #31
                #   4ae0: bmi.n 0x4adc         ;   spin WHILE locked
                #   ...  reprogram MDIV/NP_DIV, clear PD ...
                #   4afc: ldr  r2, [r3, #28]
                #   4b00: bpl.n 0x4afc         ;   spin UNTIL locked
                #
                # Measured with LOCK pinned high: 666 667 executions of those
                # three instructions per 2 M-instruction window, indefinitely.
                # Playbook trap 2.72 -- mirror a ready bit from its own enable
                # and both directions work for free, because that is what the
                # silicon does.
                ctrl = self._clock.get((base, ctrl_off), CGU_CTRL_PD)
                return 0 if ctrl & 1 else 1
            return self._clock.get((base, off),
                                   CGU_CTRL_PD if off in
                                   CGU_PLL_STAT_CTRL.values() else 0)
        if base in (CCU1_BASE, CCU2_BASE):
            # From 0x100 up, each branch clock is a CFG/STAT pair; STAT bit 0
            # (RUN) mirrors CFG bit 0. Below that are the block's own PM and
            # BASE_STAT registers, which are not a pair.
            if off >= 0x100 and off & 4:
                return self._clock.get((base, off & ~4), 0) & 1
            return self._clock.get((base, off), 0)
        if base == RGU_BASE:
            # ACTIVE_STATUS is the INVERSE of CTRL: a bit reads 1 when the
            # block is NOT held in reset. Returning all-ones unconditionally
            # satisfies `ipc_start_m0()` and breaks `ipc_halt_m0()`, which
            # asserts the M0APP reset and then waits for the same bit to go to
            # ZERO::
            #
            #   807e: str.w r3, [r2, #260]   ; RESET_CTRL1 = ~status | M0APP
            #   8082: ldr.w r3, [r2, #340]   ; RESET_ACTIVE_STATUS1
            #   808a: lsls  r3, r3, #7       ; test bit 24
            #   808c: bmi.n 0x8076           ;   spin WHILE still running
            #
            # Measured with all-ones: 333 333 executions per 3 M-instruction
            # window, for ever. Third instance of playbook trap 2.72 in this
            # one boot -- ADC channel, PLL lock, and now reset status.
            if off == RGU_ACTIVE_STATUS0:
                return ~self._clock.get((base, 0x100), 0) & 0xFFFFFFFF
            if off == RGU_ACTIVE_STATUS1:
                return ~self._clock.get((base, 0x104), 0) & 0xFFFFFFFF
            return self._clock.get((base, off), 0)
        return self._clock.get((base, off), 0)

    # -- SSP (SPI) ----------------------------------------------------------
    #
    # Nothing is on the far end of either SPI bus in this rehost, and the
    # honest model of that is a controller that always completes the transfer
    # and shifts **zeros** back (playbook trap 2.90: with 0xFF every "set this
    # bit and poll until the device clears it" spins forever, whereas with 0x00
    # an absent part fails fast).
    #
    # Left to the catch-all this was a hard hang, not a slow one: the busy-wait
    # breaker escalates to all-ones, which sets `SR.BSY` -- so
    # `while (SSP_SR & BSY);` can never exit. Two PCs (0x607e, 0x608c) sat on
    # 0x4008300c forever. Status registers need the real bit meanings, not a
    # generic "something non-zero".
    def _ssp_read(self, base: int, off: int) -> int:
        if off == 0x0C:                        # SR
            sr = SSP_SR_TFE | SSP_SR_TNF
            if self._ssp_rx.get(base):
                sr |= SSP_SR_RNE
            return sr
        if off == 0x08:                        # DR
            q = self._ssp_rx.get(base)
            return q.pop(0) if q else 0
        if off in (0x18, 0x1C):                # RIS / MIS
            return 0
        return self._ssp_regs.get((base, off), 0)

    def _ssp_write(self, base: int, off: int, value: int) -> bool:
        if off == 0x08:                        # DR: the transfer completes now
            # SSP0 carries the W25Q80BV serial flash; SSP1 has nothing wired.
            got = self.flash.xfer(value) if base == SSP0_BASE else 0
            self._ssp_rx.setdefault(base, []).append(got)
        else:
            self._ssp_regs[(base, off)] = value
        return True

    # -- I2C ----------------------------------------------------------------
    #
    # libopencm3's `i2c_tx_start()`/`i2c_tx_byte()` set a bit in CONSET and
    # then `while (!(I2C_CONSET & SI));`. Reporting SI permanently pending is
    # what a controller with a completed (if unacknowledged) transaction does,
    # and it lets every transfer finish.
    #
    # `i2c_probe()` is the one caller that reads STAT, and it wants 0x18
    # (SLA+W acknowledged). Answering 0x20 (**not** acknowledged) means
    # "nothing is fitted at that address" -- which is the truth for a bare
    # HackRF One with no PortaPack and no Operacake, and is why the firmware
    # correctly selects its null UI.
    def _i2c_read(self, base: int, off: int) -> int:
        if off == 0x00:                        # CONSET
            return I2C_CONSET_I2EN | I2C_CONSET_SI
        if off == 0x04:                        # STAT
            return I2C_STAT_SLAW_NAK
        if off == 0x08:                        # DAT
            return 0
        return self._i2c_regs.get((base, off), 0)

    def _i2c_write(self, base: int, off: int, value: int) -> bool:
        self._i2c_regs[(base, off)] = value
        return True

    # -- ADC ----------------------------------------------------------------
    #
    # LPC43xx ADC0/ADC1 (UM10503 §46):
    #     +0x00 ADCR    SEL[7:0] = the channel bitmask, START[26:24]
    #     +0x04 ADGDR   DONE[31], CHN[26:24], V_VREF[15:6]
    #     +0x0C ADINTEN
    #     +0x10 ADDR0 .. +0x2C ADDR7
    #     +0x30 ADSTAT
    #
    # THE CHANNEL FIELD IS LOAD BEARING. The firmware's own `adc_read()` is::
    #
    #     6c46: str  r3, [r2, #0]          ; ADCR = enable | START | 1<<pin
    #     6c48: ldr  r3, [r2, #4]          ; ADGDR
    #     6c4a: cmp  r3, #0
    #     6c4c: bge.n 0x6c48               ;   spin until DONE (bit 31)
    #     6c4e: ldr  r3, [r2, #4]
    #     6c50: ubfx r3, r3, #24, #3       ; CHN
    #     6c54: cmp  r3, r4                ; ...and until it is MY channel
    #     6c56: bne.n 0x6c48
    #     6c58: ldr  r0, [r2, #4]
    #     6c5a: ubfx r0, r0, #6, #10       ; the value it actually returns
    #
    # Answering DONE with CHN left at zero satisfies the first loop and hangs
    # forever in the second for any channel but 0 -- and the pin straps this
    # firmware probes are channels 3, 4 and 7. Measured before this was
    # modelled: every exception return resumed at **0x6c54**, the `cmp`.
    # Playbook trap 2.59: the register that is COMPARED and the register field
    # that is RETURNED are different, and only getting both right works.
    def _adc_write(self, addr: int, value: int) -> None:
        if addr & 0xFFF == 0x00:
            self._adc_sel[addr & ~0xFFF] = value & 0xFF

    def _adc_channel(self, base: int) -> int:
        sel = self._adc_sel.get(base, 1)
        return (sel & -sel).bit_length() - 1 if sel else 0

    def _adc_read(self, addr: int) -> int:
        off = addr & 0xFFF
        base = addr & ~0xFFF
        sample = (1 << 31) | ((ADC_MIDSCALE & 0x3FF) << 6)
        if off == 0x04:                        # ADGDR -- DONE + CHN + value
            return sample | (self._adc_channel(base) << 24)
        if 0x10 <= off <= 0x2C:                # ADDR0..ADDR7
            return sample
        if off == 0x30:                        # ADSTAT: every channel done
            return 0xFF
        return 0
