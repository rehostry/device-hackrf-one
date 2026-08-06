# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The LPC43xx **USB0 device controller** -- a Chipidea/NXP core with EHCI-style
queue heads and transfer descriptors in guest RAM.

This is the seam. Everything else in this device exists to get the firmware
here, because on a HackRF One *every* command is a USB vendor control transfer.

WHY IT IS MODELLED AT THE DESCRIPTOR LEVEL. This controller is a **bus master**.
The CPU never writes packet bytes to a FIFO: it builds a linked list of
transfer descriptors in RAM, points a queue head at the head of the list, and
writes one bit to ``ENDPTPRIME``. The controller then walks the list and does
the DMA itself. So modelling this at "register level" alone would model nothing
-- the interesting state is entirely in RAM. The model therefore reads and
writes the firmware's own dQH/dTD structures, which is also what makes the
attack's oracle honest: the reply bytes are read from the address the
**firmware** put in ``dTD.buffer_pointer_page[0]``, with the length the
**firmware** put in ``dTD.total_bytes``.

Structures (libopencm3 ``lpc43xx/usb.h``), little-endian::

    dQH (64 B, one per endpoint+direction, indexed (ep*2 + is_in)):
      +0x00 capabilities        MPL, IOS, ZLT, MULT
      +0x04 current_dtd_pointer
      +0x08 next_dtd_pointer
      +0x0C total_bytes         the dTD token overlay
      +0x10 buffer_pointer_page[5]
      +0x24 _reserved_0         (the firmware stashes its usb_endpoint_t here)
      +0x28 setup[8]            <- where the controller deposits a SETUP packet
      +0x30 _reserved_1[4]

    dTD (32 B):
      +0x00 next_dtd_pointer    bit0 = TERMINATE
      +0x04 total_bytes         [30:16] bytes, bit15 IOC, bit7 ACTIVE, bit6 HALTED
      +0x08 buffer_pointer_page[5]

Register map is ``USB0_BASE + 0x140..0x1D8`` (UM10503 §23.6); the offsets and
bit positions here are the ones the firmware's own header uses.

WHAT THE HOST DRIVES. :meth:`host_setup`, :meth:`host_in` and :meth:`host_out`
are the three transactions a USB host can perform on a control endpoint. They
are called by ``usb_host.UsbHost``, one per step, from inside the firmware's own
ISR poll of ``USBSTS`` -- see that module for why.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from halucinator import hal_log

from . import hal_link

log = hal_log.getHalLogger()

USB0_BASE = 0x40006000

# --- register offsets -------------------------------------------------------
CAPLENGTH = 0x100
DCIVERSION = 0x120
DCCPARAMS = 0x124
USBCMD = 0x140
USBSTS = 0x144
USBINTR = 0x148
FRINDEX = 0x14C
DEVICEADDR = 0x154
ENDPOINTLISTADDR = 0x158
TTCTRL = 0x15C
BURSTSIZE = 0x160
TXFILLTUNING = 0x164
BINTERVAL = 0x174
ENDPTNAK = 0x178
ENDPTNAKEN = 0x17C
PORTSC1 = 0x184
OTGSC = 0x1A4
USBMODE = 0x1A8
ENDPTSETUPSTAT = 0x1AC
ENDPTPRIME = 0x1B0
ENDPTFLUSH = 0x1B4
ENDPTSTAT = 0x1B8
ENDPTCOMPLETE = 0x1BC
ENDPTCTRL0 = 0x1C0

# --- bits -------------------------------------------------------------------
USBCMD_RS = 1 << 0
USBCMD_RST = 1 << 1
USBCMD_ATDTW = 1 << 14

USBSTS_UI = 1 << 0
USBSTS_UEI = 1 << 1
USBSTS_PCI = 1 << 2
USBSTS_URI = 1 << 6
USBSTS_SRI = 1 << 7
USBSTS_SLI = 1 << 8
USBSTS_NAKI = 1 << 16

ENDPTCTRL_RXS = 1 << 0
ENDPTCTRL_RXR = 1 << 6
ENDPTCTRL_RXE = 1 << 7
ENDPTCTRL_TXS = 1 << 16
ENDPTCTRL_TXR = 1 << 22
ENDPTCTRL_TXE = 1 << 23

DTD_TERMINATE = 1 << 0
DTD_IOC = 1 << 15
DTD_ACTIVE = 1 << 7
DTD_HALTED = 1 << 6
DTD_TOTAL_SHIFT = 16
DTD_TOTAL_MASK = 0x7FFF << DTD_TOTAL_SHIFT

QH_SIZE = 64
DTD_SIZE = 32

NUM_EP = 6


def qh_index(ep: int, is_in: bool) -> int:
    return ep * 2 + (1 if is_in else 0)


class Lpc43xxUsb0:
    """A Chipidea device controller: registers plus dQH/dTD bus mastering."""

    def __init__(self) -> None:
        self.regs: Dict[int, int] = {}
        self.usbcmd = 0
        self.usbsts = 0
        self.usbintr = 0
        self.deviceaddr = 0
        self.listaddr = 0
        self.usbmode = 0
        self.otgsc = 0
        # PORTSC1.PSPD: 0 = full speed. The firmware selects its full-speed
        # configuration descriptor from this, so it must be self-consistent
        # with the 64-byte bulk endpoints the host then sees.
        self.portsc1 = 0
        self.endptsetupstat = 0
        self.endptstat = 0
        self.endptcomplete = 0
        self.endptnak = 0
        self.endptnaken = 0
        self.endptctrl = [0] * NUM_EP
        #: head dTD address per (ep, is_in), set when the endpoint is primed.
        self.primed: Dict[Tuple[int, bool], int] = {}
        #: Evidence counters -- bookkeeping only, never an oracle.
        self.setups_delivered = 0
        self.in_transfers = 0
        self.out_transfers = 0
        self.bus_resets = 0
        self.isr_polls = 0
        self.stalls: List[int] = []
        #: Where the last IN transfer's bytes and length came from.
        self.last_in_provenance: Optional[dict] = None
        self.log_lines: List[str] = []
        #: Called on every USBSTS read, so the host advances exactly when the
        #: firmware's own ISR asks the controller what happened.
        self.on_poll = None

    # -- helpers -------------------------------------------------------------
    @property
    def running(self) -> bool:
        return bool(self.usbcmd & USBCMD_RS)

    def qh_addr(self, ep: int, is_in: bool) -> int:
        return self.listaddr + qh_index(ep, is_in) * QH_SIZE

    def raise_ui(self) -> None:
        self.usbsts |= USBSTS_UI

    def pending_irq(self) -> bool:
        """True when the controller would be asserting its interrupt line."""
        return bool(self.usbsts & self.usbintr)

    def endpoint_stalled(self, ep: int) -> bool:
        return bool(self.endptctrl[ep] & (ENDPTCTRL_RXS | ENDPTCTRL_TXS))

    def clear_stall(self, ep: int) -> None:
        self.endptctrl[ep] &= ~(ENDPTCTRL_RXS | ENDPTCTRL_TXS)

    # -- dQH / dTD access ----------------------------------------------------
    def _dtd(self, addr: int) -> Optional[Tuple[int, int, List[int]]]:
        raw = hal_link.read_mem(addr, DTD_SIZE)
        if len(raw) != DTD_SIZE:
            return None
        nxt, token = struct.unpack_from("<II", raw, 0)
        pages = list(struct.unpack_from("<5I", raw, 8))
        return nxt, token, pages

    @staticmethod
    def _pages_read(pages: List[int], length: int) -> bytes:
        """Read ``length`` bytes across the dTD's five 4 kB buffer pages.

        Only ``buffer_pointer_page[0]`` carries an offset; the rest are page
        aligned. This is the controller's own scatter rule (UM10503 §23.9.2).
        """
        out = bytearray()
        addr = pages[0]
        idx = 0
        while len(out) < length and idx < 5:
            page_end = (addr & ~0xFFF) + 0x1000
            chunk = min(length - len(out), page_end - addr)
            out += hal_link.read_mem(addr, chunk)
            idx += 1
            if idx < 5:
                addr = pages[idx]
        return bytes(out[:length])

    @staticmethod
    def _pages_write(pages: List[int], data: bytes) -> None:
        addr = pages[0]
        idx = 0
        pos = 0
        while pos < len(data) and idx < 5:
            page_end = (addr & ~0xFFF) + 0x1000
            chunk = min(len(data) - pos, page_end - addr)
            hal_link.write_mem(addr, data[pos:pos + chunk])
            pos += chunk
            idx += 1
            if idx < 5:
                addr = pages[idx]

    def _retire(self, ep: int, is_in: bool, td: int, token: int,
                remaining: int) -> None:
        """Complete a dTD the way the controller does, then notify.

        The status byte is cleared (ACTIVE off), and the byte counter is set to
        what is LEFT -- ``usb_queue_transfer_complete()`` computes
        ``transferred = maximum_length - total_bytes`` from exactly this field.
        The dQH overlay is updated too, because the firmware's next prime reads
        it back.
        """
        new_token = (token & ~(DTD_TOTAL_MASK | 0xFF)) \
            | ((remaining & 0x7FFF) << DTD_TOTAL_SHIFT)
        hal_link.write_u32(td + 4, new_token)
        qh = self.qh_addr(ep, is_in)
        hal_link.write_u32(qh + 0x04, td)              # current_dtd_pointer
        nxt = hal_link.read_u32(td + 0x00)
        hal_link.write_u32(qh + 0x08, nxt)             # next_dtd_pointer
        hal_link.write_u32(qh + 0x0C, new_token)       # the token overlay

        bit = (1 << (16 + ep)) if is_in else (1 << ep)
        self.endptstat &= ~bit
        self.endptcomplete |= bit
        if nxt & DTD_TERMINATE or nxt == 0:
            self.primed.pop((ep, is_in), None)
        else:
            self.primed[(ep, is_in)] = nxt
            self.endptstat |= bit
        self.raise_ui()

    # -- host-side transactions ---------------------------------------------
    def host_setup(self, ep: int, data: bytes) -> bool:
        """Deliver a SETUP packet, exactly as the hardware would.

        A control endpoint **cannot NAK a SETUP** -- the hardware always accepts
        it into the queue head's ``setup`` field and raises
        ``ENDPTSETUPSTAT``. So this never waits for the endpoint to be primed;
        waiting would deadlock against correct firmware (playbook trap 2.80).
        Taking a SETUP also aborts anything primed on the control endpoints,
        which is what the firmware's own ``usb_setup_complete()`` assumes.
        """
        if len(data) != 8 or not self.listaddr:
            return False
        hal_link.write_mem(self.qh_addr(ep, False) + 0x28, data)
        self.primed.pop((ep, False), None)
        self.primed.pop((ep, True), None)
        self.endptstat &= ~((1 << ep) | (1 << (16 + ep)))
        self.endptsetupstat |= 1 << ep
        self.setups_delivered += 1
        self.raise_ui()
        return True

    def host_in(self, ep: int) -> Optional[bytes]:
        """Take one IN transfer's worth of bytes out of the primed dTD.

        Returns None when the firmware has not primed the endpoint (the
        hardware would NAK). The bytes come from guest RAM at the address the
        FIRMWARE wrote into the descriptor -- this model never supplies them.
        """
        td = self.primed.get((ep, True))
        if td is None or not (self.endptstat & (1 << (16 + ep))):
            return None
        got = self._dtd(td)
        if got is None:
            return None
        _nxt, token, pages = got
        if not token & DTD_ACTIVE:
            return None
        length = (token & DTD_TOTAL_MASK) >> DTD_TOTAL_SHIFT
        data = self._pages_read(pages, length) if length else b""
        # Provenance for the attack's oracle: BOTH the address and the length
        # came out of the descriptor the FIRMWARE built. Nothing here chose
        # either, which is what makes the reply bytes non-forgeable by the
        # host -- see PROVENANCE.md §2.6.
        self.last_in_provenance = {
            "dtd": td,
            "dqh": self.qh_addr(ep, True),
            "buffer": pages[0],
            "token": token,
            "length_from_firmware": length,
        }
        self._retire(ep, True, td, token, 0)
        self.in_transfers += 1
        return data

    def host_out(self, ep: int, data: bytes) -> Optional[int]:
        """Give the firmware OUT bytes (or a zero-length status packet)."""
        td = self.primed.get((ep, False))
        if td is None or not (self.endptstat & (1 << ep)):
            return None
        got = self._dtd(td)
        if got is None:
            return None
        _nxt, token, pages = got
        if not token & DTD_ACTIVE:
            return None
        capacity = (token & DTD_TOTAL_MASK) >> DTD_TOTAL_SHIFT
        n = min(len(data), capacity)
        if n:
            self._pages_write(pages, data[:n])
        self._retire(ep, False, td, token, capacity - n)
        self.out_transfers += 1
        return n

    def bus_reset(self) -> None:
        """Drive a USB bus reset: the host has just plugged this device in."""
        self.bus_resets += 1
        self.endptsetupstat = 0
        self.endptcomplete = 0
        self.endptstat = 0
        self.primed.clear()
        self.usbsts |= USBSTS_URI | USBSTS_PCI
        log.info("Lpc43xxUsb0: bus reset driven (URI+PCI) -- the HackRF has "
                 "been 'plugged in'")

    # -- the register file ---------------------------------------------------
    def hw_read(self, addr: int, size: int) -> int:
        off = addr - USB0_BASE
        if off == USBSTS:
            # The ISR's very first action. Advancing the host here is the
            # honest moment: the firmware is asking the controller what
            # happened, and on silicon the answer reflects bus activity that
            # occurred before the read.
            self.isr_polls += 1
            if self.isr_polls in (1, 100, 10000):
                log.info("Lpc43xxUsb0: the firmware's usb0_isr has read "
                         "USBSTS %d time(s)", self.isr_polls)
            if self.on_poll is not None:
                try:
                    self.on_poll(self)
                except Exception:  # noqa: BLE001
                    log.exception("Lpc43xxUsb0: host step raised")
            return self.usbsts
        if off == USBCMD:
            return self.usbcmd
        if off == USBINTR:
            return self.usbintr
        if off == DEVICEADDR:
            return self.deviceaddr
        if off == ENDPOINTLISTADDR:
            return self.listaddr
        if off == PORTSC1:
            return self.portsc1
        if off == USBMODE:
            return self.usbmode
        if off == OTGSC:
            return self.otgsc
        if off == ENDPTSETUPSTAT:
            return self.endptsetupstat
        if off == ENDPTPRIME:
            # Priming is instantaneous in this model, so the bit the firmware
            # polls (`while (ENDPTPRIME & mask) {}`) is always already clear.
            return 0
        if off == ENDPTFLUSH:
            return 0
        if off == ENDPTSTAT:
            return self.endptstat
        if off == ENDPTCOMPLETE:
            return self.endptcomplete
        if off == ENDPTNAK:
            return self.endptnak
        if off == ENDPTNAKEN:
            return self.endptnaken
        if ENDPTCTRL0 <= off < ENDPTCTRL0 + NUM_EP * 4 and off % 4 == 0:
            return self.endptctrl[(off - ENDPTCTRL0) >> 2]
        if off == CAPLENGTH:
            return 0x01000040          # CAPLENGTH 0x40, HCIVERSION 0x0100
        if off == DCCPARAMS:
            return 0x00000186          # HOST=0, DEVICE=1, DEN=6
        if off == DCIVERSION:
            return 0x0001
        return self.regs.get(off, 0)

    def hw_write(self, addr: int, size: int, value: int) -> bool:
        off = addr - USB0_BASE
        value &= 0xFFFFFFFF
        if off == USBCMD:
            if value & USBCMD_RST:
                # A controller reset completes immediately here; the firmware
                # polls RST until it reads back clear, so it must NOT stick.
                self._controller_reset()
                value &= ~USBCMD_RST
            was_running = self.running
            self.usbcmd = value
            if self.running and not was_running:
                log.info("Lpc43xxUsb0: USBCMD.RS set -- the device controller "
                         "is RUNNING (usb_run() reached)")
            return True
        if off == USBSTS:
            self.usbsts &= ~value                     # write-1-to-clear
            return True
        if off == USBINTR:
            self.usbintr = value
            return True
        if off == DEVICEADDR:
            self.deviceaddr = value
            return True
        if off == ENDPOINTLISTADDR:
            self.listaddr = value & ~0x7FF
            log.info("Lpc43xxUsb0: ENDPOINTLISTADDR = 0x%08x (the firmware's "
                     "own dQH array)", self.listaddr)
            return True
        if off == USBMODE:
            self.usbmode = value
            return True
        if off == OTGSC:
            self.otgsc = value
            return True
        if off == PORTSC1:
            self.portsc1 = value
            return True
        if off == ENDPTSETUPSTAT:
            self.endptsetupstat &= ~value
            return True
        if off == ENDPTCOMPLETE:
            self.endptcomplete &= ~value
            return True
        if off == ENDPTPRIME:
            self._prime(value)
            return True
        if off == ENDPTFLUSH:
            self._flush(value)
            return True
        if off == ENDPTNAK:
            self.endptnak &= ~value
            return True
        if off == ENDPTNAKEN:
            self.endptnaken = value
            return True
        if ENDPTCTRL0 <= off < ENDPTCTRL0 + NUM_EP * 4 and off % 4 == 0:
            ep = (off - ENDPTCTRL0) >> 2
            before = self.endptctrl[ep]
            # RXR/TXR reset the data toggle and are self-clearing.
            self.endptctrl[ep] = value & ~(ENDPTCTRL_RXR | ENDPTCTRL_TXR)
            newly = self.endptctrl[ep] & ~before
            if newly & (ENDPTCTRL_RXS | ENDPTCTRL_TXS):
                self.stalls.append(ep)
                msg = ("ENDPTCTRL%d STALL set by the firmware (0x%08x)"
                       % (ep, self.endptctrl[ep]))
                self.log_lines.append(msg)
                log.info("Lpc43xxUsb0: %s", msg)
            return True
        self.regs[off] = value
        return True

    # -- controller internals ------------------------------------------------
    def _controller_reset(self) -> None:
        self.endptsetupstat = 0
        self.endptcomplete = 0
        self.endptstat = 0
        self.endptnak = 0
        self.primed.clear()
        self.usbsts = 0
        self.usbintr = 0
        self.deviceaddr = 0

    def _prime(self, mask: int) -> None:
        """Parse the dTD list the firmware just pointed the queue head at.

        On silicon this is asynchronous and ``ENDPTPRIME`` self-clears when the
        controller has finished parsing; here it is synchronous, so the poll
        loop in ``usb_wait_for_endpoint_priming_to_finish()`` exits at once.
        """
        for ep in range(NUM_EP):
            for is_in, bit in ((False, 1 << ep), (True, 1 << (16 + ep))):
                if not mask & bit:
                    continue
                head = hal_link.read_u32(self.qh_addr(ep, is_in) + 0x08)
                if head == 0 or head & DTD_TERMINATE:
                    continue
                self.primed[(ep, is_in)] = head
                self.endptstat |= bit

    def _flush(self, mask: int) -> None:
        for ep in range(NUM_EP):
            for is_in, bit in ((False, 1 << ep), (True, 1 << (16 + ep))):
                if mask & bit:
                    self.primed.pop((ep, is_in), None)
                    self.endptstat &= ~bit

    # -- diagnostics ---------------------------------------------------------
    def summary(self) -> dict:
        return {
            "running": self.running,
            "listaddr": self.listaddr,
            "device_address": (self.deviceaddr >> 25) & 0x7F,
            "setups_delivered": self.setups_delivered,
            "in_transfers": self.in_transfers,
            "out_transfers": self.out_transfers,
            "bus_resets": self.bus_resets,
            "isr_polls": self.isr_polls,
            "endptctrl0": self.endptctrl[0],
            "stalled_ep0": self.endpoint_stalled(0),
        }


_USB: Optional[Lpc43xxUsb0] = None


def get_usb() -> Lpc43xxUsb0:
    """The single USB0 controller (models are constructed more than once --
    playbook trap 2.3 -- so its state cannot live on the model instance)."""
    global _USB
    if _USB is None:
        _USB = Lpc43xxUsb0()
    return _USB
