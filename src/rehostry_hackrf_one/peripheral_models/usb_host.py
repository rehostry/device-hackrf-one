# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A minimal USB **host**, because a USB device does nothing until plugged in.

A HackRF One has no console, no serial port and no network. Its entire command
surface is USB vendor-specific control transfers. So there is no seam to poke
until something drives a bus reset, enumerates the device and issues SETUP
packets -- and that means writing the other end of the wire.

WHERE THE STATE MACHINE IS CLOCKED, and why. :meth:`step` is called from the
USB0 model's read of ``USBSTS``. That register read is the first thing
``usb0_isr()`` does::

    void usb0_isr() {
        const uint32_t status = usb_get_status();   /* reads USBSTS_D */
        if (status == 0) return;
        ...

so the host advances exactly when the firmware's own interrupt handler asks the
controller what happened -- which is precisely when a real controller's status
register would reflect bus activity that has already occurred. The ISR itself is
entered from the deterministic tick on IRQ 8 (see ``spawn.py``); IRQ 8 is the
**only** live interrupt vector in this image, which the extractor asserts.

ONE TRANSACTION PER STEP. Completing a stage and starting the next in the same
step never lets the firmware run in between: its ISR has not yet primed the next
descriptor, and the second notification would overwrite the first in the status
register. Same lesson as device-nitrokey-start.

WHAT IS NOT MODELLED: this is a host for *this* device, not a USB stack. No hub,
no error recovery, no bulk streaming, no isochronous scheduling. Only the
control endpoint is driven, because that is where every HackRF command lives.
"""
from __future__ import annotations

import os
import socket
import struct
import threading
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from halucinator import hal_log

log = hal_log.getHalLogger()

#: The address this host assigns during enumeration.
DEVICE_ADDRESS = 7

# Standard requests used during enumeration.
GET_DESCRIPTOR = 6
SET_ADDRESS = 5
SET_CONFIGURATION = 9

#: bmRequestType for a device-to-host **vendor** request to the device.
VENDOR_IN = 0xC0
#: ...and host-to-device.
VENDOR_OUT = 0x40


def setup_packet(bm_request_type: int, request: int, value: int = 0,
                 index: int = 0, length: int = 0) -> bytes:
    """Build the 8 bytes of a USB SETUP packet (USB 2.0 §9.3)."""
    return struct.pack("<BBHHH", bm_request_type & 0xFF, request & 0xFF,
                       value & 0xFFFF, index & 0xFFFF, length & 0xFFFF)


class Transfer:
    """One control transfer in flight, and its result."""

    __slots__ = ("setup", "want", "data", "status", "label", "stalled",
                 "provenance")

    def __init__(self, setup: bytes, want: int, label: str) -> None:
        self.setup = setup
        self.want = want
        self.label = label
        self.data = bytearray()
        self.status: Optional[str] = None
        self.stalled = False
        #: dTD/dQH/buffer addresses the FIRMWARE programmed for the reply.
        self.provenance: Optional[dict] = None

    @property
    def device_to_host(self) -> bool:
        return bool(self.setup[0] & 0x80)

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "setup": self.setup.hex(" "),
            "request": self.setup[1],
            "data": bytes(self.data).hex(" "),
            "length": len(self.data),
            "status": self.status,
            "stalled": self.stalled,
            "provenance": self.provenance,
        }


class UsbHost:
    """Drives bus reset, enumeration and then vendor control transfers."""

    #: Steps to wait for a reply before declaring the endpoint dead. A control
    #: transfer here needs a handful of ISR entries, not hundreds.
    STALL_STEPS = 400

    def __init__(self) -> None:
        self.state = "wait_run"
        self.address = 0
        self.configured = False
        self.enumerated = False
        self.steps = 0
        self.queue: Deque[Transfer] = deque()
        self.current: Optional[Transfer] = None
        self.done: List[Transfer] = []
        self.by_request: Dict[int, Transfer] = {}
        self.log_lines: List[str] = []
        self.vid_pid: Optional[Tuple[int, int]] = None
        self._wait = 0
        self._lock = threading.RLock()
        self._clients: List[Any] = []
        self._srv: Optional[socket.socket] = None

    # -- queueing ------------------------------------------------------------
    def queue_transfer(self, setup: bytes, want: int, label: str) -> Transfer:
        t = Transfer(setup, want, label)
        with self._lock:
            self.queue.append(t)
        return t

    def queue_vendor_in(self, request: int, value: int = 0, index: int = 0,
                        length: int = 0x20, label: str = "") -> Transfer:
        return self.queue_transfer(
            setup_packet(VENDOR_IN, request, value, index, length),
            length, label or f"vendor_in({request})")

    def _enumeration(self) -> List[Transfer]:
        return [
            Transfer(setup_packet(0x80, GET_DESCRIPTOR, 0x0100, 0, 18),
                     18, "GET_DESCRIPTOR(device)"),
            Transfer(setup_packet(0x00, SET_ADDRESS, DEVICE_ADDRESS), 0,
                     "SET_ADDRESS(%d)" % DEVICE_ADDRESS),
            Transfer(setup_packet(0x80, GET_DESCRIPTOR, 0x0200, 0, 32),
                     32, "GET_DESCRIPTOR(config)"),
            Transfer(setup_packet(0x00, SET_CONFIGURATION, 1), 0,
                     "SET_CONFIGURATION(1)"),
        ]

    # -- the state machine ---------------------------------------------------
    def step(self, usb) -> None:
        """Advance one transaction. Called from the USB0 model's USBSTS read."""
        self.steps += 1

        if self.state == "wait_run":
            if not usb.running:
                return
            usb.bus_reset()
            self.state = "settle"
            self._wait = 0
            self._note("host: driving a bus reset")
            return

        if self.state == "settle":
            # Let the firmware's own usb_bus_reset() run before enumerating.
            self._wait += 1
            if self._wait < 4:
                return
            with self._lock:
                for t in reversed(self._enumeration()):
                    self.queue.appendleft(t)
            self.state = "idle"
            self._note("host: enumerating")
            return

        if self.state == "idle":
            with self._lock:
                t = self.queue.popleft() if self.queue else None
            if t is None:
                return
            self.current = t
            self._wait = 0
            if usb.host_setup(0, t.setup):
                self._note("host: SETUP %s  [%s]" % (t.setup.hex(" "), t.label))
                self.state = "data" if (t.device_to_host and t.want) \
                    else "status_in"
            else:
                t.status = "no-setup"
                self._finish(t)
            return

        t = self.current
        if t is None:
            self.state = "idle"
            return

        # A STALLed control endpoint answers nothing. That is a real outcome
        # (the firmware rejected the request), not a failure of the harness.
        if usb.endpoint_stalled(0):
            t.stalled = True
            t.status = "stalled"
            usb.clear_stall(0)
            self._note("host: EP0 STALLed by the firmware  [%s]" % t.label)
            self._finish(t)
            return

        self._wait += 1
        if self._wait > self.STALL_STEPS:
            t.status = "timeout"
            self._note("host: no reply after %d steps  [%s]"
                       % (self._wait, t.label))
            self._finish(t)
            return

        if self.state == "data":
            pkt = usb.host_in(0)
            if pkt is None:
                return
            t.data += pkt
            if t.provenance is None:
                t.provenance = usb.last_in_provenance
            self._note("host: %d byte(s) IN  %s" % (len(pkt), pkt.hex(" ")))
            # Short packet or enough data ends the data stage.
            if len(pkt) < 64 or len(t.data) >= t.want:
                self.state = "status_out"
            return

        if self.state == "status_out":
            # A control transfer WITH a data stage ends with a host->device
            # zero-length OUT.
            n = usb.host_out(0, b"")
            if n is None:
                return
            t.status = "ok"
            self._finish(t)
            return

        if self.state == "status_in":
            # ...one WITHOUT a data stage ends with a device->host zero-length
            # IN. Treating one like the other deadlocks with both sides waiting.
            pkt = usb.host_in(0)
            if pkt is None:
                return
            t.status = "ok"
            self._finish(t)
            return

    def _finish(self, t: Transfer) -> None:
        self.current = None
        self.state = "idle"
        self.done.append(t)
        if t.setup[0] & 0x60 == 0x40:          # a vendor request
            self.by_request[t.setup[1]] = t
        self._decode(t)
        self._publish(t)
        if not self.enumerated and len(self.done) >= 4:
            self.enumerated = True
            self.configured = True
            self._note("host: device ENUMERATED and CONFIGURED")

    def _decode(self, t: Transfer) -> None:
        if t.label.startswith("GET_DESCRIPTOR(device)") and len(t.data) >= 12:
            vid, pid = struct.unpack_from("<HH", bytes(t.data), 8)
            self.vid_pid = (vid, pid)
            self._note("host: device descriptor -- VID:PID = %04x:%04x"
                       % (vid, pid))
        elif t.label.startswith("SET_ADDRESS") and t.status == "ok":
            self.address = DEVICE_ADDRESS

    def _note(self, line: str) -> None:
        self.log_lines.append(line)
        log.info("UsbHost: %s", line)

    # -- host-side bridge ----------------------------------------------------
    def start_bridge(self, port: int) -> None:
        """A line-oriented TCP bridge onto the USB control endpoint.

        Send ``<request> [value] [index] [length]`` (decimal or 0x-hex) and get
        back a JSON line with whatever the firmware replied. This is what makes
        the SDR attackable from outside the emulator: a request arriving here is
        delivered as a real SETUP packet into the firmware's own USB stack,
        exactly as one from libhackrf would be.
        """
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(4)
        except OSError as exc:
            log.error("UsbHost: could NOT bind tcp/%d (%s) -- nothing can be "
                      "injected this run", port, exc)
            return
        self._srv = srv
        log.info("UsbHost: USB control bridge LISTENing on tcp/%d", port)

        def accept_loop() -> None:
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                with self._lock:
                    self._clients.append(conn)
                threading.Thread(target=self._reader, args=(conn,),
                                 daemon=True).start()

        threading.Thread(target=accept_loop, daemon=True).start()

    def _reader(self, conn) -> None:
        buf = b""
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._handle_line(line.decode("ascii", "replace").strip())
        except OSError:
            pass
        finally:
            with self._lock:
                if conn in self._clients:
                    self._clients.remove(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _handle_line(self, line: str) -> None:
        if not line or line.startswith("#"):
            return
        parts = line.split()
        try:
            req = int(parts[0], 0)
            value = int(parts[1], 0) if len(parts) > 1 else 0
            index = int(parts[2], 0) if len(parts) > 2 else 0
            length = int(parts[3], 0) if len(parts) > 3 else 0x20
        except ValueError:
            return
        log.info("UsbHost: vendor request %d from the bridge "
                 "(value=0x%04x index=0x%04x length=%d)",
                 req, value, index, length)
        self.queue_vendor_in(req, value, index, length,
                             label="bridge:vendor(%d)" % req)

    def _publish(self, t: Transfer) -> None:
        import json
        line = (json.dumps(t.as_dict()) + "\n").encode("ascii")
        with self._lock:
            clients = list(self._clients)
        for c in clients:
            try:
                c.sendall(line)
            except OSError:
                pass

    # -- diagnostics ---------------------------------------------------------
    def summary(self) -> dict:
        return {
            "state": self.state,
            "steps": self.steps,
            "address": self.address,
            "configured": self.configured,
            "vid_pid": ("%04x:%04x" % self.vid_pid) if self.vid_pid else None,
            "transfers": [t.as_dict() for t in self.done[-24:]],
            "pending": len(self.queue),
        }


_HOST: Optional[UsbHost] = None


def get_host() -> UsbHost:
    global _HOST
    if _HOST is None:
        _HOST = UsbHost()
        port = os.environ.get("HAL_HRF_USB_PORT")
        if port:
            _HOST.start_bridge(int(port))
    return _HOST
