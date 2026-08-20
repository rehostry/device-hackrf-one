# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The attack: an unauthenticated USB vendor control transfer to a HackRF One.

WHAT THE VULNERABILITY IS. A HackRF One's entire command surface is
vendor-specific USB control transfers, and **none of them is authenticated**.
There is no pairing, no PIN, no session, no host allow-list -- the firmware's
``usb_vendor_request()`` looks the request byte up in a flat table and calls the
handler. Anything that can open the USB device can read its identity, retune it
across 1 MHz-6 GHz, change its sample rate and gain, drive its antenna bias tee,
put it into transmit, and (requests 10/11) **erase and rewrite the SPI flash the
firmware itself boots from**. On a shared or multi-tenant host -- a lab machine,
a CI runner, a container with the device passed through -- that is a full
takeover of the radio by any process that can reach the bus.

This attack demonstrates the reachability of that surface end to end, with an
oracle that cannot be faked by the harness.

THE ORACLE IS THE FIRMWARE'S OWN BYTES. The host writes exactly eight bytes: a
SETUP packet. The firmware then:

  1. copies its own ``firmware_info.version_string`` into its endpoint buffer,
  2. builds a transfer descriptor pointing at that buffer with the length its
     own ``strlen()`` computed, and
  3. primes EP0 IN.

The model reads the reply out of guest RAM **at the address the firmware put in
``dTD.buffer_pointer_page[0]``, for the length the firmware put in
``dTD.total_bytes``** -- both reported in the result as ``provenance``. Nothing
in this device contains a copy of the expected release string, and
``tests/test_structure.py`` asserts that: the oracle here is a SHAPE check
(:func:`_valid_version_string`), with the exact bytes predicted in
``PROVENANCE.md`` §2.2 ahead of the first boot and printed by ``main()`` for a
human to compare. An equality test against a hardcoded constant would be
satisfiable by an echo; this is not.

THE NEGATIVE CONTROL runs the identical harness with request **13**, whose slot
in the firmware's dispatch table is ``NULL`` ("used to be write_cpld"). The
firmware must reject it: ``usb_vendor_request()`` returns
``USB_REQUEST_STATUS_STALL`` and ``usb_endpoint_stall()`` writes
``ENDPTCTRL0 = RXS|TXS``. So the run asserts both that the supported request
answers *and* that the unsupported one is refused **by the firmware writing a
stall bit**. If the reply were an artifact of this harness, request 13 would
produce one too. ``landed`` requires both halves.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from typing import Callable, Optional

from . import spawn

#: HACKRF_VENDOR_REQUEST_VERSION_STRING_READ -- the firmware formats the reply
#: itself out of a struct in its own image.
REQ_VERSION_STRING_READ = 15
#: HACKRF_VENDOR_REQUEST_BOARD_ID_READ -- derived at boot from strap resistors.
REQ_BOARD_ID_READ = 14
#: HACKRF_VENDOR_REQUEST_SUPPORTED_PLATFORM_READ.
REQ_SUPPORTED_PLATFORM_READ = 46
#: NEGATIVE CONTROL: table slot 13 is NULL, so the firmware must STALL.
REQ_UNSUPPORTED = 13

#: BOARD_ID_HACKRF1_OG. Derived by the firmware from the modelled strap levels;
#: see PROVENANCE.md prediction B.
EXPECT_BOARD_ID = 0x02

BOOT_TIMEOUT = float(os.environ.get("HAL_HRF_BOOT_TIMEOUT", "240"))
REPLY_TIMEOUT = float(os.environ.get("HAL_HRF_REPLY_TIMEOUT", "180"))


def _noop(_name: str, **_data) -> None:
    pass


def _valid_version_string(raw: bytes) -> bool:
    """Is this a plausible HackRF release string, formatted by the firmware?

    Deliberately a SHAPE test, not an equality test against a constant: this
    module must not contain a copy of the expected reply, or the oracle could
    be satisfied by an echo. The exact bytes are predicted in PROVENANCE.md and
    printed in the result for a human to compare.
    """
    if not 5 <= len(raw) <= 31:
        return False
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    if not all(c.isalnum() or c in "._-+" for c in text):
        return False
    # A release is <year>.<month>.<patch>; a git build is "git-<hash>".
    return text.count(".") >= 2 or text.startswith("git-")


class _Rehost:
    """Boots the device and talks to its USB control bridge."""

    def __init__(self, log_dir: Optional[str] = None) -> None:
        self.log_dir = log_dir or tempfile.mkdtemp(prefix="hackrf-one-attack-")
        os.makedirs(self.log_dir, exist_ok=True)
        self.log = os.path.join(self.log_dir, "hackrf_one_attack.log")
        self.proc: Optional[subprocess.Popen] = None
        self._fh = None
        self._sock: Optional[socket.socket] = None
        self._buf = b""

    def start(self) -> None:
        self._fh = open(self.log, "w")
        self.proc = subprocess.Popen(
            spawn.spawn_argv(), cwd=spawn.spawn_cwd(), env=spawn.spawn_env(),
            stdout=self._fh, stderr=subprocess.STDOUT)

    def stop(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        # Kill ONLY the pid we started (playbook trap 2.10: a global pattern
        # kill takes out other sessions' emulators and the victim cannot tell
        # the difference from a clean timeout).
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except Exception:  # noqa: BLE001
                self.proc.kill()
        if self._fh is not None:
            self._fh.close()

    def log_text(self) -> str:
        try:
            with open(self.log) as fh:
                return fh.read()
        except OSError:
            return ""

    def wait_enumerated(self, timeout: float) -> bool:
        """Wait for the FIRMWARE to complete its own USB enumeration."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(2)
            if self.proc is not None and self.proc.poll() is not None:
                return False
            if "ENUMERATED and CONFIGURED" in self.log_text():
                return True
        return False

    def connect(self) -> bool:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                self._sock = socket.create_connection(
                    ("127.0.0.1", spawn.BRIDGE_PORT), timeout=10)
                self._sock.settimeout(REPLY_TIMEOUT)
                return True
            except OSError:
                time.sleep(1)
        return False

    def vendor_request(self, request: int, length: int = 0x20) -> Optional[dict]:
        """Issue one vendor control transfer and return the firmware's answer."""
        assert self._sock is not None
        self._sock.sendall(("%d 0 0 %d\n" % (request, length)).encode())
        deadline = time.time() + REPLY_TIMEOUT
        while b"\n" not in self._buf and time.time() < deadline:
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            self._buf += chunk
        if b"\n" not in self._buf:
            return None
        line, self._buf = self._buf.split(b"\n", 1)
        try:
            return json.loads(line)
        except ValueError:
            return None


def run_attack(on_stage: Optional[Callable] = None,
               log_dir: Optional[str] = None) -> dict:
    """Boot the HackRF One rehost and drive unauthenticated vendor requests.

    Returns a dict with at least ``booted`` and ``landed``. ``landed`` is true
    only when the firmware answered a supported vendor request with bytes it
    formatted itself **and** refused the unsupported one by writing a stall bit.
    """
    stage = on_stage or _noop
    res: dict = {
        "booted": False,
        "landed": False,
        "enumerated": False,
        "vid_pid": None,
        "version_string": None,
        "version_bytes": None,
        "board_id": None,
        "supported_platform": None,
        "provenance": None,
        "negative_control": None,
        "log": None,
    }
    rh = _Rehost(log_dir)
    res["log"] = rh.log
    try:
        stage("boot", msg="booting the LPC4320 rehost")
        rh.start()

        if not rh.wait_enumerated(BOOT_TIMEOUT):
            res["error"] = ("the firmware did not complete USB enumeration "
                            "within %.0fs" % BOOT_TIMEOUT)
            stage("boot_failed", msg=res["error"])
            return res
        res["booted"] = True
        res["enumerated"] = True

        text = rh.log_text()
        for line in text.splitlines():
            if "VID:PID = " in line:
                res["vid_pid"] = line.split("VID:PID = ")[1].strip()
        stage("enumerated", vid_pid=res["vid_pid"])

        if not rh.connect():
            res["error"] = "could not reach the USB control bridge on tcp/%d" \
                % spawn.BRIDGE_PORT
            return res

        # --- the attack ---------------------------------------------------
        stage("attack", request=REQ_VERSION_STRING_READ,
              msg="unauthenticated vendor request VERSION_STRING_READ")
        got = rh.vendor_request(REQ_VERSION_STRING_READ)
        version_ok = False
        if got and got.get("status") == "ok" and got.get("data"):
            raw = bytes.fromhex(got["data"].replace(" ", ""))
            res["version_bytes"] = got["data"]
            res["provenance"] = got.get("provenance")
            version_ok = _valid_version_string(raw)
            if version_ok:
                res["version_string"] = raw.decode("ascii")
            stage("reply", request=REQ_VERSION_STRING_READ,
                  data=got["data"], text=res["version_string"])

        got = rh.vendor_request(REQ_BOARD_ID_READ, length=1)
        board_ok = False
        if got and got.get("status") == "ok" and got.get("data"):
            raw = bytes.fromhex(got["data"].replace(" ", ""))
            if len(raw) == 1:
                res["board_id"] = raw[0]
                board_ok = raw[0] == EXPECT_BOARD_ID
            stage("reply", request=REQ_BOARD_ID_READ, data=got["data"])

        got = rh.vendor_request(REQ_SUPPORTED_PLATFORM_READ, length=4)
        if got and got.get("status") == "ok" and got.get("data"):
            raw = bytes.fromhex(got["data"].replace(" ", ""))
            res["supported_platform"] = int.from_bytes(raw, "big") \
                if len(raw) == 4 else None
            stage("reply", request=REQ_SUPPORTED_PLATFORM_READ,
                  data=got["data"])

        # --- the negative control ------------------------------------------
        stage("negative_control", request=REQ_UNSUPPORTED,
              msg="the same harness, a request the firmware must reject")
        got = rh.vendor_request(REQ_UNSUPPORTED)
        neg = {"request": REQ_UNSUPPORTED, "stalled": False, "data": None}
        if got:
            neg["stalled"] = bool(got.get("stalled"))
            neg["data"] = got.get("data")
        # The firmware's OWN write: usb_endpoint_stall() sets ENDPTCTRL0
        # RXS|TXS = 0x00010001. Read it back out of the emulator log rather
        # than trusting the host state machine's view.
        neg["endptctrl0_stall_logged"] = \
            "ENDPTCTRL0 STALL set by the firmware (0x00010001)" in rh.log_text()
        neg["no_data"] = not neg["data"]
        res["negative_control"] = neg
        stage("negative_control_result", **neg)

        # THE M4 SEAM, named so the census can read it, and stated as what this
        # code verifies rather than as the STATUS.md claim: an unauthenticated
        # USB vendor control transfer goes IN on EP0 and the firmware's OWN
        # data stage comes back OUT -- a version string it formatted itself and
        # a board id byte matching the LPC4320 part -- while the unsupported
        # request is refused by the firmware's own write of ENDPTCTRL0
        # RXS|TXS, read back out of the emulator log rather than from the host
        # state machine.
        res["usb_vendor_round_trip"] = bool(version_ok and board_ok)
        res["milestone"] = ("M4" if res["usb_vendor_round_trip"]
                            else "unproven (no protocol round trip observed)")
        res["landed"] = bool(
            res["usb_vendor_round_trip"]
            and version_ok and board_ok
            and neg["stalled"] and neg["no_data"]
            and neg["endptctrl0_stall_logged"])
        stage("verdict", landed=res["landed"])
        return res
    finally:
        rh.stop()


def main() -> int:
    def show(name: str, **data) -> None:
        bits = " ".join("%s=%s" % (k, v) for k, v in data.items() if v is not None)
        print("[%s] %s" % (name, bits))

    res = run_attack(on_stage=show)
    print("version_string :", res.get("version_string"))
    print("version_bytes  :", res.get("version_bytes"))
    print("board_id       :", res.get("board_id"))
    print("provenance     :", json.dumps(res.get("provenance")))
    print("neg control    :", json.dumps(res.get("negative_control")))
    print("RESULT:", json.dumps({k: v for k, v in res.items()
                                 if k in ("booted", "landed", "milestone",
                                          "usb_vendor_round_trip")}))
    return 0 if res.get("landed") else 1


if __name__ == "__main__":
    sys.exit(main())
