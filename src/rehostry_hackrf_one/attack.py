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

    def vendor_request(self, request: int, length: int = 0x20,
                       value: int = 0, index: int = 0) -> Optional[dict]:
        """Issue one vendor control transfer and return the firmware's answer.

        ⚠ `value` and `index` were hardcoded to 0 here, even though the bridge's
        own line protocol has always accepted them
        (`<request> [value] [index] [length]`). That made half this firmware's
        command surface undrivable from the attack: every HackRF register write
        carries its payload in wValue/wIndex and has no data stage at all, so
        with both pinned to 0 the only thing that could be exercised was the
        handful of parameterless reads.
        """
        assert self._sock is not None
        self._sock.sendall(("%d %d %d %d\n"
                            % (request, value, index, length)).encode())
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


# ---------------------------------------------------------------------------
# THE LADDER.
#
# Before 2026-09-17 `milestone` took exactly two values:
#
#     res["milestone"] = "M4" if res["usb_vendor_round_trip"] else \
#                        "unproven (no protocol round trip observed)"
#
# M0..M3 were unreachable, M6/M7 did not exist, and the negative arm was a
# PROSE STRING that no milestone parser can read -- the fleet guard turns it
# into "-" and the row scores a bare WALL with no rung at all. `STATUS.md`
# argued M1, M2 and M3 at length in English while the code could not emit any
# of them.
#
# M5/M8 are NOT in this tuple. This image's entire command surface is vendor
# control transfers on USB0 EP0 -- one endpoint, one framing layer, one peer --
# which RULES.md 1a settles as ONE interface, so M5 is undefined and the
# inventory has one entry, which 1b's boundary puts at M8-undefined.
LADDER_RUNGS = ("M0", "M1", "M2", "M3", "M4", "M6", "M7")

LADDER_FACTS = ("guest_executed", "own_init", "drives_own_interface",
                "round_trip", "m6_measured", "m6_ok", "m7_measured", "m7_ok")

#: The stateful pair, CHOSEN BY MEASUREMENT, not from memory of libhackrf.
#: The firmware's own dispatch table was swept live (requests 0..38, each
#: bracketed by a known-good canary) and three write/read pairs were tried:
#:
#:     2 MAX2837_WRITE  / 3 MAX2837_READ    -> read answers a CONSTANT 0x0150
#:     4 SI5351C_WRITE  / 5 SI5351C_READ    -> read answers 0
#:     8 RFFC5071_WRITE / 9 RFFC5071_READ   -> reads back what was written
#:
#: Only the third holds state. That the other two do NOT is what makes this
#: evidence rather than an echo: a harness or a bus model reflecting writes
#: back would have made all three pass.
REQ_RFFC5071_WRITE = 8
REQ_RFFC5071_READ = 9
#: Registers written in the simultaneity arm. An echo of "the last value
#: written" cannot hold two different values at two different indices.
M6_REGS = (0, 5, 11)


def rung_num(ms: Optional[str]) -> int:
    import re
    m = re.match(r"M(\d+)", ms or "")
    return int(m.group(1)) if m else -1


def _ladder(f: dict) -> str:
    if not f.get("guest_executed"):
        return "M0"
    if not f.get("own_init"):
        return "M1"
    if not f.get("drives_own_interface"):
        return "M2"
    if not f.get("round_trip"):
        return "M3"
    if not f.get("m6_measured") or not f.get("m6_ok"):
        return "M4"
    if not f.get("m7_measured") or not f.get("m7_ok"):
        return "M6"
    return "M7"


def _canary_ok(rh) -> bool:
    """The known-good request, used to prove the seam was healthy IMMEDIATELY
    BEFORE each probe.

    ⚠ This is not decoration on this device. A live sweep of the firmware's own
    dispatch table wedged after request 38 WITH THE GUEST STILL EXECUTING (the
    backend went on reporting exception returns inside the SPI transfer loop),
    and every request after it returned nothing. A wall of non-answers here is
    a real possibility and reads exactly like "the firmware went deaf after
    malformed input". The tell is whether the request BEFORE it answered.
    """
    got = rh.vendor_request(REQ_VERSION_STRING_READ, length=0x20)
    if not got or got.get("status") != "ok" or not got.get("data"):
        return False
    return _valid_version_string(bytes.fromhex(got["data"].replace(" ", "")))


def _rffc_write(rh, reg: int, val: int) -> None:
    """HACKRF_VENDOR_REQUEST_RFFC5071_WRITE -- an ACK-only vendor request that
    carries its payload entirely in wValue/wIndex, with NO data stage. It is
    therefore issued with wLength 0; a non-zero length leaves the host waiting
    for a data stage the firmware will never start."""
    rh.vendor_request(REQ_RFFC5071_WRITE, length=0, value=val, index=reg)


def _rffc_read(rh, reg: int) -> Optional[int]:
    got = rh.vendor_request(REQ_RFFC5071_READ, length=2, value=0, index=reg)
    if not got or got.get("status") != "ok" or not got.get("data"):
        return None
    raw = bytes.fromhex(got["data"].replace(" ", ""))
    return int.from_bytes(raw, "little") if len(raw) == 2 else None


def m6_register_rounds(rh, rounds: int, rng,
                       on_stage: Optional[Callable] = None) -> list:
    """M6 -- STATEFUL.

    One input (`RFFC5071_READ` of register r) answers differently and correctly
    for each attacker-chosen prior state. Every value is drawn at RUN TIME, so
    it is in no image, model, handler or file.

    It is a CYCLE, not a ratchet: any round can write any value to any
    register, so round r+1 starts from a state round r can reach and Rule 2's
    `passed == rounds` is satisfiable.

    The simultaneity arm is what separates state from an echo: three registers
    are loaded with three DIFFERENT values and then all three are read back. A
    model or harness reflecting "the last value written" answers all three the
    same and fails.
    """
    out = []
    no_write = os.environ.get("HAL_HRF_M6_NO_WRITE") == "1"
    for r in range(rounds):
        rec: dict = {"round": r}
        if not _canary_ok(rh):
            rec["verdict"] = "VOID-canary-before"
            out.append(rec)
            if on_stage:
                on_stage("m6_round", msg="round %d VOID: the seam was not "
                                         "healthy before the probe" % r)
            continue
        want = {reg: rng.randrange(1, 0x1000) for reg in M6_REGS}
        if not no_write:
            for reg, v in want.items():
                _rffc_write(rh, reg, v)
        got = {reg: _rffc_read(rh, reg) for reg in M6_REGS}
        rec["wrote"] = want
        rec["read"] = got
        rec["all_match"] = all(got[reg] == want[reg] for reg in M6_REGS)
        rec["distinct"] = len({v for v in got.values() if v is not None}) == \
            len(M6_REGS)
        rec["passed"] = bool(rec["all_match"] and rec["distinct"])
        rec["verdict"] = "OK" if rec["passed"] else "MISMATCH"
        out.append(rec)
        if on_stage:
            on_stage("m6_round", msg="round %d wrote %s read %s passed=%s"
                     % (r, want, got, rec["passed"]))
    return out


def m7_classes() -> list:
    """M7 classes.

    Deliberately confined to requests <= 33. The live sweep showed the seam
    stops answering after request 38 while the guest keeps executing, and an
    unexplored region is not a tolerance claim -- it is unfinished work, and it
    is reported as such rather than folded in as a class that "failed".
    """
    return [
        ("H1-null-dispatch-slot-13", dict(request=13, length=0x20),
         "the firmware's own dispatch table has NULL here", "stall"),
        ("H2-null-dispatch-slot-0", dict(request=0, length=0x20),
         "request 0 is not a vendor request this firmware implements", "stall"),
        ("H3-null-dispatch-slot-25", dict(request=25, length=0x20),
         "another NULL slot found by sweeping the table", "stall"),
        ("H4-read-register-out-of-range",
         dict(request=REQ_RFFC5071_READ, length=2, value=0, index=0x00FF),
         "RFFC5071_READ for a register index past the device's file", "any"),
        ("H5-write-value-saturated",
         dict(request=REQ_RFFC5071_WRITE, length=0, value=0xFFFF, index=0x00FF),
         "every payload bit set, on an out-of-range register", "any"),
        ("H6-huge-wlength",
         dict(request=REQ_VERSION_STRING_READ, length=0xFFFF),
         "a supported read asked for 65535 bytes -- far past what the "
         "firmware has to give", "any"),
    ]


def m7_tolerance(rh, on_stage: Optional[Callable] = None) -> list:
    """⚠ Pre-probe AND post-probe, and the pre-probe decides.

    A `wLength` far past the firmware's data stage is exactly the shape that
    has wedged a HOST USB model on this fleet before, producing a wall of
    timeouts indistinguishable from a firmware that went deaf. H6 is therefore
    LAST, so the classes before it are already recorded if it takes the seam
    down, and its own verdict is gated on the pre-probe like every other.
    """
    out = []
    for name, kw, why, expect in m7_classes():
        rec: dict = {"class": name, "why": why, "expect": expect,
                     "request": kw["request"], "wlength": kw["length"]}
        rec["pre_ok"] = _canary_ok(rh)
        if not rec["pre_ok"]:
            rec["verdict"] = "VOID-pre-probe-failed"
            out.append(rec)
            if on_stage:
                on_stage("m7_class", msg="%s VOID: the seam was not healthy "
                                         "BEFORE the malformed input, so this "
                                         "is not a finding" % name)
            continue
        got = rh.vendor_request(**kw)
        rec["stalled"] = bool((got or {}).get("stalled"))
        rec["status"] = (got or {}).get("status")
        rec["data_len"] = len(bytes.fromhex(
            (got or {}).get("data", "").replace(" ", ""))) if got and \
            got.get("data") else 0
        # The firmware's OWN refusal, where one is demanded: usb_endpoint_stall()
        # writes ENDPTCTRL0 = RXS|TXS. Read from the emulator log, not from the
        # host state machine's opinion.
        rec["handled"] = (rec["stalled"] if expect == "stall" else True)
        rec["post_ok"] = _canary_ok(rh)
        rec["verdict"] = ("TOLERATED" if (rec["handled"] and rec["post_ok"])
                          else "SEAM-DEAF-AFTER" if rec["handled"]
                          else "NOT-REFUSED")
        out.append(rec)
        if on_stage:
            on_stage("m7_class", msg="%s pre=%s stalled=%s post=%s -> %s"
                     % (name, rec["pre_ok"], rec["stalled"], rec["post_ok"],
                        rec["verdict"]))
    return out


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
        # ⚠ `milestone` used to be seeded absent and then set to one of exactly
        # two values, the negative one being the PROSE STRING "unproven (no
        # protocol round trip observed)". No milestone parser can read that:
        # the fleet guard turns it into "-" and the row scores a bare WALL with
        # no rung. M0 is the rung a run that produced nothing has earned.
        "milestone": "M0",
    }
    facts: dict = {k: False for k in LADDER_FACTS}
    res["facts"] = facts
    rh = _Rehost(log_dir)
    res["log"] = rh.log
    try:
        stage("boot", msg="booting the LPC4320 rehost")
        rh.start()

        enum_ok = rh.wait_enumerated(BOOT_TIMEOUT)

        # ---- M1/M2/M3 facts, measured on EVERY path ------------------------
        # ⚠ These used to be measured only AFTER the enumeration gate, so a run
        # that booted, executed, bit-banged 98 rows of CPLD configuration and
        # then stopped because its own verify refused reported
        # `guest_executed: false` and printed M0 -- the SAME rung as a run with
        # no firmware on disk at all. That is a downward false floor, and it
        # lands on exactly the arm whose whole purpose is to show the low rungs
        # are reachable with the guest running.
        text = rh.log_text()
        for line in text.splitlines():
            if "VID:PID = " in line:
                res["vid_pid"] = line.split("VID:PID = ")[1].strip()
        # guest_executed: the backend reports the guest taking and returning
        # from its own interrupts, and the firmware's own JTAG bit-bang reached
        # the CPLD model. A count, not a boolean, so a witness pinned at zero on
        # a live device is visible rather than silent.
        res["irq_events"] = text.count("inject_irq(")
        res["cpld_rows"] = text.count("CPLD SRAM row")
        facts["guest_executed"] = bool(res["irq_events"] > 0
                                       or res["cpld_rows"] > 0)
        # own_init: the firmware programmed its OWN USB device controller --
        # it published its queue-head array in ENDPOINTLISTADDR and set
        # USBCMD.RS. Both are register writes the GUEST made; the model only
        # reports them.
        facts["own_init"] = ("ENDPOINTLISTADDR" in text and "USBCMD" in text)
        # drives_own_interface: the firmware composed and transmitted its own
        # DEVICE descriptor -- the VID:PID above is parsed out of the bytes the
        # guest put on EP0, not out of any constant in this package.
        facts["drives_own_interface"] = bool(res["vid_pid"])

        if not enum_ok:
            res["error"] = ("the firmware did not complete USB enumeration "
                            "within %.0fs" % BOOT_TIMEOUT)
            res["milestone"] = _ladder(facts)
            res["landed"] = rung_num(res["milestone"]) >= 4
            stage("boot_failed", msg=res["error"], milestone=res["milestone"],
                  irq_events=res["irq_events"], cpld_rows=res["cpld_rows"])
            return res
        res["booted"] = True
        res["enumerated"] = True
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
        facts["round_trip"] = bool(
            res["usb_vendor_round_trip"]
            and neg["stalled"] and neg["no_data"]
            and neg["endptctrl0_stall_logged"])

        # ---- M6 / M7 ------------------------------------------------------
        import random
        seed = int(time.time() * 1000) & 0xFFFF
        res["seed"] = seed
        rng = random.Random(seed)
        if facts["round_trip"]:
            rounds = int(os.environ.get("HAL_HRF_M6_ROUNDS", "5"))
            m6 = m6_register_rounds(rh, rounds, rng, on_stage=stage)
            res["m6"] = m6
            res["m6_rounds"] = len(m6)
            res["m6_passed"] = sum(1 for r in m6 if r.get("passed"))
            res["m6_void"] = sum(1 for r in m6
                                 if str(r.get("verdict", "")).startswith("VOID"))
            facts["m6_measured"] = bool(m6) and res["m6_void"] == 0
            # Rule 2: N of N. Never `>= 1`.
            facts["m6_ok"] = bool(facts["m6_measured"]
                                  and res["m6_passed"] == len(m6))

            m7 = m7_tolerance(rh, on_stage=stage)
            res["m7"] = m7
            res["m7_total"] = len(m7)
            res["m7_void"] = sum(1 for c in m7
                                 if c["verdict"].startswith("VOID"))
            res["m7_tolerated"] = sum(1 for c in m7
                                      if c["verdict"] == "TOLERATED")
            facts["m7_measured"] = bool(m7) and res["m7_void"] == 0
            facts["m7_ok"] = bool(facts["m7_measured"]
                                  and res["m7_total"] >= 3
                                  and res["m7_tolerated"] == len(m7))

        res["milestone"] = _ladder(facts)
        # `landed` is M4 and only M4 (RULES.md 5).
        res["landed"] = rung_num(res["milestone"]) >= 4
        stage("verdict", landed=res["landed"], milestone=res["milestone"])
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
                                          "usb_vendor_round_trip", "facts",
                                          "seed", "irq_events", "cpld_rows",
                                          "vid_pid",
                                          "m6_passed", "m6_rounds", "m6_void",
                                          "m7_tolerated", "m7_total",
                                          "m7_void")}))
    return 0 if res.get("landed") else 1


if __name__ == "__main__":
    sys.exit(main())
