# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M8 interface parity for `device-hackrf-one`.

RULES.md §0 M8: *every entry in an independently derived inventory passes M4.*
§1a's 2026-09-29 ruling settles what an entry is: **a declared capability on a
seam the firmware exposes**, not a §1a-independent interface. So this image's
USB vendor requests are entries, exactly as `vesc-bms` grades 16 COMM packets
over one CAN link.

THE DENOMINATOR (`inventory.py`) is the image's own 59-slot dispatch array, its
extent taken from the dispatcher's own `cmp #0x3a` bound and its membership
from which slots are non-NULL. It is re-parsed **out of guest memory on every
run** and cross-checked against a pre-registered token set; a mismatch either
way VOIDS parity rather than lowering it.

THE NUMERATOR is per entry, `passed == rounds` (Rule 2 -- never `>= 1`).

THE AGREEMENT CONTROL counts REPLIES, not shapes: every one of the 10 NULL
slots, plus two out-of-range requests, is swept in the same run and must be
refused by the firmware's own `usb_endpoint_stall()`. If the static table says
a slot dispatches and the live sweep refuses it, that entry **FAILS** -- it is
never removed from the denominator (RULES.md §1a: raising parity by shrinking
the denominator is the cardinal sin).

⚠ SILENCE BOUNDS ARE DERIVED PER RUN, from that run's own worst known-good
canary latency, and are NOT device constants. A sibling lane turned five good
answers into five false failures with a fixed budget that expired ~6 s after
the last reception while the answer was still 6 600 log lines away.
"""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import time
from typing import Dict, List, Optional

from . import inventory, spawn
from .attack import BOOT_TIMEOUT, _Rehost, rung_num

#: A known-good, parameterless read used as the canary: table slot 14,
#: `read_board_id`, one byte the firmware composes itself.
REQ_CANARY = 14

#: Requests outside the dispatcher's own bound. `cmp #0x3a` admits 0..58, so
#: these can only ever be refused, whatever the array holds.
OUT_OF_RANGE = (59, 255)

LADDER_RUNGS = ("M0", "M1", "M2", "M3", "M4", "M8")

#: Facts the rung is a function of. Named so `enumerate_ladder.py` can
#: quantify over them -- and see the module docstring of `check3.py` for why
#: that enumeration is necessary and NOT sufficient.
LADDER_FACTS = ("guest_executed", "own_init", "drives_own_interface",
                "round_trip", "inventory_parsed", "guard_ok",
                "agreement_ok", "parity_full")


def _ladder(f: dict) -> str:
    """The rung, as a pure function of the facts above.

    M8 is claimed ONLY on strict parity with a guard that passed and a live
    agreement control that agreed. Anything less prints M4 and the fraction is
    reported separately as DEFINED-and-UNMET.
    """
    if not f.get("guest_executed"):
        return "M0"
    if not f.get("own_init"):
        return "M1"
    if not f.get("drives_own_interface"):
        return "M2"
    if not f.get("round_trip"):
        return "M3"
    if not (f.get("inventory_parsed") and f.get("guard_ok")
            and f.get("agreement_ok") and f.get("parity_full")):
        return "M4"
    return "M8"


def _uptime() -> str:
    try:
        return subprocess.run(["uptime"], capture_output=True, text=True,
                              timeout=10).stdout.strip()
    except Exception:  # noqa: BLE001
        return "(uptime unavailable)"


def _calibrate(rh, samples: int = 5) -> Dict:
    """This run's own worst known-good latency, measured live.

    Returns the observed canary latencies and the silence bound derived from
    them. The bound is `max(observed) * 4 + 5`, floored at 15 s: a per-run
    quantity, stated as such, never a device constant.
    """
    lat: List[float] = []
    for _ in range(samples):
        t0 = time.time()
        got = rh.vendor_request(REQ_CANARY, length=1)
        dt = time.time() - t0
        if got is not None and not got.get("stalled"):
            lat.append(dt)
    worst = max(lat) if lat else 0.0
    return {"canary_latencies_s": [round(x, 3) for x in lat],
            "canary_worst_s": round(worst, 3),
            "silence_bound_s": round(max(15.0, worst * 4 + 5), 3),
            "note": "derived from THIS run's worst known-good canary latency; "
                    "not a device constant"}


def _entry_round(rh, req: int, rng: random.Random, nonce: int) -> Dict:
    """One round for one entry.

    `wValue` and `wIndex` carry a per-run nonce so a reply cannot be a replay
    of a previous run, and `wLength` is small: this is a dispatch-coverage
    round trip, not a semantic exercise of every handler.
    """
    value = (nonce ^ (req * 0x0101)) & 0xFFFF
    index = (nonce >> 16) & 0xFFFF
    got = rh.vendor_request(req, length=2, value=value, index=index)
    rec = {"request": req, "wValue": value, "wIndex": index}
    if got is None:
        rec.update({"reply": None, "ok": False, "why": "no reply within the "
                    "run's own silence bound"})
        return rec
    rec["stalled"] = bool(got.get("stalled"))
    rec["status"] = got.get("status")
    rec["data"] = got.get("data")
    rec["provenance"] = got.get("provenance")
    # M4 for this entry: the firmware routed the request through its own
    # dispatcher and completed the control transfer. `status == "ok"` is the
    # host seeing the firmware drive the status stage from a dTD the FIRMWARE
    # programmed (`provenance`), not our bookkeeping.
    rec["ok"] = (not rec["stalled"]) and rec["status"] == "ok"
    if not rec["ok"] and "why" not in rec:
        rec["why"] = ("refused by the firmware's own dispatcher/handler"
                      if rec["stalled"] else "status=%r" % rec["status"])
    return rec


def run_parity(rounds: int = 3, control: Optional[str] = None,
               seed: Optional[int] = None) -> Dict:
    """Boot, read the inventory out of the guest, and grade every entry."""
    # ⚠ A DISTINCT PER-ROW SEED. A sibling lane latched identical registers on
    # two rows from one shared seed and had to discard the pair as a single
    # observation. This row's default seed is derived from its own package
    # name, so no other row in this batch can collide with it.
    if seed is None:
        seed = int(os.environ.get("HAL_HRF_PARITY_SEED",
                                  str(abs(hash("rehostry_hackrf_one")) % 10 ** 9)))
    rng = random.Random(seed)
    nonce = rng.getrandbits(32)

    res: Dict = {
        "booted": False, "landed": False, "milestone": None,
        "control": control, "seed": seed, "nonce": "0x%08x" % nonce,
        "rounds_requested": rounds,
        "uptime_before": _uptime(), "uptime_after": None,
        "inventory": None, "guard": None, "calibration": None,
        "entries": {}, "agreement": None,
        "inventory_size": None, "passed": None,
        "parity": None, "parity_void": None,
        "error": None,
    }
    env_extra: Dict[str, str] = {}
    if control == "guard-offset":
        env_extra["HAL_HRF_INV_OFFSET"] = "4"
    elif control == "bound-patch-0":
        env_extra["HAL_HRF_BOUND_PATCH"] = "0"

    log_dir = os.path.join(
        os.environ.get("HAL_HRF_LOG_ROOT", "/tmp"),
        "hackrf-parity-%d-%s" % (os.getpid(), control or "default"))
    rh = _Rehost(log_dir=log_dir)
    for k, v in env_extra.items():
        os.environ[k] = v
    try:
        rh.start()
        res["log"] = rh.log
        res["emulator_pid"] = rh.proc.pid if rh.proc else None
        enum_ok = rh.wait_enumerated(BOOT_TIMEOUT)
        text = rh.log_text()
        res["booted"] = ("UC_ERR" not in text and "Traceback" not in text
                         and "BootInit: backend published" in text)
        facts = {
            "guest_executed": "BootInit: backend published" in text,
            "own_init": "ENDPTLISTADDR" in text or "USBCMD" in text,
            "drives_own_interface": enum_ok,
        }

        inv = inventory.parse_log_line(text)
        res["inventory"] = inv
        facts["inventory_parsed"] = inv is not None
        if inv is None:
            res["error"] = "no %s line in the guest's own log" % inventory.LOG_TAG
            res["milestone"] = _ladder(facts)
            res["landed"] = rung_num(res["milestone"]) >= 4
            return res
        guard = inventory.check_guard(inv)
        res["guard"] = guard
        facts["guard_ok"] = guard["ok"]
        res["inventory_size"] = inv["implemented"]

        if not enum_ok:
            res["error"] = "the firmware did not enumerate within %.0fs" % BOOT_TIMEOUT
            res["milestone"] = _ladder(facts)
            res["landed"] = rung_num(res["milestone"]) >= 4
            return res
        if not rh.connect():
            res["error"] = "could not reach the USB control bridge on tcp/%d" \
                % spawn.BRIDGE_PORT
            res["milestone"] = _ladder(facts)
            res["landed"] = rung_num(res["milestone"]) >= 4
            return res

        res["calibration"] = _calibrate(rh)

        # --- the entries -----------------------------------------------------
        entries: Dict[str, Dict] = {}
        for req in inv["implemented_indices"]:
            recs = [_entry_round(rh, req, rng, nonce) for _ in range(rounds)]
            npass = sum(1 for r in recs if r["ok"])
            entries[str(req)] = {
                "request": req, "rounds": rounds, "passed": npass,
                # Rule 2, per ENTRY: N of N, never >= 1.
                "ok": npass == rounds and rounds > 0,
                "observations": recs,
            }
        res["entries"] = entries
        passed = [int(k) for k, v in entries.items() if v["ok"]]
        res["passed"] = sorted(passed)
        facts["round_trip"] = len(passed) > 0

        # --- the agreement control: REPLIES, not shapes ----------------------
        agree = {"null_slots": {}, "out_of_range": {}, "ok": None,
                 "refusals_counted": 0, "expected_refusals": 0}
        for req in list(inv["null_indices"]) + list(OUT_OF_RANGE):
            got = rh.vendor_request(req, length=2, value=nonce & 0xFFFF)
            refused = bool(got is not None and got.get("stalled"))
            bucket = ("out_of_range" if req in OUT_OF_RANGE else "null_slots")
            agree[bucket][str(req)] = {"stalled": refused,
                                       "reply": got}
            agree["expected_refusals"] += 1
            if refused:
                agree["refusals_counted"] += 1
        agree["ok"] = (agree["refusals_counted"] == agree["expected_refusals"]
                       and agree["expected_refusals"] > 1)
        # The firmware's OWN refusal write, not our classification of silence.
        agree["endptctrl0_stall_logged"] = \
            "ENDPTCTRL0 STALL set by the firmware (0x00010001)" in rh.log_text()
        res["agreement"] = agree
        facts["agreement_ok"] = bool(agree["ok"]
                                     and agree["endptctrl0_stall_logged"])

        # --- parity ----------------------------------------------------------
        n = res["inventory_size"]
        res["parity"] = "%d/%d" % (len(passed), n)
        res["parity_void"] = not guard["ok"]
        # Strict: len(passed) == inventory_size. Never a threshold.
        facts["parity_full"] = (guard["ok"] and len(passed) == n and n > 1)
        res["facts"] = facts
        res["milestone"] = _ladder(facts)
        res["landed"] = rung_num(res["milestone"]) >= 4
        return res
    finally:
        rh.stop()
        res["uptime_after"] = _uptime()
        for k in env_extra:
            os.environ.pop(k, None)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="rehostry-hackrf-one-parity")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--control", choices=("guard-offset", "bound-patch-0"),
                    default=None)
    ap.add_argument("--json-out", default=None)
    a = ap.parse_args(argv)
    res = run_parity(rounds=a.rounds, control=a.control, seed=a.seed)
    if a.json_out:
        with open(a.json_out, "w") as fh:
            json.dump(res, fh, indent=1, sort_keys=True)
    slim = {k: res[k] for k in
            ("booted", "landed", "milestone", "control", "seed",
             "inventory_size", "parity", "parity_void", "error")
            if k in res}
    slim["passed_n"] = len(res.get("passed") or [])
    slim["guard_ok"] = (res.get("guard") or {}).get("ok")
    slim["agreement_ok"] = (res.get("agreement") or {}).get("ok")
    print("RESULT:", json.dumps(slim, sort_keys=True))
    print("log          :", res.get("log"))
    print("uptime before:", res.get("uptime_before"))
    print("uptime after :", res.get("uptime_after"))
    print("calibration  :", json.dumps(res.get("calibration")))
    if res.get("passed") is not None:
        failed = sorted(set((res.get("inventory") or {}).get(
            "implemented_indices", [])) - set(res["passed"]))
        print("failed       :", failed)
    return 0 if res.get("landed") else 1


if __name__ == "__main__":
    sys.exit(main())
