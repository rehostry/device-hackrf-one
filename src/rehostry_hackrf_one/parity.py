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

#: Filled from the run's own guest-memory parse before the agreement control
#: is used. Module-level only so the helper does not have to be threaded a
#: second argument; it is never a default and never a written-down list.
_INV_NULLS: List[int] = []

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


#: Parameters used for the graded rounds.
#:
#: ⚠ THIS WAS WRONG THE FIRST TIME AND THE FIRST RUN SHOWED IT. The graded
#: rounds originally carried a per-run nonce in `wValue`/`wIndex`. Measured
#: live on 2026-09-29 (`hackrf-explore-r1`), that made the firmware's own
#: handlers refuse nine of the first twelve entries -- `write_max2837(reg=
#: garbage)`, `read_si5351c(reg=garbage)` and so on -- because a random
#: register address is an INVALID register address. Those STALLs were correct
#: firmware behaviour and a defect in the probe: a parameter sweep is a
#: SEMANTIC exercise of 49 handlers, and this run grades DISPATCH COVERAGE.
#:
#: So the graded rounds use `wValue = wIndex = 0`, which every handler accepts
#: as a legal register/mode/gain, and the nonce moves to where it belongs --
#: the separately-measured RFFC5071 write/read pair, which is where STATUS.md
#: already shows this firmware holding attacker-chosen state.
#:
#: The nonce arm is KEPT, as a negative control: "plausible but wrong
#: parameters" must be refused by the firmware's own checker, and it was.
GRADED_VALUE = 0
GRADED_INDEX = 0
GRADED_LENGTH = 0x20



def _agreement(rh) -> Dict:
    """Every NULL slot plus two out-of-range requests must be REFUSED.

    ⚠ THIS CONTROL WAS WRONG AND THE RUN SHOWED IT. It read
    `refused = got is not None and got["stalled"]`, so a probe that got **no
    reply** counted as "not refused" and the control reported disagreement. In
    the 2026-09-29 nonce-parameter arm that is exactly what happened: all 12
    probes ran after 49 entries, by which time the seam had gone deaf, and the
    control reported 0 of 12 refusals on a firmware that had in fact written its
    own `ENDPTCTRL0` stall bit earlier in the same run. **A run budget was
    classifying.**

    So each probe is now one of three things, and silence is not refusal:

    * `REFUSED`    -- the firmware STALLed EP0. What a NULL or out-of-range
                      request must do.
    * `ANSWERED`   -- the transfer completed. This would be a real disagreement
                      with the static table and would mean an entry is wrong.
    * `UNMEASURED` -- no reply. The seam was not proven healthy, so this probe
                      says NOTHING either way and the control VOIDS.
    """
    agree: Dict = {"null_slots": {}, "out_of_range": {},
                   "refused": 0, "answered": 0, "unmeasured": 0,
                   "expected": 0, "ok": None, "void": None}
    for req in list(_INV_NULLS) + list(OUT_OF_RANGE):
        got = rh.vendor_request(req, length=GRADED_LENGTH,
                               value=GRADED_VALUE, index=GRADED_INDEX)
        if got is None or got.get("status") == "timeout":
            verdict = "UNMEASURED"
        elif got.get("stalled"):
            verdict = "REFUSED"
        elif got.get("status") == "ok":
            verdict = "ANSWERED"
        else:
            verdict = "UNMEASURED"
        bucket = "out_of_range" if req in OUT_OF_RANGE else "null_slots"
        agree[bucket][str(req)] = {"verdict": verdict, "reply": got}
        agree["expected"] += 1
        agree[verdict.lower()] = agree.get(verdict.lower(), 0) + 1
    agree["void"] = agree["unmeasured"] > 0
    agree["ok"] = (not agree["void"] and agree["refused"] == agree["expected"]
                   and agree["expected"] > 1)
    # The firmware's OWN refusal write, never our classification of silence.
    agree["endptctrl0_stall_logged"] = \
        "ENDPTCTRL0 STALL set by the firmware (0x00010001)" in rh.log_text()
    return agree


def _entry_round(rh, req: int, round_ix: int) -> Dict:
    """One round for one entry, and the class of evidence it produced.

    * `DRIVEN`  -- the transfer completed AND carried data out of a transfer
                   descriptor the FIRMWARE programmed (`provenance`). The bytes
                   are the firmware's own; nothing here supplied them.
    * `ROUTED`  -- the transfer completed with NO data stage. The dispatcher
                   accepted the request and the firmware drove the status
                   stage, but there is no value to inspect. This is the state
                   `vesc-bms` records as "DECLARED ANSWERED but NOT DRIVEN",
                   and it does NOT pass.
    * `REFUSED` -- the firmware STALLed EP0 with its own `usb_endpoint_stall()`.
    * `OUT_STAGE` -- no reply: the handler wants a host->device data stage that
                   this row's USB host model does not drive. A limitation of
                   the harness, recorded as such and NOT as a firmware refusal.
    """
    got = rh.vendor_request(req, length=GRADED_LENGTH,
                            value=GRADED_VALUE, index=GRADED_INDEX)
    rec = {"request": req, "round": round_ix, "wValue": GRADED_VALUE,
           "wIndex": GRADED_INDEX, "wLength": GRADED_LENGTH}
    if got is None:
        rec.update({"reply": None, "class": "OUT_STAGE", "ok": False,
                    "why": "no reply within this run's own silence bound"})
        return rec
    rec["stalled"] = bool(got.get("stalled"))
    rec["status"] = got.get("status")
    rec["data"] = got.get("data")
    rec["length"] = got.get("length")
    rec["provenance"] = got.get("provenance")
    if rec["stalled"]:
        rec["class"] = "REFUSED"
    elif rec["status"] == "timeout":
        rec["class"] = "OUT_STAGE"
    elif rec["status"] == "ok" and (rec["length"] or 0) > 0 and rec["provenance"]:
        rec["class"] = "DRIVEN"
    elif rec["status"] == "ok":
        rec["class"] = "ROUTED"
    else:
        rec["class"] = "OTHER"
    rec["ok"] = rec["class"] == "DRIVEN"
    return rec


def run_parity(rounds: int = 3, control: Optional[str] = None,
               seed: Optional[int] = None,
               agreement_only: bool = False) -> Dict:
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
        "agreement_before": None, "agreement_after": None,
        "agreement_only": agreement_only,
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

        global _INV_NULLS
        _INV_NULLS = list(inv["null_indices"])

        # The control runs BEFORE the entry sweep, on a seam the calibration has
        # just proven healthy, and AGAIN after it. Running it only at the end
        # measured a dead seam (see `_agreement`).
        agree_before_first = _agreement(rh)

        if agreement_only:
            res["agreement_before"] = agree_before_first
            res["agreement"] = agree_before_first
            res["agreement_after"] = None
            facts["agreement_ok"] = bool(
                agree_before_first["ok"]
                and agree_before_first["endptctrl0_stall_logged"])
            facts["round_trip"] = False
            res["entries"] = {}
            res["passed"] = []
            res["parity"] = None
            res["parity_void"] = not guard["ok"]
            facts["parity_full"] = False
            res["facts"] = facts
            res["milestone"] = _ladder(facts)
            res["landed"] = rung_num(res["milestone"]) >= 4
            res["notes"] = ["--agreement-only: the entry sweep was NOT run, so "
                            "this arm carries NO parity claim. It measures the "
                            "NULL-slot/out-of-range refusals on a seam the "
                            "calibration has just proven healthy."]
            return res

        # --- the entries -----------------------------------------------------
        entries: Dict[str, Dict] = {}
        agree_after: Optional[Dict] = None
        for req in inv["implemented_indices"]:
            recs = [_entry_round(rh, req, i + 1) for i in range(rounds)]
            npass = sum(1 for r in recs if r["ok"])
            entries[str(req)] = {
                "request": req, "rounds": rounds, "passed": npass,
                # Rule 2, per ENTRY: N of N, and N > 1. `rounds > 0` was
                # satisfiable by ONE exchange, which is the one-shot oracle
                # Rule 2 forbids -- caught by this lane's own check 3.
                "ok": npass == rounds and rounds > 1,
                "classes": [r["class"] for r in recs],
                "observations": recs,
            }
        res["entries"] = entries
        agree_after = _agreement(rh)
        res["agreement_before"] = agree_before_first
        passed = [int(k) for k, v in entries.items() if v["ok"]]
        res["passed"] = sorted(passed)
        hist = {}
        for v in entries.values():
            for c in v["classes"]:
                hist[c] = hist.get(c, 0) + 1
        res["class_histogram"] = hist
        res["entry_class"] = {
            k: (v["classes"][0] if len(set(v["classes"])) == 1
                else "MIXED:" + ",".join(v["classes"]))
            for k, v in entries.items()}
        facts["round_trip"] = len(passed) > 0

        # --- the agreement control ------------------------------------------
        res["agreement_after"] = agree_after
        agree = res["agreement_before"]
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
    ap.add_argument("--agreement-only", action="store_true",
                   help="measure ONLY the NULL-slot/out-of-range refusals, on a "
                        "freshly calibrated seam. Carries no parity claim.")
    a = ap.parse_args(argv)
    res = run_parity(rounds=a.rounds, control=a.control, seed=a.seed,
                     agreement_only=a.agreement_only)
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
    slim["agreement_only"] = res.get("agreement_only")
    for k in ("agreement_before", "agreement_after"):
        a2 = res.get(k) or {}
        if a2:
            slim[k] = {"refused": a2.get("refused"),
                       "answered": a2.get("answered"),
                       "unmeasured": a2.get("unmeasured"),
                       "expected": a2.get("expected"),
                       "ok": a2.get("ok"), "void": a2.get("void")}
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
