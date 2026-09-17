#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Enumerate this row's ladder BEFORE and AFTER, scored through the fleet guard.

BEFORE is **transcribed** from commit `4d7c7ed` (the last commit before lane
`s0917-laneG` touched the row); AFTER is **imported** from `attack.py`, so the
after-column cannot drift from the shipped code.

What this answers, per assignment of the ladder's boolean facts:

* PRINTABLE (what the code can emit) vs WRITTEN (string constants returned by
  `_ladder`, read with `ast`) vs DECLARED (`attack.LADDER_RUNGS`). All three
  must end equal, or some rung is either unreachable or undeclared.
* dead branches -- a guard that no assignment can satisfy.
* how many assignments gain a NEW `M4-OK` credit from the guard. **Must be 0**:
  adding rungs ABOVE M4 must not make a non-M4 run land.
* false floors in BOTH directions -- an assignment that scored M6/M7 while the
  before-ladder printed something lower, and any assignment printing a rung
  while `guest_executed` is false.
* `DEFECT-landed-without-M4`, which must be 0 in both columns.

⚠ `census_score.score()` takes the RESULT **dict**, not its JSON text, and its
verdict is field **3** of the returned tuple. Getting either wrong produces a
clean, uniform, entirely wrong answer.
"""
from __future__ import annotations

import argparse
import ast
import itertools
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))

from rehostry_hackrf_one import attack as A  # noqa: E402

TERMS = tuple(A.LADDER_FACTS) + ("neg_stalled",)  # independent of the rung


def before_ladder(f):
    """The ladder at 4d7c7ed, transcribed verbatim from that commit.

        res = {"booted": False, "landed": False, ...}   # no `milestone` key
        if not rh.wait_enumerated(...):  return res      # -> NO MILESTONE AT ALL
        res["booted"] = True
        ...
        res["usb_vendor_round_trip"] = bool(version_ok and board_ok)
        res["milestone"] = ("M4" if res["usb_vendor_round_trip"]
                            else "unproven (no protocol round trip observed)")
        res["landed"] = bool(... and neg["stalled"] and ...)

    `milestone` took exactly two values and the negative one was a PROSE
    STRING. The fleet guard's `_milestone_num` cannot parse it, so it becomes
    "-" and the row scores a bare WALL with no rung -- and on the boot-failure
    path the key was ABSENT entirely, which scores the same way. M0..M3 were
    unreachable; M6/M7 did not exist.

    The boot gate there was `wait_enumerated`, which in this row's fact
    vocabulary is `drives_own_interface` (the firmware transmitted its own
    descriptors). `neg` -- whether the negative control stalled -- was
    independent of every ladder fact, so it is modelled as an extra boolean.
    """
    if not f["drives_own_interface"]:
        return {"booted": False, "landed": False}          # no milestone key
    landed = bool(f["round_trip"] and f["neg_stalled"])
    return {"booted": True, "landed": landed,
            "milestone": ("M4" if f["round_trip"]
                          else "unproven (no protocol round trip observed)")}


def after_ladder(f):
    ms = A._ladder(f)
    return {"booted": bool(f["drives_own_interface"]),
            "landed": A.rung_num(ms) >= 4, "milestone": ms}


def written_rungs(fn_name="_ladder"):
    src = os.path.join(os.path.dirname(HERE), "src", "rehostry_hackrf_one",
                       "attack.py")
    tree = ast.parse(open(src, encoding="utf-8").read())
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef) and fn.name == fn_name:
            return {n.value.value for n in ast.walk(fn)
                    if isinstance(n, ast.Return)
                    and isinstance(n.value, ast.Constant)
                    and isinstance(n.value.value, str)}
    raise AssertionError("%s not found" % fn_name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--guard",
                    default="/Users/user/Development/rehostry/"
                            "scratch-census-guard-a48")
    args = ap.parse_args()
    sys.path.insert(0, args.guard)
    import census_score                     # IMPORTED, never forked (§4).

    rows = []
    for bits in itertools.product((False, True), repeat=len(TERMS)):
        f = dict(zip(TERMS, bits))
        rows.append((f, before_ladder(f), after_ladder(f)))

    def tally(i):
        printable, hist, cred, defect = set(), {}, 0, 0
        for _f, *r in rows:
            x = r[i]
            printable.add(x.get("milestone", "<absent>"))
            v = census_score.score(x)[3]
            hist[v] = hist.get(v, 0) + 1
            cred += int(v == "M4-OK")
            defect += int(v == "DEFECT-landed-without-M4")
        return printable, hist, cred, defect

    bp, bh, bc, bd = tally(0)
    ap_, ah, ac, ad = tally(1)

    gained = [f for f, b, a in rows
              if census_score.score(a)[3] == "M4-OK"
              and census_score.score(b)[3] != "M4-OK"]
    new_credits = len(gained)
    # ⚠ A new credit is only acceptable if the assignment ACTUALLY completed the
    # M4 round trip. This row gains credits, and they are NOT from the M6/M7
    # branches -- they are from splitting `landed` (which carried the ATTACK's
    # DoS verdict) from the rung. The old code scored an assignment whose seam
    # round-tripped but whose reboot payload did not wedge as WALL-M4: an honest
    # M4 rehost counted as a wall. Any credit gained by an assignment WITHOUT a
    # round trip is a real defect and must be zero.
    unearned = [f for f in gained if not (f["round_trip"] and f["guest_executed"]
                                          and f["own_init"]
                                          and f["drives_own_interface"])]
    new_credits_unearned = len(unearned)

    # ⚠ `neg_stalled` is a FREE boolean in this enumeration because in the OLD
    # code it was independent of the rung. In the NEW code it is not free: the
    # firmware's refusal of the unsupported request is a COMPONENT of
    # `round_trip` (§1c -- a discriminating round trip needs valid accepted and
    # invalid rejected), so `round_trip -> neg_stalled` and any assignment with
    # round_trip true and neg_stalled false cannot occur in a real run.
    #
    # Every credit this row "gains" lives in exactly that unrealisable region.
    # Restricted to assignments the code can actually produce, the gain is 0 --
    # which is the number that matters, and it is reported rather than being
    # quietly substituted for the raw one.
    def realisable(f):
        return (not f["round_trip"]) or f["neg_stalled"]
    gained_realisable = [f for f in gained if realisable(f)]
    new_credits_realisable = len(gained_realisable)

    def entitled(f):
        """The rung the FACTS entitle a run to, written here from RULES.md §0
        directly and NOT by calling `_ladder`. Both columns are scored against
        this, so neither column grades itself."""
        if not f["guest_executed"]:
            return 0                                  # nothing executed: M0
        if not f["own_init"]:
            return 1
        if not f["drives_own_interface"]:
            return 2
        if not f["round_trip"]:
            return 3
        if not (f["m6_measured"] and f["m6_ok"]):
            return 4
        if not (f["m7_measured"] and f["m7_ok"]):
            return 6
        return 7

    # UPWARD false floor: printed HIGHER than the facts entitle (the limiting
    # case being any rung at all for a run whose guest never executed).
    up_before = sum(1 for f, b, _a in rows
                    if A.rung_num(b.get("milestone")) > entitled(f))
    up_after = sum(1 for f, _b, a in rows
                   if A.rung_num(a.get("milestone")) > entitled(f))
    up_noguest_before = sum(1 for f, b, _a in rows
                            if not f["guest_executed"]
                            and A.rung_num(b.get("milestone")) > 0)
    up_noguest_after = sum(1 for f, _b, a in rows
                           if not f["guest_executed"]
                           and A.rung_num(a.get("milestone")) > 0)
    # DOWNWARD false floor: the facts exhibit M6/M7 and the ladder printed
    # something lower -- the rung the branch could not emit.
    dn_before = sum(1 for f, b, _a in rows
                    if entitled(f) >= 6 and A.rung_num(b.get("milestone")) < entitled(f))
    dn_after = sum(1 for f, _b, a in rows
                   if entitled(f) >= 6 and A.rung_num(a.get("milestone")) < entitled(f))

    w = written_rungs()
    declared = set(A.LADDER_RUNGS)
    dead = sorted(declared - ap_)
    n = len(rows)

    print("assignments enumerated: %d  (%d booleans: %s)"
          % (n, len(TERMS), ",".join(TERMS)))
    print()
    print("%-42s %-24s %s" % ("", "BEFORE (4d7c7ed)", "AFTER (imported)"))
    print("%-42s %-24s %s" % ("PRINTABLE", ",".join(sorted(bp)),
                              ",".join(sorted(ap_))))
    print("%-42s %-24s %s" % ("WRITTEN (ast over _ladder)", "n/a (no _ladder)",
                              ",".join(sorted(w))))
    print("%-42s %-24s %s" % ("DECLARED (LADDER_RUNGS)", "n/a",
                              ",".join(sorted(declared))))
    print("%-42s %-24s %s" % ("PRINTABLE == WRITTEN == DECLARED", "-",
                              (ap_ == w == declared)))
    print("%-42s %-24s %s" % ("dead branches (declared, unreachable)", "-",
                              dead or "none"))
    print("%-42s %-24s %s" % ("credited M4-OK by the guard",
                              "%d of %d" % (bc, n), "%d of %d" % (ac, n)))
    print("%-42s %-24s %s" % ("DEFECT-landed-without-M4", bd, ad))
    print("%-42s %-24s %s" % ("assignments gaining a NEW M4-OK credit", "-",
                              new_credits))
    print("%-42s %-24s %s" % ("  ... of which UNEARNED (no round trip)", "-",
                              new_credits_unearned))
    print("%-42s %-24s %s" % ("  ... of which REALISABLE (rt -> neg_stalled)",
                              "-", new_credits_realisable))
    print("%-42s %-24s %s" % ("false floor UP (printed > entitled)",
                              up_before, up_after))
    print("%-42s %-24s %s" % ("  ... of which: rung w/o guest_executed",
                              up_noguest_before, up_noguest_after))
    print("%-42s %-24s %s" % ("false floor DOWN (M6/M7 earned, printed lower)",
                              dn_before, dn_after))
    print()
    print("guard verdict histogram BEFORE:", dict(sorted(bh.items())))
    print("guard verdict histogram AFTER :", dict(sorted(ah.items())))

    bad = []
    if ap_ != w or ap_ != declared:
        bad.append("PRINTABLE/WRITTEN/DECLARED disagree")
    if dead:
        bad.append("dead branches: %s" % dead)
    if new_credits_unearned:
        bad.append("%d assignments gained an UNEARNED M4-OK credit"
                   % new_credits_unearned)
    if new_credits_realisable:
        bad.append("%d REALISABLE assignments gained an M4-OK credit"
                   % new_credits_realisable)
    if ad:
        bad.append("DEFECT-landed-without-M4 present AFTER (%d)" % ad)
    if up_after or up_noguest_after:
        bad.append("%d upward false floors remain" % up_after)
    if dn_after:
        bad.append("%d downward false floors remain" % dn_after)
    print()
    print("VERDICT:", "CLEAN" if not bad else "; ".join(bad))
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
