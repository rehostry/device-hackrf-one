# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""``rehostry-hackrf-one`` -- run, probe, attack or open the panel.

    rehostry-hackrf-one run          boot the rehost in the foreground
    rehostry-hackrf-one probe 15 14  boot, then issue vendor requests
    rehostry-hackrf-one attack       the conforming attack (RESULT: {json})
    rehostry-hackrf-one panel        the polling web panel
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time

from . import paths, spawn


def _run(args) -> int:
    if not paths.firmware_present():
        print("firmware missing: run tools/extract_firmware.py first "
              "(expected %s)" % paths.firmware_bin(), file=sys.stderr)
        return 2
    argv = spawn.spawn_argv()
    print("+", " ".join(argv))
    proc = subprocess.Popen(argv, cwd=spawn.spawn_cwd(), env=spawn.spawn_env())
    try:
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(10)
        except Exception:  # noqa: BLE001
            proc.kill()
        return 130


def _probe(args) -> int:
    """Boot, wait for the firmware to enumerate itself, then ask it things."""
    import tempfile
    log = os.path.join(tempfile.mkdtemp(prefix="hackrf-one-probe-"), "run.log")
    fh = open(log, "w")
    proc = subprocess.Popen(spawn.spawn_argv(), cwd=spawn.spawn_cwd(),
                            env=spawn.spawn_env(), stdout=fh,
                            stderr=subprocess.STDOUT)
    print("log:", log)
    try:
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            time.sleep(2)
            if proc.poll() is not None:
                print("emulator exited rc=%s" % proc.returncode)
                return 1
            if "ENUMERATED and CONFIGURED" in open(log).read():
                break
        else:
            print("the firmware did not enumerate within %ss" % args.timeout)
            return 1
        sock = socket.create_connection(("127.0.0.1", spawn.BRIDGE_PORT),
                                        timeout=10)
        sock.settimeout(args.timeout)
        buf = b""
        for req in args.request:
            sock.sendall(("%s 0 0 %d\n" % (req, args.length)).encode())
            t0 = time.time()
            while b"\n" not in buf and time.time() - t0 < args.timeout:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
            if b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                print("request %-4s -> %s" % (req, line.decode().strip()))
            else:
                print("request %-4s -> (no reply)" % req)
        sock.close()
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except Exception:  # noqa: BLE001
            proc.kill()
        fh.close()


def _attack(args) -> int:
    from .attack import main as attack_main
    return attack_main()


def _panel(args) -> int:
    from .hackrf_one_panel import main as panel_main
    sys.argv = ["rehostry-hackrf-one-panel", "--port", str(args.port)]
    return panel_main()


def main() -> int:
    ap = argparse.ArgumentParser(prog="rehostry-hackrf-one", description=__doc__)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("run", help="boot the rehost in the foreground")
    p.set_defaults(func=_run)

    p = sub.add_parser("probe", help="boot, then issue USB vendor requests")
    p.add_argument("request", nargs="*", default=["15", "14"],
                   help="vendor request numbers (default: 15 14)")
    p.add_argument("--length", type=int, default=0x20)
    p.add_argument("--timeout", type=float, default=240.0)
    p.set_defaults(func=_probe)

    p = sub.add_parser("attack", help="the conforming attack")
    p.set_defaults(func=_attack)

    p = sub.add_parser("panel", help="the polling web panel")
    p.add_argument("--port", type=int,
                   default=int(os.environ.get("HAL_HRF_HTTP_PORT", "9019")))
    p.set_defaults(func=_panel)

    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
