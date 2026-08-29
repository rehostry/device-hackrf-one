# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A polling web panel for the rehosted HackRF One.

    rehostry-hackrf-one-panel            # or: python3 -m rehostry_hackrf_one.hackrf_one_panel

POLLING, NOT SSE (playbook trap 2.5). Proxies buffer ``text/event-stream``, so
an ``EventSource`` panel is a permanently blank page behind one while working
perfectly on localhost. ``GET /state`` returns JSON and the page polls it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import spawn

ARGS = None

STATE = {
    "running": False,
    "enumerated": False,
    "vid_pid": None,
    "boot_lines": [],
    "transfers": [],
    "verdict": "idle",
    "note": "",
    "busy": False,
    "run_id": 0,
}
_LOCK = threading.RLock()
#: Run generation, published as ``run_id``.
#:
#: ``/state`` must never hand a poller a ``verdict`` that belongs to an EARLIER
#: request. :meth:`Handler.do_POST` bumps this and clears ``verdict`` inside the
#: SAME ``_LOCK`` acquisition that accepts the POST, and every worker write is
#: gated on ``run_id == _GEN`` so a superseded request cannot post its answer
#: over a newer one's.
_GEN = 0
_PROC = None
_LOG = None
_SOCK = None
_BUF = b""

#: The vendor requests the panel offers, with the plain-language meaning of
#: each. Numbers are libhackrf's own (host/libhackrf/src/hackrf.c).
REQUESTS = [
    (15, "VERSION_STRING_READ", "the firmware's own release string"),
    (14, "BOARD_ID_READ", "which board it thinks it is"),
    (45, "BOARD_REV_READ", "the hardware revision it detected"),
    (46, "SUPPORTED_PLATFORM_READ", "which boards this build supports"),
    (18, "BOARD_PARTID_SERIALNO_READ", "part id + serial number"),
    (13, "(unsupported)", "NEGATIVE CONTROL -- the firmware must reject this"),
]


def _note(msg: str, run_id=None) -> None:
    with _LOCK:
        if run_id is not None and run_id != _GEN:
            return
        STATE["boot_lines"].append(msg)
        del STATE["boot_lines"][:-40]


def _finish(run_id) -> None:
    """Clear ``busy`` only if this run is still the current one."""
    with _LOCK:
        if run_id == _GEN:
            STATE["busy"] = False


def _boot(run_id=None) -> None:
    global _PROC, _LOG
    try:
        _boot_run()
    finally:
        if run_id is not None:
            _finish(run_id)


def _boot_run() -> None:
    global _PROC, _LOG
    with _LOCK:
        if _PROC is not None and _PROC.poll() is None:
            return
        _LOG = os.path.join(tempfile.mkdtemp(prefix="hackrf-one-panel-"),
                            "run.log")
        fh = open(_LOG, "w")
        _PROC = subprocess.Popen(spawn.spawn_argv(), cwd=spawn.spawn_cwd(),
                                 env=spawn.spawn_env(), stdout=fh,
                                 stderr=subprocess.STDOUT)
        STATE["running"] = True
        STATE["verdict"] = "booting"
        STATE["note"] = ("booting the LPC4320: board detect, clocks, the CPLD's "
                         "55 000 bit-banged JTAG clocks, then USB")
        STATE["transfers"] = []
        STATE["enumerated"] = False
    threading.Thread(target=_watch, daemon=True).start()


def _watch() -> None:
    seen = 0
    while True:
        time.sleep(1.5)
        with _LOCK:
            proc = _PROC
            log = _LOG
        if proc is None or log is None:
            return
        if proc.poll() is not None:
            with _LOCK:
                STATE["running"] = False
                STATE["verdict"] = "stopped"
            return
        try:
            text = open(log).read()
        except OSError:
            continue
        lines = text.splitlines()
        for line in lines[seen:]:
            for pat, msg in (
                    ("CPLD SRAM row 98/98", "CPLD configuration written over JTAG"),
                    ("read back for verify", "CPLD read back and verified"),
                    ("USBCMD.RS set", "USB device controller RUNNING"),
                    ("bus reset driven", "host drove a USB bus reset"),
                    ("ENDPOINTLISTADDR", "firmware published its dQH array"),
                    ("device ENUMERATED", "device ENUMERATED and CONFIGURED")):
                if pat in line:
                    _note(msg)
            m = re.search(r"VID:PID = ([0-9a-f:]+)", line)
            if m:
                with _LOCK:
                    STATE["vid_pid"] = m.group(1)
                    STATE["enumerated"] = True
                    STATE["verdict"] = "enumerated"
        seen = len(lines)


def _stop(run_id=None) -> None:
    global _PROC, _SOCK
    try:
        _stop_run()
    finally:
        if run_id is not None:
            _finish(run_id)


def _stop_run() -> None:
    global _PROC, _SOCK
    with _LOCK:
        if _SOCK is not None:
            try:
                _SOCK.close()
            except OSError:
                pass
            _SOCK = None
        # Only the pid this panel started (playbook trap 2.10).
        if _PROC is not None and _PROC.poll() is None:
            _PROC.terminate()
            try:
                _PROC.wait(10)
            except Exception:  # noqa: BLE001
                _PROC.kill()
        _PROC = None
        STATE["running"] = False
        STATE["verdict"] = "stopped"


def _bridge():
    global _SOCK
    with _LOCK:
        if _SOCK is not None:
            return _SOCK
    try:
        s = socket.create_connection(("127.0.0.1", spawn.BRIDGE_PORT), timeout=5)
        s.settimeout(120)
    except OSError:
        return None
    with _LOCK:
        _SOCK = s
    return s


def _request(run_id, num: int) -> None:
    """One USB vendor request, owned by ONE run.

    Every write below is gated on ``run_id``: a superseded request must never
    publish its answer over a newer one's, and the panel serves exactly one
    request at a time (do_POST refuses a second with 409) so two replies can
    never interleave on the single bridge socket.
    """
    try:
        _request_run(run_id, num)
    finally:
        _finish(run_id)


def _request_run(run_id, num: int) -> None:
    global _BUF
    s = _bridge()
    if s is None:
        _note("the USB control bridge is not up yet", run_id=run_id)
        return
    length = 1 if num in (14, 45) else 0x20
    try:
        s.sendall(("%d 0 0 %d\n" % (num, length)).encode())
    except OSError:
        _note("the bridge closed", run_id=run_id)
        return
    t0 = time.time()
    while b"\n" not in _BUF and time.time() - t0 < 120:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        _BUF += chunk
    if b"\n" not in _BUF:
        _note("no reply to vendor request %d" % num, run_id=run_id)
        return
    line, _BUF = _BUF.split(b"\n", 1)
    try:
        rec = json.loads(line)
    except ValueError:
        return
    raw = bytes.fromhex(rec.get("data", "").replace(" ", ""))
    try:
        text = raw.decode("ascii") if raw and all(
            32 <= b < 127 for b in raw) else None
    except UnicodeDecodeError:
        text = None
    name = next((n for r, n, _ in REQUESTS if r == num), "vendor(%d)" % num)
    with _LOCK:
        if run_id != _GEN:
            return
        STATE["transfers"].append({
            "request": num, "name": name, "setup": rec.get("setup"),
            "data": rec.get("data"), "text": text,
            "stalled": rec.get("stalled"), "status": rec.get("status"),
            "provenance": rec.get("provenance"),
        })
        del STATE["transfers"][:-12]
        if rec.get("stalled"):
            STATE["verdict"] = "rejected (request %d) -- correct" % num
        elif raw:
            STATE["verdict"] = "answered (request %d): %s" % (
                num, text or rec.get("data"))


PAGE = """<!doctype html><meta charset=utf-8>
<title>HackRF One - rehosted LPC4320</title>
<style>
 body{font:14px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;
      background:#10131a;color:#dfe5ee}
 header{padding:14px 20px;background:#161b25;border-bottom:1px solid #232a37}
 h1{margin:0;font-size:19px}
 main{padding:16px 20px;display:grid;gap:14px;
      grid-template-columns:repeat(auto-fit,minmax(330px,1fr))}
 .card{background:#161b25;border:1px solid #232a37;border-radius:8px;padding:12px 14px}
 .card h2{margin:0 0 8px;font-size:13px;text-transform:uppercase;
          letter-spacing:.06em;color:#8b97ab}
 details.brief{margin:12px 20px 0;background:#161b25;border:1px solid #2c3547;
   border-radius:8px;padding:10px 14px}
 details.brief summary{cursor:pointer;font-weight:600;color:#cfe0ff}
 details.brief p{margin:8px 0 0}
 details.brief b{color:#9fc6ff}
 button{font:inherit;padding:6px 11px;margin:3px 4px 3px 0;border-radius:6px;
        border:1px solid #35405a;background:#1e2634;color:#dfe5ee;cursor:pointer}
 button:hover{background:#26314a}
 button.attack{border-color:#7a2b34;background:#3a1b21;color:#ffd4d8}
 code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
 pre{margin:0;white-space:pre-wrap;word-break:break-all}
 table{border-collapse:collapse;width:100%}
 td,th{padding:3px 6px;border-bottom:1px solid #232a37;text-align:left;
       vertical-align:top;font-size:12.5px}
 .ok{color:#7ee2a8}.bad{color:#ff9aa2}.dim{color:#7d8798}
 .verdict{font-size:15px;font-weight:600}
</style>
<header><h1>HackRF One &mdash; rehosted NXP LPC4320 (Cortex-M4)</h1></header>
<details class=brief open>
 <summary>What this is, and what to click</summary>
 <p><b>Device</b> &mdash; a Great Scott Gadgets <b>HackRF One</b>: a 1 MHz&ndash;6 GHz
 half-duplex software-defined radio. This is its real stock
 firmware executing on an emulated LPC4320. Everything a HackRF does is
 commanded over <b>USB vendor-specific control transfers</b> &mdash; there is no
 console, no network and no other interface.</p>
 <p><b>Steps</b> &mdash; 1) <b>Boot firmware</b>, wait for <i>ENUMERATED</i>
 (about a minute: the firmware bit-bangs 55 000 JTAG clocks to configure its
 CPLD first) &rarr; 2) <b>Read version string</b> &rarr; 3) <b>Read board ID</b>
 &rarr; 4) <b>Send unsupported request (negative control)</b>.</p>
 <p><b>What you're seeing</b> &mdash; <i>Boot progress</i> is milestones parsed
 from the emulator's log. <i>USB control transfers</i> is the wire: the 8-byte
 SETUP packet this panel sent, and the bytes the <b>firmware</b> put in its own
 transfer descriptor in reply &mdash; the <i>from</i> column is the guest RAM
 address the firmware itself programmed, so nothing here is host-supplied.</p>
 <p><b>The attack</b> &mdash; every one of these requests is
 <b>unauthenticated</b>. No pairing, no PIN, no host allow-list: any process
 that can open the USB device can read its identity, retune it anywhere in
 1 MHz&ndash;6 GHz, change gain and sample rate, key its transmitter, and
 (requests 10/11) erase and rewrite the SPI flash it boots from. On a shared
 lab machine or a container with the device passed through, that is a complete
 takeover of the radio.</p>
 <p><b>Expect</b> &mdash; request 15 returns the firmware's own release string
 &mdash; the <code>version_string</code> field of the <code>firmware_info</code>
 struct in its image, which <code>PROVENANCE.md</code> predicts byte for byte
 ahead of the run &mdash; and request 14 returns <code>02</code>
 (BOARD_ID_HACKRF1_OG, which the firmware derives at boot from its strap
 resistors). The negative control, request <b>13</b>, must come back
 <b>STALLED with no data</b>: that slot in the firmware's dispatch table is
 NULL, so a device that answered it would be answering this panel rather than
 running the firmware.</p>
</details>
<main>
 <div class=card><h2>Control</h2>
  <button onclick=act('boot')>Boot firmware</button>
  <button onclick=act('stop')>Stop</button><br>
  <button onclick=act('req',15)>Read version string</button>
  <button onclick=act('req',14)>Read board ID</button>
  <button onclick=act('req',45)>Read board revision</button>
  <button onclick=act('req',46)>Read supported platforms</button><br>
  <button class=attack onclick=act('req',13)>Send unsupported request (negative control)</button>
  <p class=verdict id=verdict>idle</p>
  <p class=dim id=note></p>
 </div>
 <div class=card><h2>Device</h2>
  <table id=dev></table>
 </div>
 <div class=card><h2>Boot progress</h2><pre id=boot class=dim></pre></div>
 <div class=card style="grid-column:1/-1"><h2>USB control transfers</h2>
  <table id=xfer><tr><th>req<th>name<th>SETUP (8 bytes out)<th>reply from the firmware<th>from</tr></table>
 </div>
</main>
<script>
// A control POST that arrives while a request is outstanding is REFUSED with
// 409 -- it is never run alongside it. Surface it, so the operator sees the
// click did not start a request rather than reading the previous request's
// answer as this one's.
function act(what, n){
  fetch('/act?what='+what+(n!==undefined?'&n='+n:''),{method:'POST'})
    .then(r=>{if(r.status===409){document.getElementById('verdict').textContent=
      'refused 409 - a request is already outstanding';} poll();});
}
function esc(s){return (s===null||s===undefined)?'':String(s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;');}
function poll(){
 fetch('/state').then(r=>r.json()).then(s=>{
  document.getElementById('verdict').textContent = s.verdict;
  document.getElementById('verdict').className = 'verdict ' +
     (s.verdict.indexOf('rejected')>=0 ? 'ok' :
      s.verdict.indexOf('answered')>=0 ? 'ok' : 'dim');
  document.getElementById('note').textContent = s.note || '';
  document.getElementById('boot').textContent = (s.boot_lines||[]).join('\\n');
  document.getElementById('dev').innerHTML =
    '<tr><td>emulator<td>' + (s.running?'<span class=ok>running</span>':'<span class=dim>stopped</span>') +
    '<tr><td>enumerated<td>' + (s.enumerated?'<span class=ok>yes</span>':'<span class=dim>no</span>') +
    '<tr><td>VID:PID<td><code>' + esc(s.vid_pid||'-') + '</code>';
  var rows = '<tr><th>req<th>name<th>SETUP (8 bytes out)<th>reply from the firmware<th>from</tr>';
  (s.transfers||[]).forEach(function(t){
    var reply = t.stalled ? '<span class=bad>STALLED &mdash; refused, no data</span>'
              : ('<code>' + esc(t.data) + '</code>' +
                 (t.text ? ' <span class=ok>&quot;' + esc(t.text) + '&quot;</span>' : ''));
    var prov = t.provenance ? ('<code>0x' + (t.provenance.buffer>>>0).toString(16) +
                 '</code> len ' + t.provenance.length_from_firmware) : '<span class=dim>-</span>';
    rows += '<tr><td>' + t.request + '<td>' + esc(t.name) +
            '<td><code>' + esc(t.setup) + '</code><td>' + reply + '<td>' + prov;
  });
  document.getElementById('xfer').innerHTML = rows;
 });
}
poll(); setInterval(poll, 1500);
</script>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: A003
        pass

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/state"):
            with _LOCK:
                body = json.dumps(STATE).encode()
            self._send(200, "application/json", body)
        else:
            self._send(200, "text/html; charset=utf-8", PAGE.encode())

    def do_POST(self):  # noqa: N802
        global _GEN
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query)
        what = (q.get("what") or [""])[0]
        if what == "req":
            try:
                num = int((q.get("n") or ["15"])[0])
            except ValueError:
                self._send(400, "application/json",
                           b'{"ok":false,"reason":"bad request number"}')
                return
            worker, extra = _request, (num,)
        elif what == "boot":
            worker, extra = _boot, ()
        elif what == "stop":
            worker, extra = _stop, ()
        else:
            self._send(404, "application/json",
                       b'{"ok":false,"reason":"unknown action"}')
            return

        # ACCEPTING the POST and SUPERSEDING the previous run are ONE atomic
        # step, under the same lock `/state` reads.
        #
        # The shape this replaces ran the vendor request ON THE REQUEST THREAD
        # with no busy flag at all, so a second POST arriving while one was
        # outstanding ran CONCURRENTLY -- two replies interleaving on the one
        # bridge socket and the shared _BUF -- and answered 200 either way. For
        # the whole of that window `/state` went on serving the PREVIOUS
        # request's `verdict`, byte for byte, so the NEGATIVE CONTROL (request
        # 13, which the firmware must reject) read as the previous read's
        # "answered ...".
        #
        # So: a POST that cannot run now is REFUSED (409), never run alongside;
        # and a POST that is accepted clears the previous verdict before this
        # method returns.
        with _LOCK:
            if STATE["busy"]:
                self._send(409, "application/json", json.dumps(
                    {"ok": False, "busy": True, "verdict": STATE["verdict"],
                     "run_id": STATE["run_id"]}).encode())
                return
            if what == "req" and not STATE["running"]:
                self._send(409, "application/json", json.dumps(
                    {"ok": False, "reason": "not booted",
                     "run_id": STATE["run_id"]}).encode())
                return
            _GEN += 1
            run_id = _GEN
            STATE.update(busy=True, run_id=run_id,
                         verdict="accepted (run %d)" % run_id)
            try:
                threading.Thread(target=worker, args=(run_id,) + extra,
                                 daemon=True).start()
            except Exception:  # noqa: BLE001
                # never strand the panel in a permanent busy state
                STATE.update(busy=False, verdict="error")
                raise
        self._send(200, "application/json",
                   json.dumps({"ok": True, "run_id": run_id}).encode())


def main() -> int:
    global ARGS
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("HAL_HRF_HTTP_PORT", "9019")),
                    help="panel HTTP port (default from HAL_HRF_HTTP_PORT, "
                         "else 9019)")
    ARGS = ap.parse_args()
    srv = ThreadingHTTPServer(("0.0.0.0", ARGS.port), Handler)
    print("[hackrf_one_panel] polling panel on http://127.0.0.1:%d "
          "(USB control bridge tcp/%d)" % (ARGS.port, spawn.BRIDGE_PORT))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
