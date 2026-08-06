<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# device-hackrf-one

A **Great Scott Gadgets HackRF One** — the 1 MHz–6 GHz half-duplex
software-defined radio — rehosted from its stock firmware, as a standalone,
pip-installable HALucinator device.

The firmware is unmodified vendor **v2026.01.3** running on an emulated NXP
**LPC4320** (Cortex-M4, ARMv7E-M). It boots, detects which HackRF board it is
from its strap resistors, configures its CPLD over a bit-banged JTAG port,
brings up its USB device controller, **enumerates**, and then answers the
`hackrf_*` vendor control transfers that are its entire command surface.

```
$ rehostry-hackrf-one-attack
[boot] msg=booting the LPC4320 rehost
[enumerated] vid_pid=1d50:6089
[attack] request=15 msg=unauthenticated vendor request VERSION_STRING_READ
[reply] request=15 data=32 30 32 36 2e 30 31 2e 33 text=2026.01.3
[reply] request=14 data=02
[negative_control_result] request=13 stalled=True endptctrl0_stall_logged=True
[verdict] landed=True
RESULT: {"booted": true, "landed": true}
```

## Why this device is interesting

**A HackRF One has no console, no serial port and no network.** Every command
it accepts — read identity, retune anywhere in 1 MHz–6 GHz, set sample rate and
gain, key the transmitter, drive the antenna bias tee, and *erase and rewrite
the SPI flash it boots from* — arrives as a **USB vendor-specific control
transfer**, and **none of them is authenticated**. There is no pairing, no PIN,
no session and no host allow-list: `usb_vendor_request()` indexes a flat table
of 59 handlers with the attacker-supplied request byte and calls it.

That makes it a clean, high-value parser seam — and it means the rehost is only
worth anything if the USB device controller is modelled for real. It is.

## What makes the round-trip honest

The host writes **eight bytes**: a USB SETUP packet. Everything that comes back
is produced by the firmware:

* the firmware copies its own `firmware_info.version_string` into its endpoint
  buffer and calls `strlen()` on it;
* it builds a transfer descriptor pointing at that buffer, with that length;
* it primes EP0 IN.

The LPC43xx's USB0 is a **Chipidea-style bus master** — queue heads and
transfer descriptors live in guest RAM and the *controller* does the DMA — so
the model reads the reply from the address in the firmware's own
`dTD.buffer_pointer_page[0]`, for the length in the firmware's own
`dTD.total_bytes`. Both are reported as `provenance`. No module in this package
contains a copy of the expected reply, and a test enforces that.

The **negative control** is vendor request **13**, whose slot in the firmware's
dispatch table is `NULL` ("used to be write_cpld"). The firmware must reject it,
and it does — by writing `ENDPTCTRL0 = RXS|TXS` itself. The attack reports
`landed: true` only if the supported request answers *and* the unsupported one
is refused.

See `PROVENANCE.md` for the falsifiable prediction (written before the first
boot; all four predictions matched byte for byte) and `STATUS.md` for the
measured evidence, the adversarial controls and the known limitations.

## The interesting wall: the CPLD gates USB

`main()` configures the HackRF's XC2C64A CPLD over a bit-banged JTAG port and
**verifies the readback** before it touches USB; on failure it parks in
`halt_and_flash()` for ever. Measured here: corrupt one bit of the readback and
the device **never enumerates**, with **no fault and no diagnostic** — it just
blinks LEDs nobody can see.

Satisfying it needs no bitstream knowledge, because the firmware compares
against the array it just programmed. So the model is an IEEE 1149.1 TAP state
machine plus a 98×274-bit row store, and the firmware's own verify passes.

## Install and run

```bash
python3 tools/extract_firmware.py     # stages the vendor .bin, verifies it hard
pip install -e .                      # into a venv with halucinator[unicorn]@dev

rehostry-hackrf-one run               # boot it
rehostry-hackrf-one probe 15 14 45 46 13
rehostry-hackrf-one-attack            # the conforming attack
rehostry-hackrf-one-panel             # http://127.0.0.1:9019
python3 -m pytest tests/ -q
```

Firmware bytes are **not** committed. `tools/extract_firmware.py` stages the
vendor release binary and hard-fails unless its sha256, size, vector table,
load base, USB0 vector and `firmware_info` struct all match.

### The USB control bridge

`tcp/21209` is a line-oriented bridge onto the device's **control endpoint**.
Write `<request> [value] [index] [length]`, get back a JSON line with whatever
the firmware replied:

```
$ printf '15\n14\n13\n' | nc 127.0.0.1 21209
{"label": "bridge:vendor(15)", "setup": "c0 0f 00 00 00 00 20 00", "request": 15,
 "data": "32 30 32 36 2e 30 31 2e 33", "length": 9, "status": "ok", "stalled": false, ...}
{"label": "bridge:vendor(14)", ... "data": "02", "length": 1, "status": "ok", ...}
{"label": "bridge:vendor(13)", ... "data": "", "length": 0, "status": "stalled", "stalled": true}
```

A request arriving there is delivered as a real SETUP packet into the firmware's
own USB stack, exactly as one from `libhackrf` would be.

## Layout

```
tools/extract_firmware.py            stage + verify the vendor image; derive the addr map
src/rehostry_hackrf_one/
  configs/                           HALucinator config, addr map, logging.cfg
  peripheral_models/
    lpc43xx_usb0.py                  the Chipidea device controller (dQH/dTD)
    usb_host.py                      the other end of the wire + the TCP bridge
    cpld_xc2c64a.py                  the CPLD's JTAG TAP and ISC SRAM
    lpc43xx_gpio.py                  GPIO, board straps, JTAG pins, flash CS
    spi_flash.py                     the W25Q80BV on SSP0
    lpc43xx_soc.py                   one region, routed: ADC, SSP, I2C, CGU/CCU/RGU
    lpc_rom.py                       the boot ROM's IAP entry
    hal_link.py                      where models find the live backend
  bp_handlers/boot_init.py           publish the backend at the reset vector
  attack.py  cli.py  hackrf_one_panel.py
tests/test_structure.py              29 tests, no emulator required
```

## Licence

AGPL-3.0-or-later. The HackRF firmware itself is GPL-2.0-or-later and belongs to
Great Scott Gadgets; it is referenced, not redistributed.
