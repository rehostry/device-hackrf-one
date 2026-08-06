<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# PROVENANCE — device-hackrf-one

Where every artifact came from, and the **falsifiable static prediction** this
rehost was measured against. §2 was written and committed **before the firmware
was booted even once**; §5 records what the running firmware actually produced.

---

## 1. Firmware

| | |
|---|---|
| Device | Great Scott Gadgets **HackRF One** — 1 MHz–6 GHz half-duplex SDR |
| MCU | NXP **LPC4320**, Cortex-M4 (ARMv7E-M) application core + a Cortex-M0 baseband core |
| Image | `firmware-bin/hackrf_one_usb.bin` from release **v2026.01.3** |
| sha256 | `1d5f36c702677bc47086403c8e8c8a650d47d892a3c791e2dc9a7fa2bab1d72b` |
| size | 45 720 bytes, raw binary (no ELF, **stripped**) |
| Upstream | <https://github.com/greatscottgadgets/hackrf> tag `v2026.01.3` |
| Licence | GPL-2.0-or-later (`COPYING` ships alongside the binary) |
| Local copy | `firmware-incoming/W2d-rf-rfid/hackrf/hackrf_one_usb.bin` |

Firmware bytes are **not committed**. `tools/extract_firmware.py` stages the
vendor binary into `configs/` and hard-fails if the digest, the vector table,
the load base, the USB0 vector or `firmware_info` do not match.

### 1.1 Load base — derived, then verified

A raw `.bin` carries no load address. Three independent facts pin it at
**`0x00000000`**:

1. The vendor linker script `firmware/common/LPC4320_M4_memory.ld` says
   `rom (rx) : ORIGIN = 0x00000000, LENGTH = 1M`, with the comment
   *"rom is really the shadow region that points to SPI flash"*. On the LPC43xx
   the boot ROM maps the selected boot source into the shadow region at 0.
2. The reset vector `0x000080d1` resolves under that base to file offset
   `0x80d0`, which holds `0x4a31` — an `ldr r2, [pc, #…]` function prologue, not
   data. The extractor enforces this (playbook trap 2.81).
3. `firmware_info` (magic `HACKRFFW`) sits at file offset `0x400`, exactly where
   the vector-table region ends.

### 1.2 The vector table says what this device *is*

Every IRQ vector in the image is the same shared blocking handler
(`0x000080c9`) **except IRQ 8**, which is `0x00000d1d`. IRQ 8 on the LPC43xx M4
is **USB0**. So the only interrupt this firmware services is USB — which is the
whole interface of a HackRF One and the whole point of this rehost. The
extractor asserts both halves of that (the USB0 entry *and* that the other 63
entries collapse to one value), so a future release that moves it fails loudly.

---

## 2. Static prediction (written BEFORE the first boot)

The target seam is a **USB vendor-specific control transfer** — the
`hackrf_*` libusb command set — driven as a real SETUP packet into the
firmware's own USB device stack, with the firmware's own reply bytes captured
out of the transfer descriptor it fills in.

### 2.1 How a vendor request is dispatched (from source + the image)

`firmware/hackrf_usb/hackrf_usb.c` holds a flat dispatch table:

```c
static usb_request_handler_fn vendor_request_handler[] = {
    NULL,                                    /*  0 */
    usb_vendor_request_set_transceiver_mode, /*  1 */
    ...
    usb_vendor_request_read_board_id,        /* 14 */
    usb_vendor_request_read_version_string,  /* 15 */
    ...
};
static const uint32_t vendor_request_handler_count =
        sizeof(vendor_request_handler) / sizeof(vendor_request_handler[0]);

usb_request_status_t usb_vendor_request(usb_endpoint_t* const endpoint,
                                        const usb_transfer_stage_t stage)
{
    usb_request_status_t status = USB_REQUEST_STATUS_STALL;
    if (endpoint->setup.request < vendor_request_handler_count) {
        usb_request_handler_fn handler =
                vendor_request_handler[endpoint->setup.request];
        if (handler) { status = handler(endpoint, stage); }
    }
    return status;                       /* STALL if out of range or NULL */
}
```

The table has **59 entries (0…58)**, and entries **0, 13 and 22** are `NULL`
(13 "used to be write_cpld", 22 "was set_if_freq").

### 2.2 PREDICTION A — `HACKRF_VENDOR_REQUEST_VERSION_STRING_READ` (= 15)

```c
usb_request_status_t usb_vendor_request_read_version_string(
        usb_endpoint_t* const endpoint, const usb_transfer_stage_t stage)
{
    uint8_t length;
    if (stage == USB_TRANSFER_STAGE_SETUP) {
        length = (uint8_t) strlen(firmware_info.version_string);
        memcpy(&endpoint->buffer, firmware_info.version_string,
               sizeof(firmware_info.version_string));
        usb_transfer_schedule_block(endpoint->in, &endpoint->buffer,
                                    length, NULL, NULL);
        usb_transfer_schedule_ack(endpoint->out);
    }
    return USB_REQUEST_STATUS_OK;
}
```

`firmware_info.version_string` is `char[32]` inside `struct firmware_info_t`
(`firmware/common/firmware_info.h`), placed by the linker at guest address
**`0x00000400`**, field offset +16. Read straight out of the image:

```
00000400  48 41 43 4b 52 46 46 57  01 00 00 00 0a 00 00 00   HACKRFFW........
00000410  32 30 32 36 2e 30 31 2e  33 00 00 00 00 00 00 00   2026.01.3.......
```

`strlen()` of that field is **9**.

> **PREDICTION A.** A SETUP packet `C0 0F 00 00 00 00 20 00`
> (bmRequestType = device-to-host | vendor | device, bRequest = 15,
> wValue = 0, wIndex = 0, wLength = 0x20) makes the firmware return
> **exactly 9 bytes**:
>
> ```
> 32 30 32 36 2e 30 31 2e 33      =  "2026.01.3"
> ```
>
> The bytes must be read back out of the **dTD buffer the firmware itself
> primed on EP0 IN**, not from anywhere the host wrote. The transfer is then
> acknowledged by a zero-length OUT status stage that the firmware primes with
> `usb_transfer_schedule_ack(endpoint->out)`.

Falsifiable in three independent ways: a wrong length, wrong bytes, or the
firmware never priming EP0 IN at all would each fail it.

### 2.3 PREDICTION B — `HACKRF_VENDOR_REQUEST_BOARD_ID_READ` (= 14)

```c
endpoint->buffer[0] = detected_platform();
usb_transfer_schedule_block(endpoint->in, &endpoint->buffer, 1, NULL, NULL);
```

`detected_platform()` returns whatever `detect_hardware_platform()` latched at
boot from the **board strap resistors**, read as GPIO inputs
(`firmware/common/platform_detect.c`):

* HackRF One (pre-r9): pull-**up** on `P5_0` (GPIO2[9]), pull-**down** on
  `P6_10` (GPIO3[6]) → `HACKRF1_OG_RESISTORS` → `BOARD_ID_HACKRF1_OG` = **2**.

This device's GPIO model presents exactly those straps (and nothing on `P6_5`,
i.e. not a Praline), because that is the board this binary is built for
(`supported_platform = 0x0000000a` = OG | R9, checked by the extractor).

> **PREDICTION B.** SETUP `C0 0E 00 00 00 00 01 00` returns **one byte `0x02`**
> — and that byte is *derived by the firmware* from the strap levels the GPIO
> model presents, not stored anywhere in the image. The device ships a test that
> asserts the resistor decode (`P5_0` pull-up + `P6_10` pull-down → OG = 2, and
> the r9 pattern → 4), so the constant cannot silently become a magic number.

### 2.4 PREDICTION C — the device descriptor (a standard request)

`firmware/hackrf_usb/usb_descriptor.c` builds an 18-byte device descriptor with
`idVendor = 0x1D50`, `idProduct = 0x6089` (HACKRF_ONE), `bcdUSB = 0x0200`,
`bMaxPacketSize0 = 64`, `bcdDevice = 0x0110`.

> **PREDICTION C.** SETUP `80 06 00 01 00 00 12 00` returns 18 bytes beginning
> `12 01 00 02 00 00 00 40 50 1d 89 60 10 01`.

### 2.5 NEGATIVE CONTROL — vendor request 13

Table entry 13 is `NULL`. `usb_vendor_request` therefore returns
`USB_REQUEST_STATUS_STALL`, and `usb_request()` calls `usb_endpoint_stall()`,
which sets **`ENDPTCTRL0.RXS | ENDPTCTRL0.TXS`** (`0x00010001`).

> **PREDICTION D (negative control).** SETUP `C0 0D 00 00 00 00 20 00` —
> identical harness, identical stage, the only difference being the request
> byte — produces **no EP0 IN data at all** and instead sets the stall bits in
> `ENDPTCTRL0`. If the "reply" for request 15 were an artifact of the harness,
> request 13 would produce one too.

### 2.6 What would make the prediction *not* falsifiable

Nothing in the host model contains the string `2026.01.3`, the byte `0x02`, or
`50 1d 89 60`. The host writes only the 8 SETUP bytes. The reply bytes are read
from guest RAM at the address the **firmware** placed in
`dTD.buffer_pointer_page[0]`, with the length the **firmware** placed in
`dTD.total_bytes`. A test (`tests/test_structure.py`) asserts that neither the
USB host model nor the attack module contains a literal copy of the expected
reply that could be echoed.

---

## 3. Rehost boundary — what is modelled, and what is not

The M4's boot path touches a great deal of hardware before `usb_run()`. Every
model below is a *model* (register-level behaviour), not a stub of firmware
logic, unless explicitly marked.

| Block | Base | Treatment |
|---|---|---|
| USB0 device controller | `0x40006000` | **Full model**: dQH/dTD DMA, ENDPTPRIME/ENDPTSTAT/ENDPTCOMPLETE/ENDPTSETUPSTAT, ENDPTCTRL stall+enable, USBSTS/USBINTR, bus reset. This is the seam. |
| GPIO (byte/word/port) | `0x400F4000` | Model, incl. the board-strap levels and the bit-banged CPLD JTAG pins |
| CPLD XC2C64A over JTAG | (GPIO pins) | **Model**: a TAP state machine + a 98×274-bit ISC SRAM array, so the firmware's own `cpld_xc2c64a_jtag_sram_verify()` reads back what it wrote |
| SCU / CGU / CCU / RGU / CREG | `0x4008_6000` etc. | Model: storage + mirrored ready/lock bits |
| ADC0/1 | `0x400E3000` | Model: mid-scale readings (→ `BOARD_REV_HACKRF1_OLD`) |
| I²C0/1, SSP0/1, SGPIO, timers | various | Catch-all with busy-wait breaking |
| Boot ROM / IAP | `0x10400000` | `*(uint32_t*)0x10400100 == 0x12345678`, i.e. **"IAP not implemented"** — which is the truth for a flashless LPC4320 (vendor errata ES_LPC43X0_A §3.5) and is the path the firmware itself takes |
| Cortex-M0 baseband core | — | **Not run.** `ipc_start_m0()` is accepted and ignored. The M0 only moves sample buffers; it is not on the control path. |
| RF front end (MAX2837, RFFC5071, Si5351C, MAX5864) | SPI/I²C | Bus reads return 0 (playbook trap 2.90). The radio does not transmit; this is a control-plane rehost. |

See `STATUS.md` "Known limitations" for what this means for what the device can
and cannot be used to test.

---

## 4. Ports

| | |
|---|---|
| ZMQ rx / tx | 6118 / 6119 |
| Panel HTTP | 9019 |
| USB control bridge (TCP) | 21209 |

---

## 5. Result — filled in after the run

See `STATUS.md` for the measured firmware-side evidence and whether §2's
predictions matched.
