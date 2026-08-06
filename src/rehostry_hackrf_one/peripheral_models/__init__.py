# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Register-level models of the LPC4320 and the parts around it on the board.

  ``lpc43xx_soc``    one region for 0x40000000-0x401FFFFF, routed to the rest
  ``lpc43xx_usb0``   the Chipidea USB device controller -- the seam
  ``usb_host``       the other end of the USB wire, plus the TCP bridge
  ``lpc43xx_gpio``   GPIO, board straps, the JTAG pins, the flash chip select
  ``cpld_xc2c64a``   the XC2C64A's JTAG TAP and configuration SRAM
  ``spi_flash``      the W25Q80BV serial flash on SSP0
  ``lpc_rom``        the boot ROM's IAP entry
  ``hal_link``       where a model finds the live backend

Every one of these is here because the firmware **stops** without it; each
module's docstring records the measurement that proved it.
"""
