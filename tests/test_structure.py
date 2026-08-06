# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Structural tests: NO emulator required.

These guard the things that rot silently -- config/extractor agreement, the
spawn recipe's invariants, the register couplings this rehost turned out to
depend on, and (most importantly) the **non-forgeability** of the attack's
oracle: no module in this device may contain a copy of the reply the firmware
is supposed to produce.
"""
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
PKG = os.path.join(SRC, "rehostry_hackrf_one")
CONFIGS = os.path.join(PKG, "configs")
sys.path.insert(0, SRC)


def _config():
    with open(os.path.join(CONFIGS, "hackrf_one_config.yaml")) as fh:
        return yaml.safe_load(fh)


def _addrs():
    with open(os.path.join(CONFIGS, "hackrf_one_addrs.yaml")) as fh:
        return yaml.safe_load(fh)


def _extractor():
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import extract_firmware
    return extract_firmware


# --- spawn-recipe invariants ----------------------------------------------

def test_spawn_argv_invokes_the_installed_module_not_a_source_tree():
    from rehostry_hackrf_one import spawn
    argv = spawn.spawn_argv(python="python")
    assert argv[:4] == ["python", "-m", "halucinator.main", "-c"], argv
    assert "--emulator" in argv


def test_spawn_env_strips_source_injection():
    from rehostry_hackrf_one import spawn
    os.environ["HALUCINATOR_SRC"] = "/nonexistent/x"
    os.environ["PYTHONPATH"] = "/nonexistent/x"
    try:
        env = spawn.spawn_env()
    finally:
        os.environ.pop("HALUCINATOR_SRC", None)
        os.environ.pop("PYTHONPATH", None)
    assert "HALUCINATOR_SRC" not in env
    assert "PYTHONPATH" not in env


def test_spawn_env_sets_the_load_bearing_knobs():
    """Each of these was a silent hang before it was set (see spawn.py)."""
    from rehostry_hackrf_one import spawn
    env = spawn.spawn_env()
    # An M3 model has no VFP and this firmware is built for an M4F.
    assert env["HAL_CORTEXM_CPU_MODEL"] == "UC_CPU_ARM_CORTEX_M4"
    # HAL_DET_TICK is INERT on cortex-m without HAL_IRQ_CHUNK (trap 2.50).
    assert int(env["HAL_IRQ_CHUNK"]) > 0
    irq, period = env["HAL_DET_TICK"].split(":")
    assert int(irq) == 8, "IRQ 8 is USB0 -- the only live vector in the image"
    assert int(period) > 1, ("a period of 1 self-feeds: an exception return "
                             "also ends a chunk (trap 2.50)")


def test_config_files_are_shipped_and_named_consistently():
    from rehostry_hackrf_one import paths
    for name in paths.CONFIG_FILES:
        assert os.path.isfile(os.path.join(CONFIGS, name)), name


# --- the config agrees with the image --------------------------------------

def test_config_vector_table_matches_the_extractor():
    ef = _extractor()
    cfg = _config()
    assert cfg["machine"]["entry_addr"] == ef.EXPECT_RESET
    assert cfg["machine"]["init_sp"] == ef.EXPECT_INIT_SP
    assert cfg["machine"]["entry_addr"] & 1, "the reset vector must be Thumb"


def test_load_base_is_the_boot_shadow_region():
    ef = _extractor()
    cfg = _config()
    assert cfg["memories"]["rom"]["base_addr"] == ef.LOAD_BASE == 0


def test_every_intercept_resolves_to_a_generated_symbol():
    """An intercept whose `function:` does not resolve is DROPPED SILENTLY
    (playbook trap 2.26), so the handler simply never runs."""
    names = set(_addrs()["symbols"].values())
    for entry in _config().get("intercepts", []):
        assert entry["function"] in names, entry


def test_the_usb0_vector_is_the_only_live_irq():
    """The whole device's interrupt plumbing rests on this."""
    ef = _extractor()
    assert ef.USB0_IRQ == 8
    from rehostry_hackrf_one import spawn
    assert spawn.spawn_env()["HAL_DET_TICK"].startswith("%d:" % ef.USB0_IRQ)


def test_peripheral_regions_are_4k_aligned_multiples_of_4k():
    for name, spec in _config()["peripherals"].items():
        assert spec["base_addr"] % 0x1000 == 0, name
        assert spec["size"] % 0x1000 == 0, name


def test_peripheral_regions_do_not_overlap():
    """An overlap leaves the overlapping range mapped by NEITHER region
    (playbook trap 2.39)."""
    spans = sorted((s["base_addr"], s["base_addr"] + s["size"], n)
                   for n, s in _config()["peripherals"].items())
    for (_lo1, hi1, n1), (lo2, _hi2, n2) in zip(spans, spans[1:]):
        assert hi1 <= lo2, "%s overlaps %s" % (n1, n2)


def test_the_usb0_controller_is_inside_the_soc_region():
    from rehostry_hackrf_one.peripheral_models import lpc43xx_usb0
    soc = _config()["peripherals"]["soc"]
    assert soc["base_addr"] <= lpc43xx_usb0.USB0_BASE \
        < soc["base_addr"] + soc["size"]


# --- register couplings this rehost depends on -----------------------------

def test_board_straps_decode_to_hackrf_one_and_r9_decodes_differently():
    """PROVENANCE.md prediction B rests on this: board id 2 is DERIVED from
    strap levels, not a magic constant. If the constant were wrong, the r9
    pattern would have to decode to 2 as well -- assert that it does not."""
    from rehostry_hackrf_one.peripheral_models import lpc43xx_gpio as g
    og = g.STRAPS_HACKRF1_OG
    assert g.decode_board_straps(og[(2, 9)], og[(3, 6)], og[(3, 4)]) == 2
    r9 = g.STRAPS_HACKRF1_R9
    assert g.decode_board_straps(r9[(2, 9)], r9[(3, 6)], r9[(3, 4)]) == 4


def test_a_gpio_output_reads_back_the_level_it_drives():
    """Playbook trap 2.72 -- firmware constantly asks the pad about itself."""
    from rehostry_hackrf_one.peripheral_models.lpc43xx_gpio import (
        GPIO_BASE, Lpc43xxGpio)
    g = Lpc43xxGpio()
    g.hw_write(GPIO_BASE + 0x2000 + 2 * 4, 4, 1 << 5)      # DIR2 bit5 = output
    g.hw_write(GPIO_BASE + 0x2200 + 2 * 4, 4, 1 << 5)      # SET2 bit5
    assert g.hw_read(GPIO_BASE + 0x1000 + 2 * 0x80 + 5 * 4, 4)
    g.hw_write(GPIO_BASE + 0x2280 + 2 * 4, 4, 1 << 5)      # CLR2 bit5
    assert not g.hw_read(GPIO_BASE + 0x1000 + 2 * 0x80 + 5 * 4, 4)


def test_pll_lock_mirrors_power_down_in_both_directions():
    """A LOCK bit pinned high makes the firmware's *unlock* wait
    unsatisfiable, which is a hard hang with no diagnostic."""
    from rehostry_hackrf_one.peripheral_models import lpc43xx_soc as s
    soc = s.Lpc43xxSoc("soc", 0x40000000, 0x200000)
    for stat, ctrl in s.CGU_PLL_STAT_CTRL.items():
        soc._clock[(s.CGU_BASE, ctrl)] = 1                 # PD set
        assert soc._clock_read(s.CGU_BASE, stat) & 1 == 0
        soc._clock[(s.CGU_BASE, ctrl)] = 0                 # PD clear
        assert soc._clock_read(s.CGU_BASE, stat) & 1 == 1


def test_reset_active_status_is_the_inverse_of_reset_ctrl():
    """`ipc_halt_m0()` waits for the bit to go to ZERO; `ipc_start_m0()` for
    it to go to ONE. Only the inverse-of-CTRL model satisfies both."""
    from rehostry_hackrf_one.peripheral_models import lpc43xx_soc as s
    soc = s.Lpc43xxSoc("soc", 0x40000000, 0x200000)
    m0 = 1 << 24
    soc._clock[(s.RGU_BASE, 0x104)] = m0                   # M0APP held in reset
    assert soc._clock_read(s.RGU_BASE, s.RGU_ACTIVE_STATUS1) & m0 == 0
    soc._clock[(s.RGU_BASE, 0x104)] = 0                    # released
    assert soc._clock_read(s.RGU_BASE, s.RGU_ACTIVE_STATUS1) & m0 == m0


def test_adc_reports_the_channel_the_firmware_selected():
    """`adc_read()` spins until ADGDR's CHN field equals the channel it asked
    for; a model that always reports channel 0 hangs on channels 3/4/7."""
    from rehostry_hackrf_one.peripheral_models import lpc43xx_soc as s
    soc = s.Lpc43xxSoc("soc", 0x40000000, 0x200000)
    for ch in (0, 3, 4, 7):
        soc._adc_write(s.ADC0_LO + 0x00, 1 << ch)
        v = soc._adc_read(s.ADC0_LO + 0x04)
        assert v & (1 << 31), "DONE must be set"
        assert (v >> 24) & 7 == ch
        assert 2 <= ((v >> 6) & 0x3FF) <= 1022, "must read as 'nothing fitted'"


def test_ssp_status_never_reports_busy():
    """The busy-wait breaker's all-ones sets SR.BSY, so `while (SR & BSY);`
    could never exit. Two PCs sat on 0x4008300c for ever."""
    from rehostry_hackrf_one.peripheral_models import lpc43xx_soc as s
    soc = s.Lpc43xxSoc("soc", 0x40000000, 0x200000)
    sr = soc._ssp_read(s.SSP0_BASE, 0x0C)
    assert sr & s.SSP_SR_TNF, "transmit FIFO must accept a byte"
    assert not sr & s.SSP_SR_BSY, "a modelled bus is never busy"


def test_serial_flash_answers_the_device_id_the_firmware_waits_for():
    """`w25q80bv_setup()` is `do { id = get_device_id(); } while (id != 0x13
    && ...);` -- an unbounded retry with no error path."""
    from rehostry_hackrf_one.peripheral_models.spi_flash import (
        CMD_DEVICE_ID, DEVICE_ID, W25q80bv)
    f = W25q80bv()
    f.select(True)
    out = [f.xfer(CMD_DEVICE_ID)] + [f.xfer(0xFF) for _ in range(4)]
    assert out[4] == DEVICE_ID
    # ...and the chip select is the frame delimiter (trap 2.88): a fresh
    # select must start a fresh command.
    f.select(False)
    f.select(True)
    assert f.xfer(CMD_DEVICE_ID) == 0


def test_cpld_reads_back_exactly_what_was_written():
    """The firmware's own `cpld_xc2c64a_jtag_sram_verify()` compares the read
    against the array it just programmed, so this property IS the boot gate."""
    from rehostry_hackrf_one.peripheral_models import cpld_xc2c64a as c
    cpld = c.Xc2c64aJtag()
    cpld.ir = c.IR_ISC_WRITE
    cpld.sr_bits = c.DR_BITS_ISC
    pattern = 0x0123456789ABCDEF0FEDCBA987654321 & c.ROW_MASK
    cpld.sr = pattern | (0x45 << c.BITS_IN_ROW)
    cpld._update_dr()
    assert cpld.sram[0x45] == pattern
    cpld.ir = c.IR_ISC_SRAM_READ
    cpld.addr = 0x45
    cpld._capture_dr()
    assert cpld.sr & c.ROW_MASK == pattern


def test_cpld_idcode_and_ir_capture_satisfy_the_firmwares_own_checks():
    from rehostry_hackrf_one.peripheral_models import cpld_xc2c64a as c
    # cpld_xc2c64a_jtag_idcode_ok()
    assert ((c.IDCODE ^ 0xF6E5F093) & 0x0FFF8FFF) == 0
    # cpld_xc2c_jtag_read_write_protect()  and  cpld_xc2c_jtag_is_done()
    assert ((c.IR_CAPTURE ^ 0x01) & 0x03) == 0
    assert ((c.IR_CAPTURE ^ 0x05) & 0x07) == 0


def test_usb_setup_packet_encoding_round_trips():
    import struct

    from rehostry_hackrf_one.peripheral_models.usb_host import (
        VENDOR_IN, setup_packet)
    pkt = setup_packet(VENDOR_IN, 15, 0, 0, 0x20)
    assert len(pkt) == 8
    bmt, req, val, idx, ln = struct.unpack("<BBHHH", pkt)
    assert (bmt, req, val, idx, ln) == (0xC0, 15, 0, 0, 0x20)
    assert bmt & 0x80, "device-to-host"
    assert (bmt >> 5) & 3 == 2, "vendor type"


def test_dtd_token_length_field_decodes_where_the_controller_reads_it():
    """The oracle's length comes from this field of the firmware's own dTD."""
    from rehostry_hackrf_one.peripheral_models import lpc43xx_usb0 as u
    token = (9 << u.DTD_TOTAL_SHIFT) | u.DTD_IOC | u.DTD_ACTIVE
    assert (token & u.DTD_TOTAL_MASK) >> u.DTD_TOTAL_SHIFT == 9
    assert token & u.DTD_ACTIVE


def test_queue_head_index_matches_the_firmwares_own_macro():
    """USB_QH_INDEX(addr) = ((addr & 0xF) * 2) + ((addr >> 7) & 1)."""
    from rehostry_hackrf_one.peripheral_models.lpc43xx_usb0 import qh_index
    for address in (0x00, 0x80, 0x02, 0x81):
        ep, is_in = address & 0xF, bool(address & 0x80)
        assert qh_index(ep, is_in) == ((address & 0xF) * 2
                                       + ((address >> 7) & 1))


# --- the oracle must not be forgeable --------------------------------------

def _device_sources():
    for root, _dirs, files in os.walk(PKG):
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


def test_no_module_contains_the_reply_the_firmware_must_produce():
    """If the expected version string appeared anywhere in this device, the
    'reply' could be an echo. It must exist only in the firmware image and in
    PROVENANCE.md's prediction."""
    needles = ("2026.01.3", "32 30 32 36", "323032362e")
    for path in _device_sources():
        with open(path) as fh:
            text = fh.read()
        for needle in needles:
            assert needle not in text, "%s contains %r" % (path, needle)


def test_the_attack_validates_the_version_string_by_shape_not_equality():
    from rehostry_hackrf_one import attack
    assert attack._valid_version_string(b"2026.01.3")
    assert attack._valid_version_string(b"2021.03.1")
    assert not attack._valid_version_string(b"")
    assert not attack._valid_version_string(b"\x00\x01\x02\x03\x04\x05")
    assert not attack._valid_version_string(b"hello")          # no dots


def test_the_attack_exposes_the_fleet_interface():
    import inspect

    from rehostry_hackrf_one import attack
    sig = inspect.signature(attack.run_attack)
    assert list(sig.parameters) == ["on_stage", "log_dir"]
    src = inspect.getsource(attack)
    assert 'print("RESULT:", json.dumps(' in src
    # `landed` must require the negative control too.
    assert "endptctrl0_stall_logged" in src


def test_the_negative_control_is_a_null_slot_in_the_firmwares_own_table():
    """Request 13 is `NULL, // used to be write_cpld` in hackrf_usb.c, so the
    firmware MUST stall it. Anything else would not be a control."""
    from rehostry_hackrf_one import attack
    assert attack.REQ_UNSUPPORTED == 13
    assert attack.REQ_VERSION_STRING_READ == 15
    assert attack.REQ_BOARD_ID_READ == 14


def test_panel_polls_and_carries_the_five_line_briefing():
    from rehostry_hackrf_one import hackrf_one_panel as panel
    page = panel.PAGE
    assert "EventSource" not in page, "panels must poll, never SSE (trap 2.5)"
    assert "setInterval(poll, 1500)" in page
    assert "details class=brief open" in page
    for label in ("<b>Device</b>", "<b>Steps</b>", "<b>What you're seeing</b>",
                  "<b>The attack</b>", "<b>Expect</b>"):
        assert label in page, label


def test_every_source_file_carries_the_agpl_header():
    for path in _device_sources():
        with open(path) as fh:
            head = fh.read(400)
        assert "Copyright 2026 Christopher Wright" in head, path
        assert "SPDX-License-Identifier: AGPL-3.0-or-later" in head, path
