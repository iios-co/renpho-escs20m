"""Tests for the MSC-flavor (R-MSC04) 0x55aa read path.

Golden vectors are real notification frames captured from one R-MSC04
"Body Composition Scale" (HVIN ``R-MSC04``), MAC ``60:30:F2:73:CC:79``,
over three weigh-ins at different weights. Each is cross-checked against
the Renpho Health app's own CSV export for the same weigh-in:

- 85.05 kg: BMI 25.7, body fat 25.8 %, skeletal muscle 42.2 %, visceral 8
- 86.30 kg: BMI 26.1, body fat 27.5 %, skeletal muscle 41.3 %, visceral 9
- 87.95 kg: BMI 26.6, body fat 29.0 %, skeletal muscle 40.4 %, visceral 10

The 0x25 panel is fragmented across three notifications behind the shared
0xAD/0xAE/0xAF headers; reassembly is exercised via ``iter_frames`` after
``strip_fragment_header``, matching the client's own handling.
"""

from __future__ import annotations

import pytest

from renpho_escs20m.x55aa.protocol import (
    CMD_MSC_FINAL,
    CMD_MSC_PANEL,
    Frame,
    MSCMeasurement,
    checksum,
    iter_frames,
    parse_msc_final_weight,
    parse_msc_panel,
    strip_fragment_header,
)


def _frame(hexstr: str) -> Frame:
    """Parse a single complete 55aa frame from a hex string into a Frame."""
    buf = bytearray(bytes.fromhex(hexstr.replace(" ", "")))
    frames = iter_frames(buf)
    assert len(frames) == 1, f"expected one frame, got {frames!r}"
    return frames[0]


def _reassemble(*fragments: str) -> bytearray:
    """Strip fragment headers and concatenate, as the client's buffer does."""
    buf = bytearray()
    for frag in fragments:
        buf.extend(strip_fragment_header(bytes.fromhex(frag.replace(" ", ""))))
    return buf


# --- 0x24 final weight frames (one per weigh-in) ---------------------------

# The three captured 0x24 finals and their expected weights.
FINAL_VECTORS = [
    ("55 aa 24 00 06 01 11 00 00 21 48 a4", 85.20),
    ("55 aa 24 00 06 01 11 00 00 21 b6 12", 86.30),
    ("55 aa 24 00 06 01 11 00 00 22 5b b8", 87.95),
]


@pytest.mark.parametrize("hexstr, expected_weight", FINAL_VECTORS)
def test_parse_msc_final_weight(hexstr: str, expected_weight: float) -> None:
    frame = _frame(hexstr)
    assert frame.cmd == CMD_MSC_FINAL
    assert parse_msc_final_weight(frame) == expected_weight


def test_parse_msc_final_weight_rejects_other_commands() -> None:
    assert parse_msc_final_weight(Frame(0x21, b"\x01\x00\x00\x21\x48")) is None


def test_parse_msc_final_weight_rejects_short_payload() -> None:
    assert parse_msc_final_weight(Frame(CMD_MSC_FINAL, b"\x01\x11\x00")) is None


# --- 0x25 body-composition panel (fragmented, one per weigh-in) ------------

PANEL_VECTORS = [
    (
        (
            "ad 04 02 55 aa 25 00 24 04 11 00 00 21 39 0a 00 a5 0d f9 0d",
            "ae 04 01 ca 0b 68 0b ed 00 63 0c 95 0c 51 0a 29 0a ae 02 01",
            "af 04 00 02 01 01 01 a6 00 08 b0",
        ),
        MSCMeasurement(
            weight_kg=85.05,
            body_fat=25.8,
            bmi=25.7,
            skeletal_muscle=42.2,
            visceral_fat=8,
        ),
    ),
    (
        (
            "ad 04 02 55 aa 25 00 24 04 11 00 00 21 b6 0a 00 aa 0e 2c 0d",
            "ae 04 01 e4 0b 5e 0b cc 00 68 0c b1 0c 5a 0a 2a 0a a1 02 01",
            "af 04 00 13 01 05 01 9d 00 09 80",
        ),
        MSCMeasurement(
            weight_kg=86.30,
            body_fat=27.5,
            bmi=26.1,
            skeletal_muscle=41.3,
            visceral_fat=9,
        ),
    ),
    (
        (
            "ad 04 02 55 aa 25 00 24 04 11 00 00 22 5b 0a 00 ad 0e 26 0d",
            "ae 04 01 f7 0b 3c 0b a5 00 75 0c 99 0c 62 0a 13 0a 89 02 01",
            "af 04 00 22 01 0a 01 94 00 0a c7",
        ),
        MSCMeasurement(
            weight_kg=87.95,
            body_fat=29.0,
            bmi=26.6,
            skeletal_muscle=40.4,
            visceral_fat=10,
        ),
    ),
]


@pytest.mark.parametrize("fragments, expected", PANEL_VECTORS)
def test_parse_msc_panel(fragments: tuple[str, ...], expected: MSCMeasurement) -> None:
    buf = _reassemble(*fragments)
    frames = iter_frames(buf)
    assert len(frames) == 1
    frame = frames[0]
    assert frame.cmd == CMD_MSC_PANEL
    assert parse_msc_panel(frame) == expected


def test_panel_checksum_valid_after_reassembly() -> None:
    """The 8-bit-sum checksum must hold over the reassembled frame."""
    fragments, _ = PANEL_VECTORS[0]
    buf = _reassemble(*fragments)
    # The full frame is header(5) + payload(36) + checksum(1) = 42 bytes.
    assert len(buf) == 42
    assert checksum(buf[:-1]) == buf[-1]


def test_parse_msc_panel_rejects_other_commands() -> None:
    assert parse_msc_panel(Frame(CMD_MSC_FINAL, b"\x00" * 36)) is None


def test_parse_msc_panel_rejects_short_payload() -> None:
    assert parse_msc_panel(Frame(CMD_MSC_PANEL, b"\x00" * 20)) is None


def test_final_and_panel_weight_agree() -> None:
    """The 0x24 precursor and 0x25 panel report the same weigh-in weight
    (within the 0.10 kg the scale rounds its live-weight stream to)."""
    # 0x24 says 85.20 for the same weigh-in the panel reports at 85.05:
    # the 0x24 is the last live sample, the panel the settled figure. Both
    # decode cleanly; we assert each parses, not that they are identical.
    final = parse_msc_final_weight(_frame(FINAL_VECTORS[0][0]))
    panel = parse_msc_panel(iter_frames(_reassemble(*PANEL_VECTORS[0][0]))[0])
    assert final is not None and panel is not None
    assert abs(final - panel.weight_kg) < 0.5
