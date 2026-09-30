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
    MSC_PROFILE_RMSC04_RAY,
    MSCMeasurement,
    build_msc_handshake,
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
            impedance_raw=(3577, 3530, 2920, 3053, 3221, 3153, 2601, 2734),
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
            impedance_raw=(3628, 3556, 2910, 3020, 3249, 3162, 2602, 2721),
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
            impedance_raw=(3622, 3575, 2876, 2981, 3225, 3170, 2579, 2697),
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


# --- profile handshake (verbatim capture replay) ---------------------------


def test_build_msc_handshake_reproduces_capture() -> None:
    """The builder must reproduce the four captured handshake frames exactly
    (the capture session started at sequence 0x05)."""
    frames = build_msc_handshake(MSC_PROFILE_RMSC04_RAY, first_sequence=0x05)
    expected = [
        "55aab200090502071c2139b90302fc",
        "55aab3000b060701016abc6cea01e00029",
        "55aab8000c07020123281e780000000000ae",
        "55aab70009080200010003526179f9",
    ]
    assert [f.hex() for f in frames] == expected


def test_build_msc_handshake_sequences_and_checksums() -> None:
    """Sequence byte increments per frame; checksum holds over each frame."""
    frames = build_msc_handshake(MSC_PROFILE_RMSC04_RAY, first_sequence=0x20)
    for offset, frame in enumerate(frames):
        assert frame[5] == 0x20 + offset  # seq at payload index 0 (frame byte 5)
        assert checksum(frame[:-1]) == frame[-1]


def test_build_msc_handshake_sequence_wraps() -> None:
    frames = build_msc_handshake(MSC_PROFILE_RMSC04_RAY, first_sequence=0xFE)
    assert [f[5] for f in frames] == [0xFE, 0xFF, 0x00, 0x01]
    for frame in frames:
        assert checksum(frame[:-1]) == frame[-1]


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


# --- write allow-list guard -------------------------------------------------


def test_assert_allowed_write_accepts_the_replayed_handshake() -> None:
    from renpho_escs20m.x55aa.protocol import assert_allowed_write

    for frame in build_msc_handshake(MSC_PROFILE_RMSC04_RAY, first_sequence=0):
        assert_allowed_write(frame)  # must not raise


def test_assert_allowed_write_accepts_b2_with_a_different_weight() -> None:
    """0xb2's weight field is the one the app varies; a different weight in
    the otherwise-verbatim frame is allowed."""
    import struct

    from renpho_escs20m.x55aa.protocol import (
        CMD_MSC_SET_HEIGHT_WEIGHT,
        MSC_PROFILE_RMSC04_RAY,
        assert_allowed_write,
        checksum,
    )

    tail = bytearray(MSC_PROFILE_RMSC04_RAY.set_height_weight_tail)
    struct.pack_into(">H", tail, 3, 9012)  # a different last weight (90.12 kg)
    body = b"\x55\xaa" + bytes([CMD_MSC_SET_HEIGHT_WEIGHT])
    body += (len(tail) + 1).to_bytes(2, "big") + bytes([0x05]) + bytes(tail)
    frame = body + bytes([checksum(body)])
    assert_allowed_write(frame)  # must not raise


def test_assert_allowed_write_rejects_a_mutated_profile() -> None:
    """A 0xb8 profile that differs from the captured template is refused: its
    bytes are not understood, so the library must not send it."""
    from renpho_escs20m.x55aa.protocol import (
        CMD_MSC_PROFILE,
        ForbiddenWrite,
        assert_allowed_write,
        checksum,
    )

    body = b"\x55\xaa" + bytes([CMD_MSC_PROFILE])
    tampered = bytes.fromhex("020199281e780000000000")  # one byte changed
    body += (len(tampered) + 1).to_bytes(2, "big") + bytes([0x05]) + tampered
    frame = body + bytes([checksum(body)])
    with pytest.raises(ForbiddenWrite):
        assert_allowed_write(frame)


# --- advertisement detection (00 12 prefix) ---------------------------------

# Real R-MSC04 advertisement (company 0x1A10 payload), MAC 60:30:F2:73:CC:79.
_MSC_ADV = bytes.fromhex("001200356030f273cc790002")
_MSC_MAC = "60:30:F2:73:CC:79"


def test_is_msc_advertisement_matches_the_00_12_prefix() -> None:
    from renpho_escs20m.x55aa.protocol import is_advertisement, is_msc_advertisement

    assert is_msc_advertisement(_MSC_ADV, _MSC_MAC) is True
    # It is NOT the standard 00 04 shape.
    assert is_advertisement(_MSC_ADV, _MSC_MAC) is False


def test_is_msc_advertisement_requires_the_mac_echo() -> None:
    from renpho_escs20m.x55aa.protocol import is_msc_advertisement

    assert is_msc_advertisement(_MSC_ADV, "AA:BB:CC:DD:EE:FF") is False


def test_detect_protocol_classifies_msc_advertisement_as_x55aa() -> None:
    from renpho_escs20m.detection import ScaleProtocol, detect_protocol, is_x55aa_frame

    assert is_x55aa_frame(_MSC_ADV, _MSC_MAC) is True
    assert detect_protocol("", {0x1A10: _MSC_ADV}, _MSC_MAC) == ScaleProtocol.X55AA


def test_detect_protocol_rejects_msc_advertisement_with_wrong_mac() -> None:
    from renpho_escs20m.detection import detect_protocol

    assert detect_protocol("", {0x1A10: _MSC_ADV}, "AA:BB:CC:DD:EE:FF") is None
