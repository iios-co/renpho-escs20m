"""Renpho 0x55aa (LeFu hardware) GATT protocol."""

from .protocol import (
    MSC_PROFILE_RMSC04_RAY,
    MSCCapturedProfile,
    MSCMeasurement,
    X55AAProfile,
    X55AAProfileResolver,
    age_on,
    build_guest_profile_command,
    build_msc_handshake,
)
from .scale import Renpho55AAScale

__all__ = [
    "Renpho55AAScale",
    "X55AAProfile",
    "X55AAProfileResolver",
    "MSCCapturedProfile",
    "MSCMeasurement",
    "MSC_PROFILE_RMSC04_RAY",
    "age_on",
    "build_guest_profile_command",
    "build_msc_handshake",
]
