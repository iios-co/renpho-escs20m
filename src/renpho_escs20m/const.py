"""Constants for the Renpho ES-CS20M scale."""

# QN-Scale hardware ships two GATT transports for the same wire protocol.
# The renpho ES-CS20M uses the FFF0 service (preferred when present):
NOTIFY_CHARACTERISTIC_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
COMMAND_CHARACTERISTIC_UUID = "0000fff2-0000-1000-8000-00805f9b34fb"

# Other QN scales (e.g. Arboleaf CS20M) expose the FFE0 service
# instead. Pre-measurement and stored-record frames arrive as indications
# on FFE2; set-time and stored-query commands go to FFE4, the rest to FFE3.
FFE0_NOTIFY_CHARACTERISTIC_UUID = "0000ffe1-0000-1000-8000-00805f9b34fb"
FFE0_INDICATE_CHARACTERISTIC_UUID = "0000ffe2-0000-1000-8000-00805f9b34fb"
FFE0_COMMAND_CHARACTERISTIC_UUID = "0000ffe3-0000-1000-8000-00805f9b34fb"
FFE0_ALT_COMMAND_CHARACTERISTIC_UUID = "0000ffe4-0000-1000-8000-00805f9b34fb"

# The 0x55aa variant (LeFu hardware) exposes vendor service 0x1A10: readings
# arrive as notifications on 2A10; 2A11 is the write characteristic
# (write-with-response only). The basic-flavor client is notify-only and
# never writes; the command UUID is kept for the extended flavor, whose
# on-device body composition requires a profile write.
X55AA_NOTIFY_CHARACTERISTIC_UUID = "00002a10-0000-1000-8000-00805f9b34fb"
X55AA_COMMAND_CHARACTERISTIC_UUID = "00002a11-0000-1000-8000-00805f9b34fb"
# MSC flavor (R-MSC04) only: the live-weight stream arrives on 0x2A10 as
# above, but the command acks and the final 0x24 / 0x25 body-composition
# panel are delivered as INDICATIONS on a separate characteristic, 0x2A12.
# A client that subscribes to 0x2A10 alone sees the live weight but never a
# final, so the MSC path subscribes to both.
X55AA_INDICATE_CHARACTERISTIC_UUID = "00002a12-0000-1000-8000-00805f9b34fb"

# Standard BLE SIG characteristics on the scale's Device Information services.
BATTERY_LEVEL_CHARACTERISTIC_UUID = "00002a19-0000-1000-8000-00805f9b34fb"
FIRMWARE_REVISION_CHARACTERISTIC_UUID = "00002a26-0000-1000-8000-00805f9b34fb"

WEIGHT_KEY = "weight"
BODY_FAT_KEY = "body_fat"
RESISTANCE_1_KEY = "resistance_1"
RESISTANCE_2_KEY = "resistance_2"

# Body-composition metrics some scales compute on-device and stream after
# the final measurement. Only models that send the extended-metrics frames
# report these; everywhere else the caller derives its own from body fat
# (see :mod:`renpho_escs20m.body_metrics`). Masses are kg, percentages are
# percent, BMR is kcal/day, and visceral fat, body age, body score and body
# shape are the scale's own unitless ratings.
BMI_KEY = "bmi"
BODY_WATER_KEY = "body_water"
MUSCLE_MASS_KEY = "muscle_mass"
VISCERAL_FAT_KEY = "visceral_fat"
BODY_AGE_KEY = "body_age"
BMR_KEY = "bmr"
PROTEIN_KEY = "protein"
BONE_MASS_KEY = "bone_mass"
FAT_FREE_MASS_KEY = "fat_free_mass"
SUBCUTANEOUS_FAT_KEY = "subcutaneous_fat"
SKELETAL_MUSCLE_KEY = "skeletal_muscle"
BODY_SCORE_KEY = "body_score"
BODY_SHAPE_KEY = "body_shape"

# Scale-provided ("as measured by the device") metrics for the MSC flavor
# (R-MSC04). Distinct from the keys above so a consumer can expose the scale's
# own on-device figures ALONGSIDE its own computed ones and compare them,
# rather than one overwriting the other. Body fat rides BODY_FAT_KEY as usual
# (there is no computed-vs-scale ambiguity: the caller's computation takes the
# scale's body fat as its input). ``impedance_raw`` is the verbatim tuple of
# raw bio-impedance samples from the panel; units/segments unattributed.
SCALE_BMI_KEY = "scale_bmi"
SCALE_SKELETAL_MUSCLE_KEY = "scale_skeletal_muscle"
SCALE_VISCERAL_FAT_KEY = "scale_visceral_fat"
IMPEDANCE_RAW_KEY = "impedance_raw"
# The entire 0x25 panel payload as hex — every byte the scale sent, including
# any not yet attributed to a field. Diagnostic, so no transmitted data is
# ever lost and future decoding has ground truth.
RAW_PANEL_HEX_KEY = "raw_panel_hex"

__all__ = [
    "NOTIFY_CHARACTERISTIC_UUID",
    "COMMAND_CHARACTERISTIC_UUID",
    "FFE0_NOTIFY_CHARACTERISTIC_UUID",
    "FFE0_INDICATE_CHARACTERISTIC_UUID",
    "FFE0_COMMAND_CHARACTERISTIC_UUID",
    "FFE0_ALT_COMMAND_CHARACTERISTIC_UUID",
    "X55AA_NOTIFY_CHARACTERISTIC_UUID",
    "X55AA_COMMAND_CHARACTERISTIC_UUID",
    "X55AA_INDICATE_CHARACTERISTIC_UUID",
    "BATTERY_LEVEL_CHARACTERISTIC_UUID",
    "FIRMWARE_REVISION_CHARACTERISTIC_UUID",
    "WEIGHT_KEY",
    "BODY_FAT_KEY",
    "RESISTANCE_1_KEY",
    "RESISTANCE_2_KEY",
    "BMI_KEY",
    "BODY_WATER_KEY",
    "MUSCLE_MASS_KEY",
    "VISCERAL_FAT_KEY",
    "BODY_AGE_KEY",
    "BMR_KEY",
    "PROTEIN_KEY",
    "BONE_MASS_KEY",
    "FAT_FREE_MASS_KEY",
    "SUBCUTANEOUS_FAT_KEY",
    "SKELETAL_MUSCLE_KEY",
    "BODY_SCORE_KEY",
    "BODY_SHAPE_KEY",
    "SCALE_BMI_KEY",
    "SCALE_SKELETAL_MUSCLE_KEY",
    "SCALE_VISCERAL_FAT_KEY",
    "IMPEDANCE_RAW_KEY",
    "RAW_PANEL_HEX_KEY",
]
