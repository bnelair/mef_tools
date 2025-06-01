import struct
import hashlib
import os
from datetime import datetime
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# UNIVERSAL_HEADER_BYTES = 1024
# CRC_START_VALUE = 0xFFFFFFFF
# PASSWORD_BYTES = 16  # AES-128 key size
# PASSWORD_VALIDATION_FIELD_BYTES = 16  # First 16 bytes of SHA-256 hash
# SHA256_OUTPUT_SIZE_BYTES = 32  # 256 bits
#
# # Access Levels
# LEVEL_0_ACCESS = 0
# LEVEL_1_ACCESS = 1
# LEVEL_2_ACCESS = 2


# --- Constants ---
UNIVERSAL_HEADER_BYTES = 1024
CRC_START_VALUE = 0xFFFFFFFF
PASSWORD_BYTES = 16
PASSWORD_VALIDATION_FIELD_BYTES = 16
MEF_VERSION_MAJOR = 3
MEF_VERSION_MINOR = 0
MEF_LITTLE_ENDIAN = 1
UUTC_NO_ENTRY = 0x8000000000000000 # For si8 time fields
SI4_NO_ENTRY_NEG1 = -1 # For some si4 fields like segment_number if not applicable
UI4_NO_ENTRY_FFFF = 0xFFFFFFFF # For some ui4 fields
SF8_NO_ENTRY_NEG1_0 = -1.0 # For some sf8 fields like filter settings
SF8_NO_ENTRY_NAN = float('nan') # For fields like max/min native sample value
# Access Levels & Encryption Flags
LEVEL_0_ACCESS = 0
LEVEL_1_ACCESS = 1
LEVEL_2_ACCESS = 2
NO_ENCRYPTION = 0
LEVEL_1_ENCRYPTION = 1
LEVEL_2_ENCRYPTION = 2


# CRC Table from meflib.h (CRC_KOOPMAN32_KEY)
CRC_KOOPMAN32_TABLE = (
    0x00000000, 0x9695C4CA, 0xFB4839C9, 0x6DDDFD03, 0x20F3C3CF, 0xB6660705,
    0xDBBBFA06, 0x4D2E3ECC, 0x41E7879E, 0xD7724354, 0xBAAFBE57, 0x2C3A7A9D,
    0x61144451, 0xF781809B, 0x9A5C7D98, 0x0CC9B952, 0x83CF0F3C, 0x155ACBF6,
    0x788736F5, 0xEE12F23F, 0xA33CCCF3, 0x35A90839, 0x5874F53A, 0xCEE131F0,
    0xC22888A2, 0x54BD4C68, 0x3960B16B, 0xAFF575A1, 0xE2DB4B6D, 0x744E8FA7,
    0x199372A4, 0x8F06B66E, 0xD1FDAE25, 0x47686AEF, 0x2AB597EC, 0xBC205326,
    0xF10E6DEA, 0x679BA920, 0x0A465423, 0x9CD390E9, 0x901A29BB, 0x068FED71,
    0x6B521072, 0xFDC7D4B8, 0xB0E9EA74, 0x267C2EBE, 0x4BA1D3BD, 0xDD341777,
    0x5232A119, 0xC4A765D3, 0xA97A98D0, 0x3FEF5C1A, 0x72C162D6, 0xE454A61C,
    0x89895B1F, 0x1F1C9FD5, 0x13D52687, 0x8540E24D, 0xE89D1F4E, 0x7E08DB84,
    0x3326E548, 0xA5B32182, 0xC86EDC81, 0x5EFB184B, 0x7598EC17, 0xE30D28DD,
    0x8ED0D5DE, 0x18451114, 0x556B2FD8, 0xC3FEEB12, 0xAE231611, 0x38B6D2DB,
    0x347F6B89, 0xA2EAAF43, 0xCF375240, 0x59A2968A, 0x148CA846, 0x82196C8C,
    0xEFC4918F, 0x79515545, 0xF657E32B, 0x60C227E1, 0x0D1FDAE2, 0x9B8A1E28,
    0xD6A420E4, 0x4031E42E, 0x2DEC192D, 0xBB79DDE7, 0xB7B064B5, 0x2125A07F,
    0x4CF85D7C, 0xDA6D99B6, 0x9743A77A, 0x01D663B0, 0x6C0B9EB3, 0xFA9E5A79,
    0xA4654232, 0x32F086F8, 0x5F2D7BFB, 0xC9B8BF31, 0x849681FD, 0x12034537,
    0x7FDEB834, 0xE94B7CFE, 0xE582C5AC, 0x73170166, 0x1ECAFC65, 0x885F38AF,
    0xC5710663, 0x53E4C2A9, 0x3E393FAA, 0xA8ACFB60, 0x27AA4D0E, 0xB13F89C4,
    0xDCE274C7, 0x4A77B00D, 0x07598EC1, 0x91CC4A0B, 0xFC11B708, 0x6A8473C2,
    0x664DCA90, 0xF0D80E5A, 0x9D05F359, 0x0B903793, 0x46BE095F, 0xD02BCD95,
    0xBDF63096, 0x2B63F45C, 0xEB31D82E, 0x7DA41CE4, 0x1079E1E7, 0x86EC252D,
    0xCBC21BE1, 0x5D57DF2B, 0x308A2228, 0xA61FE6E2, 0xAAD65FB0, 0x3C439B7A,
    0x519E6679, 0xC70BA2B3, 0x8A259C7F, 0x1CB058B5, 0x716DA5B6, 0xE7F8617C,
    0x68FED712, 0xFE6B13D8, 0x93B6EEDB, 0x05232A11, 0x480D14DD, 0xDE98D017,
    0xB3452D14, 0x25D0E9DE, 0x2919508C, 0xBF8C9446, 0xD2516945, 0x44C4AD8F,
    0x09EA9343, 0x9F7F5789, 0xF2A2AA8A, 0x64376E40, 0x3ACC760B, 0xAC59B2C1,
    0xC1844FC2, 0x57118B08, 0x1A3FB5C4, 0x8CAA710E, 0xE1778C0D, 0x77E248C7,
    0x7B2BF195, 0xEDBE355F, 0x8063C85C, 0x16F60C96, 0x5BD8325A, 0xCD4DF690,
    0xA0900B93, 0x3605CF59, 0xB9037937, 0x2F96BDFD, 0x424B40FE, 0xD4DE8434,
    0x99F0BAF8, 0x0F657E32, 0x62B88331, 0xF42D47FB, 0xF8E4FEA9, 0x6E713A63,
    0x03ACC760, 0x953903AA, 0xD8173D66, 0x4E82F9AC, 0x235F04AF, 0xB5CAC065,
    0x9EA93439, 0x083CF0F3, 0x65E10DF0, 0xF374C93A, 0xBE5AF7F6, 0x28CF333C,
    0x4512CE3F, 0xD3870AF5, 0xDF4EB3A7, 0x49DB776D, 0x24068A6E, 0xB2934EA4,
    0xFFBD7068, 0x6928B4A2, 0x04F549A1, 0x92608D6B, 0x1D663B05, 0x8BF3FFCF,
    0xE62E02CC, 0x70BBC606, 0x3D95F8CA, 0xAB003C00, 0xC6DDC103, 0x504805C9,
    0x5C81BC9B, 0xCA147851, 0xA7C98552, 0x315C4198, 0x7C727F54, 0xEAE7BB9E,
    0x873A469D, 0x11AF8257, 0x4F549A1C, 0xD9C15ED6, 0xB41CA3D5, 0x2289671F,
    0x6FA759D3, 0xF9329D19, 0x94EF601A, 0x027AA4D0, 0x0EB31D82, 0x9826D948,
    0xF5FB244B, 0x636EE081, 0x2E40DE4D, 0xB8D51A87, 0xD508E784, 0x439D234E,
    0xCC9B9520, 0x5A0E51EA, 0x37D3ACE9, 0xA1466823, 0xEC6856EF, 0x7AFD9225,
    0x17206F26, 0x81B5ABEC, 0x8D7C12BE, 0x1BE9D674, 0x76342B77, 0xE0A1EFBD,
    0xAD8FD171, 0x3B1A15BB, 0x56C7E8B8, 0xC0522C72
)

class TimeSeriesMetadataSection2_:
    SIZE = 10752
    # Offsets relative to the start of Section 2's data bytes
    FIELD_DEFINITIONS = [
        ('channel_description_raw', '2048s', 0, 2048),  # utf8[511]
        ('session_description_raw', '2048s', 2048, 2048),  # utf8[511]
        ('recording_duration', '<q', 4096, 8),  # si8
        ('reference_description_raw', '2048s', 4104, 2048),  # utf8[511]
        ('acquisition_channel_number', '<q', 6152, 8),  # si8
        ('sampling_frequency', '<d', 6160, 8),  # sf8
        ('low_frequency_filter_setting', '<d', 6168, 8),  # sf8
        ('high_frequency_filter_setting', '<d', 6176, 8),  # sf8
        ('notch_filter_frequency_setting', '<d', 6184, 8),  # sf8
        ('ac_line_frequency', '<d', 6192, 8),  # sf8
        ('units_conversion_factor', '<d', 6200, 8),  # sf8
        ('units_description_raw', '128s', 6208, 128),  # utf8[31]
        ('maximum_native_sample_value', '<d', 6336, 8),  # sf8
        ('minimum_native_sample_value', '<d', 6344, 8),  # sf8
        ('start_sample', '<q', 6352, 8),  # si8
        ('number_of_samples', '<q', 6360, 8),  # si8
        ('number_of_blocks', '<q', 6368, 8),  # si8
        ('maximum_block_bytes', '<q', 6376, 8),  # si8
        ('maximum_block_samples', '<I', 6384, 4),  # ui4
        ('maximum_difference_bytes', '<I', 6388, 4),  # ui4
        ('block_interval', '<q', 6392, 8),  # si8
        ('number_of_discontinuities', '<q', 6400, 8),  # si8
        ('maximum_contiguous_blocks', '<q', 6408, 8),  # si8
        ('maximum_contiguous_block_bytes', '<q', 6416, 8),  # si8
        ('maximum_contiguous_samples', '<q', 6424, 8),  # si8
        ('protected_region_raw', '2160s', 6432, 2160),
        ('discretionary_region_raw', '2160s', 8592, 2160)
    ]

    def __init__(self, section_bytes: bytes):
        if len(section_bytes) < self.SIZE:
            raise ValueError(f"TimeSeriesMetadataSection2 expects {self.SIZE} bytes, got {len(section_bytes)}")
        self._data_raw = {}
        self.parse(section_bytes)

    def parse(self, data_bytes: bytes):
        for name, fmt, offset, size in self.FIELD_DEFINITIONS:
            field_bytes = data_bytes[offset: offset + size]
            if 's' in fmt:
                self._data_raw[name] = field_bytes
            else:
                self._data_raw[name] = struct.unpack(fmt, field_bytes)[0]

    def _decode_utf8_field(self, field_name_raw):
        raw = self._data_raw.get(field_name_raw)
        return raw.split(b'\0', 1)[0].decode('utf-8', errors='replace') if raw else None

    def _encode_utf8_field(self, field_name_raw):
        raw = self._data_raw.get(field_name_raw)
        return raw.encode('utf-8') + b'\0' * (2048 - len(raw)) if raw else b'\0' * 2048

    @property
    def channel_description(self):
        return self._decode_utf8_field('channel_description_raw')

    @channel_description.setter
    def channel_description(self, value: str):
        if not isinstance(value, str):
            raise ValueError("Channel description must be a string.")

        if len(value) > 2048:
            raise ValueError("Channel description cannot exceed 2048 characters.")

        self._data_raw['channel_description_raw'] = value.encode('utf-8') + b'\0' * (2048 - len(value))

    @property
    def session_description(self):
        return self._decode_utf8_field('session_description_raw')

    @session_description.setter
    def session_description(self, value: str):
        if not isinstance(value, str):
            raise ValueError("Session description must be a string.")

        if len(value) > 2048:
            raise ValueError("Session description cannot exceed 2048 characters.")

        self._data_raw['session_description_raw'] = value.encode('utf-8') + b'\0' * (2048 - len(value))

    @property
    def recording_duration(self):
        return self._data_raw.get('recording_duration')

    @recording_duration.setter
    def recording_duration(self, value: int):
        if not isinstance(value, int):
            raise ValueError("Recording duration must be an integer.")

        if value < 0:
            raise ValueError("Recording duration cannot be negative.")

        self._data_raw['recording_duration'] = value

    @property
    def reference_description(self):
        return self._decode_utf8_field('reference_description_raw')

    @reference_description.setter
    def reference_description(self, value: str):
        if not isinstance(value, str):
            raise ValueError("Reference description must be a string.")

        if len(value) > 2048:
            raise ValueError("Reference description cannot exceed 2048 characters.")

        self._data_raw['reference_description_raw'] = value.encode('utf-8') + b'\0' * (2048 - len(value))

    @property
    def acquisition_channel_number(self):
        return self._data_raw.get('acquisition_channel_number')

    @acquisition_channel_number.setter
    def acquisition_channel_number(self, value: int):
        if not isinstance(value, int):
            raise ValueError("Acquisition channel number must be an integer.")

        if value < 0:
            raise ValueError("Acquisition channel number cannot be negative.")

        self._data_raw['acquisition_channel_number'] = value

    @property
    def sampling_frequency(self):
        return self._data_raw.get('sampling_frequency')

    @sampling_frequency.setter
    def sampling_frequency(self, value: float):
        if not isinstance(value, (int, float)):
            raise ValueError("Sampling frequency must be a number.")

        if value <= 0:
            raise ValueError("Sampling frequency must be positive.")

        self._data_raw['sampling_frequency'] = value

    @property
    def units_description(self):
        return self._decode_utf8_field('units_description_raw')

    @units_description.setter
    def units_description(self, value: str):
        if not isinstance(value, str):
            raise ValueError("Units description must be a string.")

        if len(value) > 128:
            raise ValueError("Units description cannot exceed 128 characters.")

        self._data_raw['units_description_raw'] = value.encode('utf-8') + b'\0' * (128 - len(value))

    def __str__(self):
        return (f"  TimeSeriesMetadataSection2: SamplingRate={self.sampling_frequency}, "
                f"Units='{self.units_description}', "
                f"ChannelDesc='{self.channel_description[:30]}...'")


class UniversalHeader_:
    def __init__(self, source_bytes: bytes = None, filepath: str = None):
        # Field definitions: (name, struct_format, offset, size_in_bytes)
        # Based on MEF 3 Specification.pdf pages 13-15
        self._fields_definition = [
            ('header_crc', '<I', 0, 4),
            ('body_crc', '<I', 4, 4),
            ('file_type_string_raw', '4s', 8, 4),  # Store raw bytes for file_type
            ('mef_version_major', '<B', 13, 1),
            ('mef_version_minor', '<B', 14, 1),
            ('byte_order_code', '<B', 15, 1),
            ('start_time', '<q', 16, 8),
            ('end_time', '<q', 24, 8),
            ('number_of_entries', '<q', 32, 8),
            ('maximum_entry_size', '<q', 40, 8),
            ('segment_number', '<i', 48, 4),
            ('channel_name_raw', '256s', 52, 256),
            ('session_name_raw', '256s', 308, 256),
            ('anonymized_name_raw', '256s', 564, 256),
            ('level_UUID_raw', '16s', 820, 16),
            ('file_UUID_raw', '16s', 836, 16),
            ('provenance_UUID_raw', '16s', 852, 16),
            ('level_1_password_validation_field_raw', '16s', 868, 16),
            ('level_2_password_validation_field_raw', '16s', 884, 16),
            ('protected_region_raw', '60s', 900, 60),
            ('discretionary_region_raw', '64s', 960, 64)
        ]
        self._data_raw = {}  # To store raw unpacked values
        self.is_crc_valid = None

        self.encryption_handler = EncryptionHandler()

        if filepath:
            try:
                with open(filepath, 'rb') as f:
                    source_bytes = f.read(UNIVERSAL_HEADER_BYTES)
            except FileNotFoundError:
                raise FileNotFoundError(f"Error: File '{filepath}' not found.")
            except Exception as e:
                raise IOError(f"Error reading Universal Header from '{filepath}': {e}")

        if source_bytes:
            if len(source_bytes) < UNIVERSAL_HEADER_BYTES:
                raise ValueError(
                    f"Data provided is too short for Universal Header. Expected {UNIVERSAL_HEADER_BYTES}, got {len(source_bytes)}.")
            self.parse(source_bytes)

        print('KOKOOOOOOOOOOT', source_bytes.__len__())

    def parse(self, data_bytes: bytes):
        for name, fmt, offset, size in self._fields_definition:
            field_bytes = data_bytes[offset: offset + size]
            # Store raw unpacked value, special handling for strings will be properties
            if 's' in fmt:  # Store byte strings directly
                self._data_raw[name] = field_bytes
            else:
                self._data_raw[name] = struct.unpack(fmt, field_bytes)[0]

        self._validate_header_crc(data_bytes)

    def _validate_header_crc(self, full_header_bytes: bytes):
        if 'header_crc' not in self._data_raw:
            self.is_crc_valid = False
            return

        stored_crc = self._data_raw['header_crc']
        bytes_for_crc = full_header_bytes[4:UNIVERSAL_HEADER_BYTES]
        calculated_crc = calculate_mef_crc32(bytes_for_crc, CRC_START_VALUE)
        self.is_crc_valid = (stored_crc == calculated_crc)

    # --- Properties to access parsed fields with nice formatting ---
    @property
    def header_crc(self):
        return self._data_raw.get('header_crc')

    @property
    def body_crc(self):
        return self._data_raw.get('body_crc')

    @property
    def file_type_string(self):
        raw = self._data_raw.get('file_type_string_raw')
        return raw.decode('ascii', errors='replace').rstrip('\x00') if raw else None

    @property
    def mef_version_major(self):
        return self._data_raw.get('mef_version_major')

    @property
    def mef_version_minor(self):
        return self._data_raw.get('mef_version_minor')

    @property
    def byte_order_code(self):
        return self._data_raw.get('byte_order_code')

    @property
    def start_time(self):
        return self._data_raw.get('start_time')

    @property
    def end_time(self):
        return self._data_raw.get('end_time')

    @property
    def number_of_entries(self):
        return self._data_raw.get('number_of_entries')

    @property
    def maximum_entry_size(self):
        return self._data_raw.get('maximum_entry_size')

    @property
    def segment_number(self):
        return self._data_raw.get('segment_number')

    @property
    def channel_name(self):
        raw = self._data_raw.get('channel_name_raw')
        return raw.split(b'\0', 1)[0].decode('utf-8', errors='replace') if raw else None

    @property
    def session_name(self):
        raw = self._data_raw.get('session_name_raw')
        return raw.split(b'\0', 1)[0].decode('utf-8', errors='replace') if raw else None

    @property
    def anonymized_name(self):
        raw = self._data_raw.get('anonymized_name_raw')
        return raw.split(b'\0', 1)[0].decode('utf-8', errors='replace') if raw else None

    @property
    def level_UUID(self):
        raw = self._data_raw.get('level_UUID_raw')
        return raw.hex() if raw else None

    @property
    def file_UUID(self):
        raw = self._data_raw.get('file_UUID_raw')
        return raw.hex() if raw else None

    @property
    def provenance_UUID(self):
        raw = self._data_raw.get('provenance_UUID_raw')
        return raw.hex() if raw else None

    @property
    def level_1_password_validation_field(self):  # Returns as hex string
        raw = self._data_raw.get('level_1_password_validation_field_raw')
        return raw.hex() if raw else None

    @property
    def level_1_password_validation_field_bytes(self):  # Returns raw bytes
        return self._data_raw.get('level_1_password_validation_field_raw')

    @property
    def level_2_password_validation_field(self):  # Returns as hex string
        raw = self._data_raw.get('level_2_password_validation_field_raw')
        return raw.hex() if raw else None

    @property
    def level_2_password_validation_field_bytes(self):  # Returns raw bytes
        return self._data_raw.get('level_2_password_validation_field_raw')

    @property
    def protected_region(self):
        raw = self._data_raw.get('protected_region_raw')
        return raw.hex() if raw else None  # Or return raw bytes: self._data_raw.get('protected_region_raw')

    @property
    def discretionary_region(self):
        raw = self._data_raw.get('discretionary_region_raw')
        return raw.hex() if raw else None  # Or return raw bytes: self._data_raw.get('discretionary_region_raw')

    def check_password(self, user_password_str: str):
        """
        Validates the provided user password against this Universal Header's
        validation fields using the provided EncryptionHandler.
        """
        if not self._data_raw:
            raise ValueError("UniversalHeader has not been parsed. Load data first.")
        return self.encryption_handler.validate_password_and_derive_keys(user_password_str, self)

    def __str__(self):
        lines = ["UniversalHeader:"]
        if not self._data_raw:
            return "UniversalHeader: (empty)"

        # Use properties for nice output
        lines.append(f"  Header CRC: 0x{self.header_crc:08X}" if self.header_crc is not None else "  Header CRC: None")
        lines.append(f"  Body CRC: 0x{self.body_crc:08X}" if self.body_crc is not None else "  Body CRC: None")
        lines.append(f"  File Type String: {self.file_type_string}")
        lines.append(f"  MEF Version: {self.mef_version_major}.{self.mef_version_minor}")
        lines.append(
            f"  Byte Order Code: {self.byte_order_code} ({'Little Endian' if self.byte_order_code == 1 else 'Big Endian' if self.byte_order_code == 0 else 'Unknown'})")
        lines.append(
            f"  Start Time: {self.start_time} (0x{self.start_time:X})" if self.start_time is not None else " Start Time: None")
        lines.append(
            f"  End Time: {self.end_time} (0x{self.end_time:X})" if self.end_time is not None else " End Time: None")
        lines.append(f"  Number of Entries: {self.number_of_entries}")
        lines.append(f"  Maximum Entry Size: {self.maximum_entry_size}")
        lines.append(f"  Segment Number: {self.segment_number}")
        lines.append(f"  Channel Name: {self.channel_name}")
        lines.append(f"  Session Name: {self.session_name}")
        lines.append(f"  Anonymized Name: {self.anonymized_name}")
        lines.append(f"  Level UUID: {self.level_UUID}")
        lines.append(f"  File UUID: {self.file_UUID}")
        lines.append(f"  Provenance UUID: {self.provenance_UUID}")
        lines.append(f"  L1 Password Validation: {self.level_1_password_validation_field}")
        lines.append(f"  L2 Password Validation: {self.level_2_password_validation_field}")
        lines.append(f"  Header CRC Valid: {self.is_crc_valid}")
        return "\n".join(lines)

    def is_password_protected(self) -> bool:
        """
        Checks if the Universal Header indicates that password protection
        (Level 1 or Level 2 via validation fields) is active.
        Returns True if either L1 or L2 validation field is non-zero.
        """
        if not self._data_raw:
            # If called before parsing, we can't know.
            # Alternatively, if _raw_bytes is available, parse them first.
            if self._raw_bytes:
                self.parse(self._raw_bytes)
            else:
                raise ValueError("UniversalHeader has no data loaded to check password protection status.")

        l1_val_bytes = self.level_1_password_validation_field_bytes
        l2_val_bytes = self.level_2_password_validation_field_bytes

        is_l1_zero = all(b == 0 for b in l1_val_bytes)
        is_l2_zero = all(b == 0 for b in l2_val_bytes)

        return not (is_l1_zero and is_l2_zero)  # Protected if NOT BOTH are zero


def calculate_mef_crc32(data_bytes, initial_crc=CRC_START_VALUE):
    current_crc = initial_crc
    for byte_val in data_bytes:
        tmp = (current_crc ^ byte_val) & 0xFF
        current_crc = (current_crc >> 8) ^ CRC_KOOPMAN32_TABLE[tmp]
    return current_crc


class HeaderABC:
    SIZE = 0  # To be defined by subclass
    # Each tuple: (prop_name, raw_key, struct_fmt, offset, size, is_utf8)
    FIELD_DEFINITIONS = []

    def __init__(self, data_bytes: bytes = None, create_new: bool = False):
        self._data_raw = {}  # Stores raw byte representation of each field
        self._initialized_for_new = create_new

        if create_new:
            self._initialize_new_raw_data()
        elif data_bytes:
            if len(data_bytes) != self.SIZE:  # Use self.SIZE defined by subclass
                raise ValueError(
                    f"{self.__class__.__name__} expects {self.SIZE} bytes for initialization, "
                    f"got {len(data_bytes)}"
                )
            self._parse_into_raw_data(data_bytes)
        elif self.SIZE > 0:  # If not creating new and no data_bytes, but SIZE is defined
            raise ValueError(f"{self.__class__.__name__} requires data_bytes or create_new=True if SIZE > 0")

        self._make_properties()

    def _initialize_new_raw_data(self):
        """
        Populates _data_raw with default byte values.
        Subclasses should override to set meaningful MEF defaults.
        """
        for _, raw_key, fmt, _, size, _ in self.FIELD_DEFINITIONS:
            # Basic default: null bytes for strings, packed zeros for numbers
            if 's' in fmt:
                self._data_raw[raw_key] = b'\0' * size
            else:
                # Pack a zero of the appropriate type
                try:
                    if fmt.lower() in ['<q', '<Q']:  # 64-bit int
                        self._data_raw[raw_key] = struct.pack(fmt, 0)
                    elif fmt.lower() in ['<i', '<I', '<l', '<L']:  # 32-bit int
                        self._data_raw[raw_key] = struct.pack(fmt, 0)
                    elif fmt.lower() in ['<h', '<H']:  # 16-bit int
                        self._data_raw[raw_key] = struct.pack(fmt, 0)
                    elif fmt.lower() in ['<b', '<B']:  # 8-bit int
                        self._data_raw[raw_key] = struct.pack(fmt, 0)
                    elif fmt.lower() in ['<f', '<d']:  # float/double
                        self._data_raw[raw_key] = struct.pack(fmt, 0.0)
                    else:
                        self._data_raw[raw_key] = b'\0' * size  # Fallback
                except struct.error:
                    self._data_raw[raw_key] = b'\0' * size  # Fallback if packing zero fails for some format

    def _parse_into_raw_data(self, data_bytes: bytes):
        """Parses section_bytes and stores raw bytes for each field in _data_raw."""
        for _, raw_key, _, offset, size, _ in self.FIELD_DEFINITIONS:
            self._data_raw[raw_key] = data_bytes[offset: offset + size]

    def _make_properties(self):
        class_flag = f'_properties_made_for_{self.__class__.__name__}'
        if hasattr(self.__class__, class_flag):
            return

        for prop_name, raw_key, fmt, _, size, type_hint in self.FIELD_DEFINITIONS:  # Changed 'is_utf8' to 'type_hint'

            # Create getter
            def _create_getter(r_key_local, s_fmt_local, s_type_hint_local):  # Use local names to avoid closure issues
                def getter_method(obj_self):
                    raw_bytes = obj_self._data_raw.get(r_key_local)
                    if raw_bytes is None:
                        return None
                    if 's' in s_fmt_local:  # Field is defined as a byte string type (e.g., '16s', '256s')
                        if s_type_hint_local == 'hex':
                            return raw_bytes.hex()
                        elif s_type_hint_local == 'utf8':
                            return raw_bytes.split(b'\0', 1)[0].decode('utf-8', errors='replace')
                        elif s_type_hint_local == 'ascii':
                            return raw_bytes.split(b'\0', 1)[0].decode('ascii', errors='replace')
                        else:  # Default for 'Ns' if no specific type hint, or hint is False/None for raw bytes
                            return raw_bytes.decode('utf-8', errors='replace').replace('\x00', '')  # Return str
                    else:  # Numerical type
                        return struct.unpack(s_fmt_local, raw_bytes)[0]

                return getter_method

            # Create setter (ensure its parameters also use distinct local names if issues arise)
            def _create_setter(p_name_local, r_key_local, s_fmt_local, s_size_local, s_type_hint_local):
                def setter_method(obj_self, value):
                    packed_value = b''
                    if 's' in s_fmt_local:  # Field is defined as a byte string type (e.g., '256s')
                        if s_type_hint_local == 'hex':
                            if not isinstance(value, str):
                                raise TypeError(
                                    f"Property '{p_name_local}' expects a hex string for 'hex' type, got {type(value)}")
                            if len(value) != s_size_local * 2:  # Hex string is twice the byte size
                                raise ValueError(
                                    f"Property '{p_name_local}' hex string length is incorrect. "
                                    f"Expected {s_size_local * 2}, got {len(value)}"
                                )
                            try:
                                packed_value = bytes.fromhex(value)
                            except ValueError as e_hex:
                                raise ValueError(f"Invalid hex string for '{p_name_local}': '{value}'. Error: {e_hex}")

                        elif s_type_hint_local in ['utf8', 'ascii']:  # Defined string types
                            if not isinstance(value, str):
                                raise TypeError(f"Property '{p_name_local}' expects a string, got {type(value)}")
                            encoding = 'utf-8' if s_type_hint_local == 'utf8' else 'ascii'
                            try:
                                encoded_value = value.encode(encoding)  # Do not use errors='replace' by default
                            except UnicodeEncodeError as e_enc:
                                raise ValueError(
                                    f"Error encoding string for '{p_name_local}' to {encoding}: {value}. Error: {e_enc}")

                            # Pad with nulls to the right, or truncate if too long
                            packed_value = encoded_value.ljust(s_size_local, b'\0')[:s_size_local]

                        else:  # Default case for 'Ns' if type_hint is False, None, or unrecognized for strings
                            # This case should ideally not be hit if FIELD_DEFINITIONS is well-defined.
                            # If it's meant to store raw bytes directly via a property, the property should accept bytes.
                            # For now, let's assume if 's' is in fmt, and it's not hex/utf8/ascii, it implies a user error
                            # or a need for a more specific type hint.
                            # To make it accept strings and store them as ascii by default for unknown 's' formats:
                            if isinstance(value, str):
                                encoded_value = value.encode('ascii', errors='ignore')  # Or 'replace'
                                packed_value = encoded_value.ljust(s_size_local, b'\0')[:s_size_local]
                            elif isinstance(value, bytes):  # Allow setting raw bytes if no clear string type
                                packed_value = value.ljust(s_size_local, b'\0')[:s_size_local]
                            else:
                                raise TypeError(
                                    f"Property '{p_name_local}' with format '{s_fmt_local}' "
                                    f"expects a string or bytes, got {type(value)}"
                                )

                    else:  # Numerical type
                        try:
                            packed_value = struct.pack(s_fmt_local, value)
                        except struct.error as e:
                            raise ValueError(
                                f"Error packing value '{value}' for '{p_name_local}' with format '{s_fmt_local}': {e}")

                    if len(packed_value) != s_size_local:
                        # This check is crucial, especially after packing/padding.
                        raise ValueError(
                            f"Internal error: Final packed/padded size for '{p_name_local}' is {len(packed_value)}, expected {s_size_local}")
                    obj_self._data_raw[r_key_local] = packed_value  # Store the processed bytes

                return setter_method

            setattr(self.__class__, prop_name, property(
                _create_getter(raw_key, fmt, type_hint),  # Pass the type_hint
                _create_setter(prop_name, raw_key, fmt, size, type_hint)
            ))
        setattr(self.__class__, class_flag, True)

    def to_bytes(self) -> bytes:
        if not self._data_raw and self.SIZE > 0 and not self._initialized_for_new:
            raise ValueError(
                f"_data_raw is empty for {self.__class__.__name__}. Call parse() or initialize with create_new=True.")

        buffer = bytearray(self.SIZE)
        for _, raw_key, _, offset, size, _ in self.FIELD_DEFINITIONS:
            raw_bytes_val = self._data_raw.get(raw_key)
            if raw_bytes_val is None:
                # This indicates an issue with initialization if creating new,
                # or that FIELD_DEFINITIONS doesn't match _data_raw content.
                raise ValueError(
                    f"Field '{raw_key}' not found in _data_raw during serialization for {self.__class__.__name__}.")

            # Ensure the raw_bytes_val is correctly sized before placing in buffer
            # This should be guaranteed if setters/initializers are correct.
            if len(raw_bytes_val) != size:
                print(
                    f"Warning: Size mismatch for {raw_key} in {self.__class__.__name__}. Expected {size}, got {len(raw_bytes_val)}. Will use as is or truncate.")
                # This might indicate an issue if not a variable length string that was pre-padded

            buffer[offset: offset + size] = raw_bytes_val[:size]  # Truncate if somehow larger, though should match
        return bytes(buffer)

    @property
    def data(self) -> dict:
        """Returns a dictionary of all fields converted to their Python data types."""
        parsed_dict = {}
        for prop_name, _, _, _, _, _ in self.FIELD_DEFINITIONS:
            # This will call the dynamically created getter for each property
            parsed_dict[prop_name] = getattr(self, prop_name)
        return parsed_dict

    def update(self, update_dict: dict):
        """Updates fields from a dictionary of Python-typed values using setters."""
        allowed_prop_names = {defn[0] for defn in self.FIELD_DEFINITIONS}
        for prop_name, value in update_dict.items():
            if prop_name not in allowed_prop_names:
                raise KeyError(f"Field '{prop_name}' is not an allowable property for {self.__class__.__name__}.")
            setattr(self, prop_name, value)  # This will call the dynamically created setter


class EncryptionHandler:
    def __init__(self):
        """
        Handler for MEF 3 cryptographic operations.
        """
        pass

    def _extract_terminal_password_bytes(self, password_str: str) -> bytes:
        """
        Converts a UTF-8 password string to a 16-byte sequence by taking
        the terminal byte of each UTF-8 character. Pads with zeros.
        Corresponds to C function extract_terminal_password_bytes.
        """
        if not password_str:  # Handle empty string password gracefully
            return b'\0' * PASSWORD_BYTES

        password_bytes_list = []
        utf8_encoded_password = password_str.encode('utf-8')

        i = 0
        char_count = 0
        while i < len(utf8_encoded_password) and char_count < PASSWORD_BYTES:
            byte = utf8_encoded_password[i]
            # Determine how many bytes this UTF-8 character occupies
            if (byte & 0b10000000) == 0b00000000:  # 1-byte char (0xxxxxxx)
                char_len = 1
            elif (byte & 0b11100000) == 0b11000000:  # 2-byte char (110xxxxx)
                char_len = 2
            elif (byte & 0b11110000) == 0b11100000:  # 3-byte char (1110xxxx)
                char_len = 3
            elif (byte & 0b11111000) == 0b11110000:  # 4-byte char (11110xxx)
                char_len = 4
            else:  # Should not happen with valid UTF-8
                raise ValueError("Invalid UTF-8 start byte")

            if i + char_len > len(utf8_encoded_password):
                raise ValueError("Incomplete UTF-8 character at end of password string")

            # The terminal byte is the last byte of the multi-byte sequence
            terminal_byte = utf8_encoded_password[i + char_len - 1]
            password_bytes_list.append(terminal_byte)
            i += char_len
            char_count += 1

        # Pad with zeros if fewer than PASSWORD_BYTES characters
        processed_bytes = bytes(password_bytes_list)
        if len(processed_bytes) < PASSWORD_BYTES:
            processed_bytes += b'\0' * (PASSWORD_BYTES - len(processed_bytes))

        return processed_bytes[:PASSWORD_BYTES]  # Ensure it's exactly PASSWORD_BYTES

    def validate_password_and_derive_keys(self, user_password_str: str, universal_header: 'UniversalHeader'):
        """
        Validates the user's password against the Universal Header's validation fields
        and derives AES keys.

        Args:
            user_password_str: The plain-text UTF-8 password from the user.
            universal_header: An instance of the UniversalHeader class (or an object
                              with .level_1_password_validation_field and
                              .level_2_password_validation_field attributes as bytes).

        Returns:
            A dictionary:
            {
                'access_level': int (0, 1, or 2),
                'level1_key_bytes': 16-byte AES key for Level 1 or None,
                'level2_key_bytes': 16-byte AES key for Level 2 or None
            }
        """
        if user_password_str is None or user_password_str == "":
            # Check if file is unencrypted based on validation fields being zero
            l1_val_field_bytes = bytes.fromhex(universal_header.level_1_password_validation_field)
            l2_val_field_bytes = bytes.fromhex(universal_header.level_2_password_validation_field)
            if all(b == 0 for b in l1_val_field_bytes) and \
                    all(b == 0 for b in l2_val_field_bytes):
                return {'access_level': LEVEL_0_ACCESS, 'level1_key_bytes': None, 'level2_key_bytes': None}
            else:  # File has passwords set, but none provided by user
                return {'access_level': LEVEL_0_ACCESS, 'level1_key_bytes': None, 'level2_key_bytes': None}

        user_processed_key_bytes = self._extract_terminal_password_bytes(user_password_str)

        # SHA-256 hash of the processed user password
        sha256_user_key = hashlib.sha256(user_processed_key_bytes).digest()

        # --- Level 1 Check ---
        uh_l1_validation_bytes = bytes.fromhex(universal_header.level_1_password_validation_field)

        if sha256_user_key[:PASSWORD_VALIDATION_FIELD_BYTES] == uh_l1_validation_bytes:
            return {
                'access_level': LEVEL_1_ACCESS,
                'level1_key_bytes': user_processed_key_bytes,
                'level2_key_bytes': None
            }

        # --- Level 2 Check ---
        # L2_Validation_Field = (SHA256(L2_pass_bytes)[0:16]) XOR (L1_pass_bytes)
        # So, L1_pass_bytes = (SHA256(L2_pass_bytes)[0:16]) XOR L2_Validation_Field
        uh_l2_validation_bytes = bytes.fromhex(universal_header.level_2_password_validation_field)

        putative_l1_key_bytes_list = []
        for i in range(PASSWORD_VALIDATION_FIELD_BYTES):
            putative_l1_key_bytes_list.append(sha256_user_key[i] ^ uh_l2_validation_bytes[i])
        putative_l1_key_bytes = bytes(putative_l1_key_bytes_list)

        sha256_putative_l1_key = hashlib.sha256(putative_l1_key_bytes).digest()

        if sha256_putative_l1_key[:PASSWORD_VALIDATION_FIELD_BYTES] == uh_l1_validation_bytes:
            return {
                'access_level': LEVEL_2_ACCESS,
                'level1_key_bytes': putative_l1_key_bytes,  # This is the derived L1 key
                'level2_key_bytes': user_processed_key_bytes  # This is the L2 key (from user's input)
            }

        # If neither matched
        return {'access_level': LEVEL_0_ACCESS, 'level1_key_bytes': None, 'level2_key_bytes': None}

    def aes_encrypt(self, data_bytes: bytes, key_bytes: bytes) -> bytes:
        """
        Encrypts data using AES-128 ECB mode.
        Data must be a multiple of 16 bytes.
        """
        if len(data_bytes) % 16 != 0:
            raise ValueError("Data length for AES encryption must be a multiple of 16 bytes.")
        if len(key_bytes) != 16:
            raise ValueError("AES key must be 16 bytes.")

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data_bytes) + encryptor.finalize()

    def aes_decrypt(self, encrypted_bytes: bytes, key_bytes: bytes) -> bytes:
        """
        Decrypts data using AES-128 ECB mode.
        """
        if len(encrypted_bytes) % 16 != 0:
            raise ValueError("Encrypted data length for AES decryption must be a multiple of 16 bytes.")
        if len(key_bytes) != 16:
            raise ValueError("AES key must be 16 bytes.")

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_bytes) + decryptor.finalize()


# --- UniversalHeader inheriting from HeaderABC ---
class UniversalHeader(HeaderABC):
    SIZE = UNIVERSAL_HEADER_BYTES
    # (prop_name, raw_key, struct_fmt, offset, size, is_utf8_or_hex_or_ascii)
    # 'hex' for properties that should return hex strings for byte arrays
    # 'utf8' for UTF-8 strings
    # 'ascii' for ASCII strings
    # False or None for numerical or uninterpreted byte strings
    FIELD_DEFINITIONS = [
        ('header_crc', 'header_crc_raw', '<I', 0, 4, False),
        ('body_crc', 'body_crc_raw', '<I', 4, 4, False),
        ('file_type_string', 'file_type_string_raw', '5s', 8, 5, 'ascii'),  # MEF uses 4s + null, treat as 5s here
        ('mef_version_major', 'mef_version_major_raw', '<B', 13, 1, False),
        ('mef_version_minor', 'mef_version_minor_raw', '<B', 14, 1, False),
        ('byte_order_code', 'byte_order_code_raw', '<B', 15, 1, False),
        ('start_time', 'start_time_raw', '<q', 16, 8, False),
        ('end_time', 'end_time_raw', '<q', 24, 8, False),
        ('number_of_entries', 'number_of_entries_raw', '<q', 32, 8, False),
        ('maximum_entry_size', 'maximum_entry_size_raw', '<q', 40, 8, False),
        ('segment_number', 'segment_number_raw', '<i', 48, 4, False),
        ('channel_name', 'channel_name_raw', '256s', 52, 256, 'utf8'),
        ('session_name', 'session_name_raw', '256s', 308, 256, 'utf8'),
        ('anonymized_name', 'anonymized_name_raw', '256s', 564, 256, 'utf8'),
        ('level_UUID', 'level_UUID_raw', '16s', 820, 16, 'hex'),
        ('file_UUID', 'file_UUID_raw', '16s', 836, 16, 'hex'),
        ('provenance_UUID', 'provenance_UUID_raw', '16s', 852, 16, 'hex'),
        ('level_1_password_validation_field', 'level_1_password_validation_field_raw', '16s', 868, 16, 'hex'),
        ('level_2_password_validation_field', 'level_2_password_validation_field_raw', '16s', 884, 16, 'hex'),
        ('protected_region', 'protected_region_raw', '60s', 900, 60, 'hex'),  # Or just raw bytes
        ('discretionary_region', 'discretionary_region_raw', '64s', 960, 64, 'hex')  # Or just raw bytes
    ]

    def __init__(self, source_bytes: bytes = None, filepath: str = None, create_new: bool = False):
        self.encryption_handler = EncryptionHandler()
        self.is_crc_valid = None
        self._raw_bytes_for_crc_calc = None
        super().__init__(data_bytes=source_bytes, create_new=create_new)

        if source_bytes:
            self._raw_bytes_for_crc_calc = source_bytes[:UNIVERSAL_HEADER_BYTES]
            self._validate_header_crc()
        elif create_new:
            self._raw_bytes_for_crc_calc = self.to_bytes()  # For consistent CRC validation if called immediately
            self.is_crc_valid = None  # CRC is not yet meaningful for a new header

    def _initialize_new_raw_data(self):
        super()._initialize_new_raw_data()  # Base class initializes with packed zeros or empty bytes
        # Set MEF specific defaults by calling property setters
        self.mef_version_major = MEF_VERSION_MAJOR
        self.mef_version_minor = MEF_VERSION_MINOR
        self.byte_order_code = MEF_LITTLE_ENDIAN
        self.start_time = UUTC_NO_ENTRY
        self.end_time = UUTC_NO_ENTRY
        self.number_of_entries = -1
        self.maximum_entry_size = -1
        self.segment_number = -1  # Default "no entry" for segment number
        self.channel_name = ""
        self.session_name = ""
        self.anonymized_name = ""
        # UUIDs are raw bytes, setters expect hex string
        new_level_uuid = uuid.uuid4().bytes
        self.level_UUID = new_level_uuid.hex()  # Uses setter
        new_file_uuid = uuid.uuid4().bytes
        self.file_UUID = new_file_uuid.hex()  # Uses setter
        self.provenance_UUID = new_file_uuid.hex()  # Provenance is self for new files
        # Password validation fields default to zeros
        self.level_1_password_validation_field = ('00' * PASSWORD_VALIDATION_FIELD_BYTES)
        self.level_2_password_validation_field = ('00' * PASSWORD_VALIDATION_FIELD_BYTES)
        # Protected/Discretionary regions default to zeros
        self.protected_region = ('00' * 60)
        self.discretionary_region = ('00' * 64)
        self._initialized_for_new = True

    def _validate_header_crc(self):
        if self._raw_bytes_for_crc_calc is None:
            self.is_crc_valid = None
            return
        stored_crc_val = self.header_crc  # Access via property
        bytes_for_crc = self._raw_bytes_for_crc_calc[4:UNIVERSAL_HEADER_BYTES]
        calculated_crc = calculate_mef_crc32(bytes_for_crc)
        self.is_crc_valid = (stored_crc_val == calculated_crc)

    def update_header_crc(self):
        # Ensure _data_raw reflects all current property values before serializing for CRC
        # This happens naturally if setters update _data_raw with packed bytes
        current_header_bytes = self.to_bytes()
        bytes_for_crc = current_header_bytes[4:UNIVERSAL_HEADER_BYTES]
        new_crc = calculate_mef_crc32(bytes_for_crc)
        self.header_crc = new_crc  # Calls setter
        self._raw_bytes_for_crc_calc = self.to_bytes()  # Update the base for future validation
        self.is_crc_valid = True

    # Expose password validation field bytes for EncryptionHandler
    @property
    def level_1_password_validation_field_bytes(self):
        return self._data_raw.get('level_1_password_validation_field_raw', b'\0' * 16)

    @property
    def level_2_password_validation_field_bytes(self):
        return self._data_raw.get('level_2_password_validation_field_raw', b'\0' * 16)


    def set_password_validation_fields(self, level1_key_bytes: bytes = None, level2_key_bytes: bytes = None):
        handler = self.encryption_handler
        l1_val_field, l2_val_field = b'\0' * 16, b'\0' * 16
        if level1_key_bytes:
            if len(level1_key_bytes) != PASSWORD_BYTES: raise ValueError("L1 key bytes must be 16 bytes.")
            l1_hash = hashlib.sha256(level1_key_bytes).digest()
            l1_val_field = l1_hash[:PASSWORD_VALIDATION_FIELD_BYTES]
        if level2_key_bytes:
            if not level1_key_bytes: raise ValueError("L2 password requires L1 for validation field.")
            if len(level2_key_bytes) != PASSWORD_BYTES: raise ValueError("L2 key bytes must be 16 bytes.")
            l2_hash_16b = hashlib.sha256(level2_key_bytes).digest()[:PASSWORD_VALIDATION_FIELD_BYTES]
            l2_val_field = bytes([l2_hash_16b[i] ^ level1_key_bytes[i] for i in range(PASSWORD_VALIDATION_FIELD_BYTES)])

        self._data_raw['level_1_password_validation_field_raw'] = l1_val_field
        self._data_raw['level_2_password_validation_field_raw'] = l2_val_field


    def check_password(self, user_password_str: str):
        """
        Validates the provided user password against this Universal Header's
        validation fields using the provided EncryptionHandler.
        """
        if not self._data_raw:
            raise ValueError("UniversalHeader has not been parsed. Load data first.")
        return self.encryption_handler.validate_password_and_derive_keys(user_password_str, self)


    def is_password_protected(self) -> bool:
        """
        Checks if the Universal Header indicates that password protection
        (Level 1 or Level 2 via validation fields) is active.
        Returns True if either L1 or L2 validation field is non-zero.
        """
        if not self._data_raw:
            # If called before parsing, we can't know.
            # Alternatively, if _raw_bytes is available, parse them first.
            if self._raw_bytes:
                self.parse(self._raw_bytes)
            else:
                raise ValueError("UniversalHeader has no data loaded to check password protection status.")

        l1_val_bytes = self.level_1_password_validation_field_bytes
        l2_val_bytes = self.level_2_password_validation_field_bytes

        is_l1_zero = all(b == 0 for b in l1_val_bytes)
        is_l2_zero = all(b == 0 for b in l2_val_bytes)

        return not (is_l1_zero and is_l2_zero)  # Protected if NOT BOTH are zero


class MetadataSection1:
    SIZE = 1536
    # Offsets relative to the start of Section 1's data bytes
    FIELD_DEFINITIONS = [
        ('section2_encryption_level', '<b', 0, 1),  # si1
        ('section3_encryption_level', '<b', 1, 1),  # si1
        ('protected_region_raw', '766s', 2, 766),
        ('discretionary_region_raw', '768s', 768, 768)
    ]

    def __init__(self, section_bytes: bytes):
        if len(section_bytes) < self.SIZE:
            raise ValueError(f"MetadataSection1 expects {self.SIZE} bytes, got {len(section_bytes)}")
        self._data_raw = {}
        self.parse(section_bytes)

    def parse(self, data_bytes: bytes):
        for name, fmt, offset, size in self.FIELD_DEFINITIONS:
            field_bytes = data_bytes[offset: offset + size]
            if 's' in fmt:  # Raw byte fields
                self._data_raw[name] = field_bytes
            else:
                self._data_raw[name] = struct.unpack(fmt, field_bytes)[0]

    @property
    def section2_encryption_level(self):
        return self._data_raw.get('section2_encryption_level')

    @property
    def section3_encryption_level(self):
        return self._data_raw.get('section3_encryption_level')

    @property
    def protected_region(self):
        return self._data_raw.get('protected_region_raw', b'').hex()

    @property
    def discretionary_region(self):
        return self._data_raw.get('discretionary_region_raw', b'').hex()

    def __str__(self):
        return (f"  MetadataSection1: Sec2Enc={self.section2_encryption_level}, "
                f"Sec3Enc={self.section3_encryption_level}")


class TimeSeriesMetadataSection2(HeaderABC):
    SIZE = 10752
    # Field definitions: (prop_name, raw_key, struct_fmt, offset, size, is_utf8)
    FIELD_DEFINITIONS = [
        ('channel_description', 'channel_description_raw', '2048s', 0, 2048, True),
        ('session_description', 'session_description_raw', '2048s', 2048, 2048, True),
        ('recording_duration', 'recording_duration_raw', '<q', 4096, 8, False),
        ('reference_description', 'reference_description_raw', '2048s', 4104, 2048, True),
        ('acquisition_channel_number', 'acquisition_channel_number_raw', '<q', 6152, 8, False),
        ('sampling_frequency', 'sampling_frequency_raw', '<d', 6160, 8, False),
        ('low_frequency_filter_setting', 'low_frequency_filter_setting_raw', '<d', 6168, 8, False),
        ('high_frequency_filter_setting', 'high_frequency_filter_setting_raw', '<d', 6176, 8, False),
        ('notch_filter_frequency_setting', 'notch_filter_frequency_setting_raw', '<d', 6184, 8, False),
        ('ac_line_frequency', 'ac_line_frequency_raw', '<d', 6192, 8, False),
        ('units_conversion_factor', 'units_conversion_factor_raw', '<d', 6200, 8, False),
        ('units_description', 'units_description_raw', '128s', 6208, 128, True),
        ('maximum_native_sample_value', 'maximum_native_sample_value_raw', '<d', 6336, 8, False),
        ('minimum_native_sample_value', 'minimum_native_sample_value_raw', '<d', 6344, 8, False),
        ('start_sample', 'start_sample_raw', '<q', 6352, 8, False),
        ('number_of_samples', 'number_of_samples_raw', '<q', 6360, 8, False),
        ('number_of_blocks', 'number_of_blocks_raw', '<q', 6368, 8, False),
        ('maximum_block_bytes', 'maximum_block_bytes_raw', '<q', 6376, 8, False),
        ('maximum_block_samples', 'maximum_block_samples_raw', '<I', 6384, 4, False),
        ('maximum_difference_bytes', 'maximum_difference_bytes_raw', '<I', 6388, 4, False),
        ('block_interval', 'block_interval_raw', '<q', 6392, 8, False),
        ('number_of_discontinuities', 'number_of_discontinuities_raw', '<q', 6400, 8, False),
        ('maximum_contiguous_blocks', 'maximum_contiguous_blocks_raw', '<q', 6408, 8, False),
        ('maximum_contiguous_block_bytes', 'maximum_contiguous_block_bytes_raw', '<q', 6416, 8, False),
        ('maximum_contiguous_samples', 'maximum_contiguous_samples_raw', '<q', 6424, 8, False),
        ('protected_region', 'protected_region_raw', '2160s', 6432, 2160, False),  # Property might return hex
        ('discretionary_region', 'discretionary_region_raw', '2160s', 8592, 2160, False)  # Property might return hex
    ]

    def __init__(self, section_bytes: bytes = None, create_new: bool = False):
        super().__init__(data_bytes=section_bytes, create_new=create_new)
        # _make_properties is called by super().__init__

    def _initialize_new_raw_data(self):
        """Populates _data_raw with MEF default/no-entry values for TimeSeriesMetadataSection2."""
        super()._initialize_new_raw_data()  # Initialize with zeros/empty bytes from base

        # Override with specific MEF "no entry" values where applicable
        # This requires mapping property names to their default MEF values
        # For example:
        # self.sampling_frequency = -1.0 # Using the setter which updates _data_raw
        # self.channel_description = ""
        # ... and so on for all fields.
        # For simplicity in this example, I'm relying on the base zero-initialization.
        # A full implementation would set MEF-specific "no entry" values here.
        # For instance, if a field's "no entry" is -1 for an int, or -1.0 for a float:
        no_entry_values = {
            'recording_duration_raw': -1, 'acquisition_channel_number_raw': -1,
            'sampling_frequency_raw': -1.0, 'low_frequency_filter_setting_raw': -1.0,
            'high_frequency_filter_setting_raw': -1.0, 'notch_filter_frequency_setting_raw': -1.0,
            'ac_line_frequency_raw': -1.0, 'units_conversion_factor_raw': 0.0,
            'maximum_native_sample_value_raw': float('nan'),  # Or specific MEF NaN like value
            'minimum_native_sample_value_raw': float('nan'),
            'start_sample_raw': -1, 'number_of_samples_raw': -1, 'number_of_blocks_raw': -1,
            'maximum_block_bytes_raw': -1, 'maximum_block_samples_raw': 0xFFFFFFFF,
            'maximum_difference_bytes_raw': 0xFFFFFFFF, 'block_interval_raw': -1,
            'number_of_discontinuities_raw': -1, 'maximum_contiguous_blocks_raw': -1,
            'maximum_contiguous_block_bytes_raw': -1, 'maximum_contiguous_samples_raw': -1,
        }
        for prop, raw_key, fmt, _, size, _ in self.FIELD_DEFINITIONS:
            if raw_key in no_entry_values:
                # Pack the specific "no entry" value
                try:
                    self._data_raw[raw_key] = struct.pack(fmt, no_entry_values[raw_key])
                except struct.error:  # Handle NaN for floats if struct.pack fails
                    if 'd' in fmt or 'f' in fmt and no_entry_values[raw_key] != no_entry_values[
                        raw_key]:  # Check for NaN
                        # A common way to represent NaN in binary might be specific
                        # For now, packing as 0.0 if NaN packing fails. Ideally, use MEF spec.
                        # MEF uses specific bit patterns for NaN/inf in RED data,
                        # but sf8 "no entry" for sampling_frequency is -1.0. max/min native values can be NaN.
                        if prop == 'maximum_native_sample_value' or prop == 'minimum_native_sample_value':
                            # For sf8 NaN, all exponent bits set, fraction non-zero
                            # A common pattern for double: 0x7ff8000000000000 (or similar, varies)
                            # MEF Spec (p23) says "NaN indicates no entry" for these.
                            # This part needs careful handling of NaN representation if you need to write MEF NaN values.
                            # For now, just a placeholder:
                            self._data_raw[raw_key] = struct.pack(fmt, float('nan'))
                        else:
                            self._data_raw[raw_key] = struct.pack(fmt, 0.0)
                    else:
                        self._data_raw[raw_key] = struct.pack(fmt, 0)  # Fallback

        self._initialized_for_new = True

    # Manual properties are no longer needed if _make_properties in HeaderABC works correctly
    # The _decode_utf8_field helper can be used by the dynamically created getters if needed,
    # or its logic can be inlined.

    def __str__(self):
        # This can leverage the self.data property from HeaderABC
        # Or you can format specific important fields.
        data_dict = self.data
        return (f"  TimeSeriesMetadataSection2: SamplingRate={data_dict.get('sampling_frequency', 'N/A')}, "
                f"Units='{data_dict.get('units_description', 'N/A')}', "
                f"ChannelDesc='{data_dict.get('channel_description', '')[:30]}...'")


class MetadataSection3:
    SIZE = 3072
    # Offsets relative to the start of Section 3's data bytes
    FIELD_DEFINITIONS = [
        ('recording_time_offset', '<q', 0, 8),  # si8
        ('dst_start_time', '<q', 8, 8),  # si8
        ('dst_end_time', '<q', 16, 8),  # si8
        ('gmt_offset', '<i', 24, 4),  # si4
        ('subject_name_1_raw', '128s', 28, 128),  # utf8[31]
        ('subject_name_2_raw', '128s', 156, 128),  # utf8[31]
        ('subject_id_raw', '128s', 284, 128),  # utf8[31]
        ('recording_location_raw', '512s', 412, 512),  # utf8[127]
        ('protected_region_raw', '1124s', 924, 1124),
        ('discretionary_region_raw', '1024s', 2048, 1024)
    ]

    def __init__(self, section_bytes: bytes):
        if len(section_bytes) < self.SIZE:
            raise ValueError(f"MetadataSection3 expects {self.SIZE} bytes, got {len(section_bytes)}")
        self._data_raw = {}
        self.parse(section_bytes)

    def parse(self, data_bytes: bytes):
        for name, fmt, offset, size in self.FIELD_DEFINITIONS:
            field_bytes = data_bytes[offset: offset + size]
            if 's' in fmt:
                self._data_raw[name] = field_bytes
            else:
                self._data_raw[name] = struct.unpack(fmt, field_bytes)[0]

    def _decode_utf8_field(self, field_name_raw):
        raw = self._data_raw.get(field_name_raw)
        return raw.split(b'\0', 1)[0].decode('utf-8', errors='replace') if raw else None

    @property
    def recording_time_offset(self):
        return self._data_raw.get('recording_time_offset')

    @property
    def dst_start_time(self):
        return self._data_raw.get('dst_start_time')

    @property
    def dst_end_time(self):
        return self._data_raw.get('dst_end_time')

    @property
    def gmt_offset(self):
        return self._data_raw.get('gmt_offset')

    @property
    def subject_name_1(self):
        return self._decode_utf8_field('subject_name_1_raw')

    @property
    def subject_name_2(self):
        return self._decode_utf8_field('subject_name_2_raw')

    @property
    def subject_id(self):
        return self._decode_utf8_field('subject_id_raw')

    @property
    def recording_location(self):
        return self._decode_utf8_field('recording_location_raw')

    # Add other properties as needed...

    def __str__(self):
        return (f"  MetadataSection3: RTO={self.recording_time_offset}, GMT_Offset={self.gmt_offset}, "
                f"SubjectID='{self.subject_id}'")


class TimeSeriesMetadataFile:
    FILE_SIZE = 16384  # 16KB
    # Offsets for sections within the 16KB file data
    UH_OFFSET = 0
    UH_SIZE = UNIVERSAL_HEADER_BYTES

    SECTION1_FILE_OFFSET = UH_OFFSET + UH_SIZE
    SECTION1_SIZE = MetadataSection1.SIZE

    SECTION2_FILE_OFFSET = SECTION1_FILE_OFFSET + SECTION1_SIZE
    SECTION2_SIZE = TimeSeriesMetadataSection2.SIZE

    SECTION3_FILE_OFFSET = SECTION2_FILE_OFFSET + SECTION2_SIZE
    SECTION3_SIZE = MetadataSection3.SIZE

    def __init__(self, filepath: str = None, password = None):
        self.filepath = filepath
        self._password = password

        self.universal_header_bytes = None
        self.universal_header: UniversalHeader = None

        self.section1_bytes = None
        self.section1: MetadataSection1 = None
        self.pwd_check = None  # Access level derived from password validation

        self.section2_bytes = None
        self.section2: TimeSeriesMetadataSection2 = None  # Specific to Time Series

        self.section3_bytes = None
        self.section3: MetadataSection3 = None

        self._load_from_file()
        self._parse_universal_header()

        self._parse_metadata()

    def _load_from_file(self):
        try:
            with open(self.filepath, 'rb') as f:
                self._raw_data = f.read(self.FILE_SIZE)
        except FileNotFoundError:
            raise FileNotFoundError(f"Error: File '{self.filepath}' not found.")
        except Exception as e:
            raise IOError(f"Error reading file '{self.filepath}': {e}")

        if len(self._raw_data) < self.FILE_SIZE:
            raise ValueError(
                f"File '{self.filepath}' is too short. Expected {self.FILE_SIZE}, got {len(self._raw_data)}.")

        self.universal_header_bytes = self._raw_data[self.UH_OFFSET:self.UH_SIZE+self.UH_OFFSET]
        self.section1_bytes = self._raw_data[self.SECTION1_FILE_OFFSET: self.SECTION1_FILE_OFFSET + self.SECTION1_SIZE]
        self.section2_bytes = self._raw_data[self.SECTION2_FILE_OFFSET: self.SECTION2_FILE_OFFSET + self.SECTION2_SIZE]
        self.section3_bytes = self._raw_data[self.SECTION3_FILE_OFFSET: self.SECTION3_FILE_OFFSET + self.SECTION3_SIZE]


    def _parse_universal_header(self):
        self.universal_header = UniversalHeader(source_bytes=self.universal_header_bytes)

        if not self.universal_header.is_crc_valid:
            raise ValueError(f"Universal Header CRC validation failed for file '{self.filepath}'.")

        if self._password is None and self.universal_header.is_password_protected():
            raise ValueError(f"File '{self.filepath}' is password protected. Cannot parse without a password.")

        if self.universal_header.is_password_protected():
            if self._password is None:
                raise ValueError(f"File '{self.filepath}' is password protected. Cannot parse without a password.")
            # Validate the password and derive keys
            self.pwd_check = self.universal_header.encryption_handler.validate_password_and_derive_keys(
                self._password, self.universal_header
            )

            if self.pwd_check['access_level'] == LEVEL_0_ACCESS:
                raise ValueError(f"Invalid password for file '{self.filepath}'. Access denied.")

    def _parse_metadata(self):
        # Get raw byte chunks for each section directly from _raw_data
        raw_s1_bytes = self._raw_data[self.SECTION1_FILE_OFFSET: self.SECTION1_FILE_OFFSET + self.SECTION1_SIZE]
        raw_s2_bytes = self._raw_data[self.SECTION2_FILE_OFFSET: self.SECTION2_FILE_OFFSET + self.SECTION2_SIZE]
        raw_s3_bytes = self._raw_data[self.SECTION3_FILE_OFFSET: self.SECTION3_FILE_OFFSET + self.SECTION3_SIZE]

        # 1. Parse Section 1 (it's never encrypted itself)
        self.section1 = MetadataSection1(raw_s1_bytes)

        # Bytes to be parsed for S2 and S3, initially raw, potentially decrypted below
        s2_bytes_to_parse = raw_s2_bytes
        s3_bytes_to_parse = raw_s3_bytes

        # Check if password validation was successful and keys are available
        if self.pwd_check and self.pwd_check['access_level'] > LEVEL_0_ACCESS:
            handler = self.universal_header.encryption_handler  # Get the handler instance

            # 2. Decrypt Section 2 if necessary
            s2_enc_flag = self.section1.section2_encryption_level
            if s2_enc_flag == 1:  # Level 1 Encrypted
                if self.pwd_check['access_level'] >= LEVEL_1_ACCESS and self.pwd_check['level1_key_bytes']:
                    try:
                        s2_bytes_to_parse = handler.aes_decrypt(raw_s2_bytes, self.pwd_check['level1_key_bytes'])
                    except Exception as e:
                        print(
                            f"Warning: Failed to decrypt Section 2 with Level 1 key: {e}. Parsing raw/encrypted bytes.")
                else:
                    print(
                        "Warning: Section 2 is Level 1 encrypted, but insufficient access or no L1 key. Parsing raw/encrypted bytes.")
            elif s2_enc_flag == 2:  # Level 2 Encrypted
                if self.pwd_check['access_level'] >= LEVEL_2_ACCESS and self.pwd_check['level2_key_bytes']:
                    try:
                        s2_bytes_to_parse = handler.aes_decrypt(raw_s2_bytes, self.pwd_check['level2_key_bytes'])
                    except Exception as e:
                        print(
                            f"Warning: Failed to decrypt Section 2 with Level 2 key: {e}. Parsing raw/encrypted bytes.")
                else:
                    print(
                        "Warning: Section 2 is Level 2 encrypted, but insufficient access or no L2 key. Parsing raw/encrypted bytes.")
            # If s2_enc_flag is 0 (NO_ENCRYPTION) or negative (already decrypted marker, though C lib usually makes it positive before writing)
            # then s2_bytes_to_parse remains raw_s2_bytes

            # 3. Decrypt Section 3 if necessary
            s3_enc_flag = self.section1.section3_encryption_level
            if s3_enc_flag == 1:  # Level 1 Encrypted
                if self.pwd_check['access_level'] >= LEVEL_1_ACCESS and self.pwd_check['level1_key_bytes']:
                    try:
                        s3_bytes_to_parse = handler.aes_decrypt(raw_s3_bytes, self.pwd_check['level1_key_bytes'])
                    except Exception as e:
                        print(
                            f"Warning: Failed to decrypt Section 3 with Level 1 key: {e}. Parsing raw/encrypted bytes.")
                else:
                    print(
                        "Warning: Section 3 is Level 1 encrypted, but insufficient access or no L1 key. Parsing raw/encrypted bytes.")
            elif s3_enc_flag == 2:  # Level 2 Encrypted
                if self.pwd_check['access_level'] >= LEVEL_2_ACCESS and self.pwd_check['level2_key_bytes']:
                    try:
                        s3_bytes_to_parse = handler.aes_decrypt(raw_s3_bytes, self.pwd_check['level2_key_bytes'])
                    except Exception as e:
                        print(
                            f"Warning: Failed to decrypt Section 3 with Level 2 key: {e}. Parsing raw/encrypted bytes.")
                else:
                    print(
                        "Warning: Section 3 is Level 2 encrypted, but insufficient access or no L2 key. Parsing raw/encrypted bytes.")
        elif self.section1.section2_encryption_level != 0 or self.section1.section3_encryption_level != 0:
            # Sections are marked as encrypted, but we couldn't/didn't attempt password validation (e.g. no password provided for protected file)
            print(
                "Warning: Metadata sections may be encrypted, but no valid password context. Parsing raw/encrypted bytes for S2/S3.")

        # 4. Parse Section 2 (now potentially decrypted)
        self.section2 = TimeSeriesMetadataSection2(s2_bytes_to_parse)

        # 5. Parse Section 3 (now potentially decrypted)
        self.section3 = MetadataSection3(s3_bytes_to_parse)

    def __str__(self):
        if not self.universal_header:
            return f"TimeSeriesMetadataFile: {self.filepath} (not fully parsed or empty)"

        return (
            f"TimeSeriesMetadataFile: {self.filepath}\n"
            f"{self.universal_header}\n"
            f"{self.section1}\n"
            f"{self.section2}\n"
            f"{self.section3}"
        )
