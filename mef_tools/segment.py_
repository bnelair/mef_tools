from dataclasses import dataclass
from typing import Optional
import struct
from datetime import datetime, timezone
import hashlib
from typing import Optional, Tuple

from dataclasses import dataclass
from typing import Optional
import struct
from datetime import datetime, timezone
import hashlib
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# DONE
# - password validation in UniversalHeader works!
# parsing worked without pwd too
# TODO
# time to wrap up the decoding of the tmet file with validation and without.
# then move to tidx files.

def generate_section_key(password: str, level: int) -> bytes:
    """Generate encryption key for section based on password and level."""
    pwd_bytes = password.encode('utf-8')
    if level == 1:
        return hashlib.sha256(pwd_bytes).digest()
    else:  # level 2
        level1_hash = hashlib.sha256(pwd_bytes).digest()
        return hashlib.sha256(level1_hash).digest()


def decrypt_section(data: bytes, password: str, level: int) -> bytes:
    """
    Decrypt section data using password and encryption level.
    """
    key = generate_section_key(password, level)
    iv = b'\x00' * 16  # Zero IV per MEF spec

    # Pad data to AES block size if needed
    block_size = 16
    pad_length = (block_size - len(data) % block_size) % block_size
    padded_data = data + bytes([pad_length] * pad_length)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    return decryptor.update(padded_data) + decryptor.finalize()

class MEFBinaryFormat:
    """Constants for MEF binary format"""
    MEF_TRUE = 1
    MEF_UNKNOWN = 0
    MEF_FALSE = -1

    MEF_BIG_ENDIAN = 0
    MEF_LITTLE_ENDIAN = 1

    # File type codes
    RECORD_DATA_FILE = 'rdat'
    RECORD_INDICES_FILE = 'ridx'
    TIME_SERIES_METADATA_FILE = 'tmet'
    TIME_SERIES_DATA_FILE = 'tdat'
    TIME_SERIES_INDICES_FILE = 'tidx'
    VIDEO_METADATA_FILE = 'vmet'
    VIDEO_INDICES_FILE = 'vidx'

def _convert_signed_to_unsigned(value):
    """Convert signed 64-bit to unsigned preserving bit pattern."""
    return value & 0xFFFFFFFFFFFFFFFF


class UniversalHeader:
    """Parser for MEF3 Universal Header."""

    HEADER_BYTES = 1024

    def __init__(self, raw_bytes: bytes = None, path: str = None):
        if path is not None:
            with open(path, 'rb') as f:
                raw_bytes = f.read(self.HEADER_BYTES)
        elif raw_bytes is None:
            raise ValueError("Either raw_bytes or path must be provided")

        if len(raw_bytes) < self.HEADER_BYTES:
            raise ValueError(f"Header must be {self.HEADER_BYTES} bytes")

        # First 16 bytes
        fmt_header = "<II5sBBB"
        (self.header_crc,
         self.body_crc,
         file_type,
         self.mef_version_major,
         self.mef_version_minor,
         self.byte_order_code) = struct.unpack(fmt_header, raw_bytes[:16])

        # Times - next 16 bytes
        (self.start_time,
         self.end_time) = struct.unpack("<qq", raw_bytes[16:32])
        self.start_time *= -1  # Per spec: "Times that have been offset are made negative"
        self.end_time *= -1

        # File metadata - next 20 bytes
        (self.number_of_entries,
         self.maximum_entry_size,
         self.segment_number) = struct.unpack("<qqI", raw_bytes[32:52])

        # UTF-8 strings
        self.channel_name = raw_bytes[52:308].decode('utf-8').rstrip('\x00')
        self.session_name = raw_bytes[308:564].decode('utf-8').rstrip('\x00')
        self.anonymized_name = raw_bytes[564:820].decode('utf-8').rstrip('\x00')

        # UUIDs - 16 bytes each
        self.level_uuid = raw_bytes[820:836]
        self.file_uuid = raw_bytes[836:852]
        self.provenance_uuid = raw_bytes[852:868]

        # Password validation fields - 16 bytes each
        self.level_1_password_validation = raw_bytes[868:884]
        self.level_2_password_validation = raw_bytes[884:900]

        # Protected/discretionary regions
        self.protected_region = raw_bytes[900:960]
        self.discretionary_region = raw_bytes[960:1024]

        self.file_type_string = file_type.decode('ascii').rstrip('\x00')

    def get_start_datetime(self) -> Optional[datetime]:
        """Convert start time (μUTC) to datetime."""
        if self.start_time == 0x8000000000000000:  # No entry
            return None
        return datetime.fromtimestamp(self.start_time / 1_000_000, tz=timezone.utc)

    def get_end_datetime(self) -> Optional[datetime]:
        """Convert end time (μUTC) to datetime."""
        if self.end_time == 0x8000000000000000:  # No entry
            return None
        return datetime.fromtimestamp(self.end_time / 1_000_000, tz=timezone.utc)

    def has_level_1_password(self) -> bool:
        """Check if level 1 password validation is present."""
        return not all(x == 0 for x in self.level_1_password_validation)

    def has_level_2_password(self) -> bool:
        """Check if level 2 password validation is present."""
        return not all(x == 0 for x in self.level_2_password_validation)

    def is_original_file(self) -> bool:
        """Check if this is the originating file by comparing UUIDs."""
        return self.file_uuid == self.provenance_uuid

    def check_password(self, password: str) -> Tuple[bool, bool]:
        """Check if password is valid for this MEF file."""
        has_level_1 = self.has_level_1_password()
        has_level_2 = self.has_level_2_password()

        if not (has_level_1 or has_level_2):
            return True, True

        if not password:
            return False, False

        # Get password bytes (equivalent to extract_terminal_password_bytes)
        pwd_bytes = password.encode('utf-8')
        password_bytes = pwd_bytes + b'\x00' * (16 - len(pwd_bytes)) if len(pwd_bytes) < 16 else pwd_bytes[:16]

        # Check level 1 access first
        sha = hashlib.sha256(password_bytes).digest()
        level1_valid = sha[:16] == self.level_1_password_validation

        if level1_valid:
            return True, False  # Level 1 password cannot be Level 2 password

        # If not level 1, check level 2
        # XOR SHA hash with level 2 validation to get putative level 1 password
        putative_level1_bytes = bytes(a ^ b for a, b in zip(sha[:16], self.level_2_password_validation))

        # Validate putative level 1 password
        sha = hashlib.sha256(putative_level1_bytes).digest()
        level2_valid = sha[:16] == self.level_1_password_validation

        return level2_valid, level2_valid  # Level 2 access implies Level 1 access


class MetadataSection1:
    """Parser for MEF3 Metadata Section 1."""

    def __init__(self, raw_bytes: bytes):
        """Initialize from raw bytes."""
        # Section 1 contains encryption levels (2 bytes)
        self.section_2_encryption = raw_bytes[0]  # ui1
        self.section_3_encryption = raw_bytes[1]  # ui1

        # Protected region (766 bytes)
        self.protected_region = raw_bytes[2:768]

        # Discretionary region (768 bytes)
        self.discretionary_region = raw_bytes[768:1536]

    def is_section_2_encrypted(self) -> bool:
        """Check if section 2 is encrypted."""
        return self.section_2_encryption > 0

    def is_section_3_encrypted(self) -> bool:
        """Check if section 3 is encrypted."""
        return self.section_3_encryption > 0

    def get_encryption_level(self, section: int) -> int:
        """Get encryption level for specified section (2 or 3)."""
        if section == 2:
            return self.section_2_encryption
        elif section == 3:
            return self.section_3_encryption
        raise ValueError("Invalid section number. Must be 2 or 3.")


class MetadataSection3:
    """Parser for MEF3 Metadata Section 3."""

    def __init__(self, raw_bytes: bytes):
        """Initialize from raw bytes."""
        # Parse time offsets (28 bytes total)
        (self.recording_time_offset,
         self.dst_start_time,
         self.dst_end_time,
         self.gmt_offset) = struct.unpack("<qqqI", raw_bytes[0:28])

        # Parse subject info strings
        self.subject_name_1 = raw_bytes[28:156].decode('utf-8').rstrip('\x00')  # 128 bytes
        self.subject_name_2 = raw_bytes[156:284].decode('utf-8').rstrip('\x00')  # 128 bytes
        self.subject_id = raw_bytes[284:412].decode('utf-8').rstrip('\x00')  # 128 bytes
        self.recording_location = raw_bytes[412:924].decode('utf-8').rstrip('\x00')  # 512 bytes

        # Protected region (1124 bytes)
        self.protected_region = raw_bytes[924:2048]

        # Discretionary region (1024 bytes)
        self.discretionary_region = raw_bytes[2048:3072]

    def get_local_datetime(self, utc_time: int) -> datetime:
        """Convert UTC time to local time using GMT offset."""
        if utc_time == 0x8000000000000000:  # No entry
            return None
        local_ts = utc_time / 1_000_000  # Convert μs to s
        local_ts += self.gmt_offset  # Apply GMT offset
        return datetime.fromtimestamp(local_ts, tz=timezone.utc)

    def has_dst_change(self) -> bool:
        """Check if DST change occurred during recording."""
        return (self.dst_start_time != 0 and self.dst_start_time != 0x8000000000000000) or \
            (self.dst_end_time != 0 and self.dst_end_time != 0x8000000000000000)

    def get_timezone_offset_hours(self) -> float:
        """Return timezone offset in hours."""
        return self.gmt_offset / 3600.0

    def is_time_offset_applied(self) -> bool:
        """Check if recording time offset is applied."""
        return self.recording_time_offset != 0


class TimeSeriesMetadataSection2:
    """Parser for MEF3 Time Series Metadata Section 2."""

    def __init__(self, raw_bytes: bytes):
        """Initialize from raw bytes."""
        # Common fields
        self.channel_description = raw_bytes[0:2048].decode('utf-8').rstrip('\x00')
        self.session_description = raw_bytes[2048:4096].decode('utf-8').rstrip('\x00')
        self.recording_duration = struct.unpack("<q", raw_bytes[4096:4104])[0]

        # Reference description
        self.reference_description = raw_bytes[4104:6152].decode('utf-8').rstrip('\x00')

        # Technical metadata - 7 doubles
        (self.acquisition_channel_number,
         self.sampling_frequency,
         self.low_frequency_filter_setting,
         self.high_frequency_filter_setting,
         self.notch_filter_frequency_setting,
         self.ac_line_frequency,
         self.units_conversion_factor) = struct.unpack("<qdddddd", raw_bytes[6152:6208])

        self.units_description = raw_bytes[6208:6336].decode('utf-8').rstrip('\x00')

        # Sample statistics - careful with offsets and sizes
        (self.maximum_native_sample_value,
         self.minimum_native_sample_value) = struct.unpack("<dd", raw_bytes[6336:6352])

        (self.start_sample,
         self.number_of_samples,
         self.number_of_blocks,
         self.maximum_block_bytes) = struct.unpack("<qqqq", raw_bytes[6352:6384])

        self.maximum_block_samples = struct.unpack("<I", raw_bytes[6384:6388])[0]
        self.maximum_difference_bytes = struct.unpack("<I", raw_bytes[6388:6392])[0]

        # Additional discontinuity statistics
        (self.block_interval,
         self.number_of_discontinuities,
         self.maximum_contiguous_blocks,
         self.maximum_contiguous_block_bytes,
         self.maximum_contiguous_samples) = struct.unpack("<qqqqq", raw_bytes[6392:6432])

        # Protected/discretionary regions
        self.protected_region = raw_bytes[8992:11152]
        self.discretionary_region = raw_bytes[11152:13312]

    def get_sample_rate(self) -> float:
        """Return sampling frequency in Hz."""
        return self.sampling_frequency

    def get_duration_seconds(self) -> float:
        """Return recording duration in seconds."""
        return self.recording_duration / 1_000_000  # Convert microseconds to seconds

    def get_native_units(self) -> str:
        """Return the units description string."""
        return self.units_description

    def get_total_samples(self) -> int:
        """Return total number of samples."""
        return self.number_of_samples

    def get_discontinuity_count(self) -> int:
        """Return number of discontinuities."""
        return self.number_of_discontinuities


class VideoMetadataSection2:
    """Parser for MEF3 Video Metadata Section 2."""

    def __init__(self, raw_bytes: bytes):
        """Initialize from raw bytes."""
        # Common fields for all section 2 types
        self.channel_description = raw_bytes[0:2048].decode('utf-8').rstrip('\x00')
        self.session_description = raw_bytes[2048:4096].decode('utf-8').rstrip('\x00')
        self.recording_duration = struct.unpack("<q", raw_bytes[4096:4104])[0]

        # Video specific fields
        (self.horizontal_resolution,
         self.vertical_resolution,
         self.frame_rate,
         self.number_of_clips,
         self.maximum_clip_bytes) = struct.unpack("<qqddq", raw_bytes[4104:4144])

        self.video_format = raw_bytes[4144:4272].decode('utf-8').rstrip('\x00')
        self.video_file_crc = struct.unpack("<I", raw_bytes[4272:4276])[0]

        # Protected/discretionary regions
        self.protected_region = raw_bytes[4276:7512]
        self.discretionary_region = raw_bytes[7512:10752]


class TMETFile:
    """Main class for parsing MEF3 files."""

    def __init__(self, filename: str, password: Optional[str] = None):
        # check if it is .tmet file
        if not filename.endswith('.tmet'):
            raise ValueError("Not a valid .tmet file")

        self.universal_header_bytes = None

        with open(filename, 'rb') as f:
            header_bytes = f.read(UniversalHeader.HEADER_BYTES)
            self.universal_header = UniversalHeader(header_bytes)



            if self.universal_header.has_level_1_password() or self.universal_header.has_level_2_password():
                if not password:
                    raise ValueError("Password required for encrypted file")

                level_1_valid, level_2_valid = validate_mef_password(
                    password,
                    self.universal_header.level_1_password_validation,
                    self.universal_header.level_2_password_validation
                )

                print(level_1_valid, level_2_valid)

                if not (level_1_valid and level_2_valid):
                    raise ValueError("Invalid password")

            if self.is_metadata_file():
                section1_bytes = f.read(1536)
                self.metadata_section1 = MetadataSection1(section1_bytes)

                section2_bytes = f.read(13312)
                if password and self.metadata_section1.is_section_2_encrypted():
                    section2_bytes = decrypt_section(
                        section2_bytes,
                        password,
                        self.metadata_section1.get_encryption_level(2)
                    )

                if self.universal_header.file_type_string == MEFBinaryFormat.TIME_SERIES_METADATA_FILE:
                    self.metadata_section2 = TimeSeriesMetadataSection2(section2_bytes)
                else:
                    self.metadata_section2 = VideoMetadataSection2(section2_bytes)

                section3_bytes = f.read(3072)
                if password and self.metadata_section1.is_section_3_encrypted():
                    section3_bytes = decrypt_section(
                        section3_bytes,
                        password,
                        self.metadata_section1.get_encryption_level(3)
                    )
                self.metadata_section3 = MetadataSection3(section3_bytes)
            else:
                self.metadata_section1 = None
                self.metadata_section2 = None
                self.metadata_section3 = None

    def is_metadata_file(self) -> bool:
        """Check if this is a metadata file."""
        return self.universal_header.file_type_string == MEFBinaryFormat.TIME_SERIES_METADATA_FILE


def validate_mef_password(password: str, level_1_validation: bytes, level_2_validation: bytes) -> Tuple[bool, bool]:
    """
    Validate MEF password against level 1 and level 2 validation fields per MEF spec.
    """
    has_level_1 = not all(x == 0 for x in level_1_validation)
    has_level_2 = not all(x == 0 for x in level_2_validation)

    if not (has_level_1 or has_level_2):
        return True, True

    if not password:
        return False, False

    # Get password bytes (equivalent to extract_terminal_password_bytes)
    pwd_bytes = password.encode('utf-8')
    password_bytes = pwd_bytes + b'\x00' * (16 - len(pwd_bytes)) if len(pwd_bytes) < 16 else pwd_bytes[:16]

    # Check level 1 access first
    sha = hashlib.sha256(password_bytes).digest()
    level1_valid = sha[:16] == level_1_validation

    if level1_valid:
        return True, False  # Level 1 password cannot be Level 2 password

    # If not level 1, check level 2
    # XOR SHA hash with level 2 validation to get putative level 1 password
    putative_level1_bytes = bytes(a ^ b for a, b in zip(sha[:16], level_2_validation))

    # Validate putative level 1 password
    sha = hashlib.sha256(putative_level1_bytes).digest()
    level2_valid = sha[:16] == level_1_validation

    return level2_valid, level2_valid  # Level 2 access implies Level 1 access


def check_mef_access(mef_file: 'MEF3File', password: Optional[str] = None) -> Tuple[bool, bool]:
    """
    Check access levels for a MEF file with optional password.

    Args:
        mef_file: MEF3File instance
        password: Optional password string

    Returns:
        Tuple of (can_access_level_1, can_access_level_2) booleans
    """
    return validate_mef_password(
        password or '',
        mef_file.universal_header.level_1_password_validation,
        mef_file.universal_header.level_2_password_validation
    )