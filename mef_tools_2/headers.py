"""
MEF 3.0 Header Classes

This module provides classes for reading and manipulating MEF 3.0 file headers.
"""

import os
import struct
import time
from dataclasses import dataclass, fields
from typing import Optional, Union, Dict, Any, BinaryIO, Type, TypeVar, ClassVar
from enum import IntEnum


class HeaderType(IntEnum):
    """Types of MEF headers."""
    UNIVERSAL = 1
    TIME_SERIES_METADATA = 2
    TIME_SERIES_INDICES = 3


@dataclass
class BaseHeader:
    """Base class for all MEF headers."""
    HEADER_SIZE: ClassVar[int] = 0
    FORMAT_STRING: ClassVar[str] = ""
    HEADER_TYPE: ClassVar[HeaderType]

    @classmethod
    def from_file(cls, file_path: str) -> 'BaseHeader':
        """Create a header instance by reading from a file."""
        with open(file_path, 'rb') as f:
            return cls.from_bytes(f.read(cls.HEADER_SIZE))

    @classmethod
    def from_bytes(cls, data: bytes) -> 'BaseHeader':
        """Create a header instance from bytes."""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Insufficient data for {cls.__name__} header. "
                             f"Expected at least {cls.HEADER_SIZE} bytes, got {len(data)}")

        values = struct.unpack(cls.FORMAT_STRING, data[:cls.HEADER_SIZE])
        field_names = [f.name for f in fields(cls) if not f.name.startswith('_')]
        field_values = {}

        for name, value in zip(field_names, values):
            if name in field_values:
                if isinstance(field_values[name], list):
                    field_values[name].append(value)
                else:
                    field_values[name] = [field_values[name], value]
            else:
                field_values[name] = value

        return cls(**field_values)

    def to_bytes(self) -> bytes:
        """Convert the header to bytes."""
        values = []
        for field in fields(self):
            if field.name.startswith('_'):
                continue
            value = getattr(self, field.name)
            if isinstance(value, (list, tuple)):
                values.extend(value)
            else:
                values.append(value)
        return struct.pack(self.FORMAT_STRING, *values)


@dataclass
class UniversalHeader(BaseHeader):
    """Universal header present in all MEF 3.0 files."""
    HEADER_SIZE: ClassVar[int] = 1024
    HEADER_TYPE: ClassVar[HeaderType] = HeaderType.UNIVERSAL

    # Format string for struct.unpack/pack
    # Format: < for little-endian, I for uint32, 5s for 5-byte string, etc.
    FORMAT_STRING: ClassVar[str] = (
        "<"  # Little-endian
        "I"  # header_crc (uint32)
        "I"  # body_crc (uint32)
        "5s"  # file_type_string (4 chars + null)
        "B"  # mef_version_major (uint8)
        "B"  # mef_version_minor (uint8)
        "B"  # byte_order_code (uint8)
        "x"  # padding to align to 8 bytes
        "q"  # start_time (int64)
        "q"  # end_time (int64)
        "q"  # number_of_entries (int64)
        "q"  # maximum_entry_size (int64)
        "i"  # segment_number (int32)
        "4x"  # padding to align to 52 bytes
        "256s"  # channel_name (utf-8)
        "256s"  # session_name (utf-8)
        "256s"  # anonymized_name (utf-8)
        "16s"  # level_UUID (16 bytes)
        "16s"  # file_UUID (16 bytes)
        "16s"  # provenance_UUID (16 bytes)
        "16s"  # level_1_password_validation (16 bytes)
        "16s"  # level_2_password_validation (16 bytes)
        "60s"  # protected_region (60 bytes)
        "64s"  # discretionary_region (64 bytes)
    )

    # Header fields with their types and descriptions
    header_crc: int
    body_crc: int
    file_type_string: str
    mef_version_major: int
    mef_version_minor: int
    byte_order_code: int
    start_time: int
    end_time: int
    number_of_entries: int
    maximum_entry_size: int
    segment_number: int
    channel_name: str
    session_name: str
    anonymized_name: str
    level_UUID: bytes
    file_UUID: bytes
    provenance_UUID: bytes
    level_1_password_validation: bytes
    level_2_password_validation: bytes
    protected_region: bytes
    discretionary_region: bytes

    def __post_init__(self):
        """Post-initialization to clean up string fields."""
        # Clean up string fields by removing null terminators
        if isinstance(self.file_type_string, bytes):
            self.file_type_string = self.file_type_string.decode('ascii', errors='ignore').rstrip('\x00')
        if isinstance(self.channel_name, bytes):
            self.channel_name = self.channel_name.decode('utf-8', errors='ignore').rstrip('\x00')
        if isinstance(self.session_name, bytes):
            self.session_name = self.session_name.decode('utf-8', errors='ignore').rstrip('\x00')
        if isinstance(self.anonymized_name, bytes):
            self.anonymized_name = self.anonymized_name.decode('utf-8', errors='ignore').rstrip('\x00')

    @classmethod
    def create_new(cls, file_type: str = "tmet") -> 'UniversalHeader':
        """Create a new UniversalHeader with default values."""
        import uuid
        import time

        now = int(time.time() * 1_000_000)  # Microseconds since epoch

        return cls(
            header_crc=0,  # Will be calculated on save
            body_crc=0,  # Will be calculated on save
            file_type_string=file_type.ljust(4)[:4],  # Ensure 4 chars
            mef_version_major=3,
            mef_version_minor=0,
            byte_order_code=1,  # 1 for little-endian
            start_time=now,
            end_time=0,  # Will be updated when file is closed
            number_of_entries=0,
            maximum_entry_size=0,  # Will be updated as entries are added
            segment_number=0,
            channel_name="",
            session_name="",
            anonymized_name="",
            level_UUID=uuid.uuid4().bytes,
            file_UUID=uuid.uuid4().bytes,
            provenance_UUID=uuid.uuid4().bytes,
            level_1_password_validation=b'\0' * 16,  # No password by default
            level_2_password_validation=b'\0' * 16,  # No password by default
            protected_region=b'\0' * 60,
            discretionary_region=b'\0' * 64
        )

    def update_crc(self) -> None:
        """Update the header CRC."""
        # Set header_crc to 0 for CRC calculation
        self.header_crc = 0
        header_bytes = self.to_bytes()
        # Calculate CRC on all bytes except the first 4 (header_crc field)
        crc = self._calculate_crc(header_bytes[4:])
        self.header_crc = crc

    def is_password_protected(self) -> bool:
        """Check if the file is password protected."""
        return (self.level_1_password_validation != b'\0' * 16 or
                self.level_2_password_validation != b'\0' * 16)

    def verify_password(self, password: str, level: int = 1) -> bool:
        """
        Verify a password against the stored validation hashes.

        Args:
            password: The password to verify
            level: Password level (1 or 2)

        Returns:
            bool: True if password is correct for the specified level
        """
        if level not in (1, 2):
            raise ValueError("Password level must be 1 or 2")

        import hashlib
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        # Derive key from password using PBKDF2
        salt = b'mef3_salt'  # Standard salt used in MEF 3.0
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,  # 16 bytes = 128 bits
            salt=salt,
            iterations=10000,
        )
        key = kdf.derive(password.encode('utf-8'))

        # For level 1, compare with stored hash
        if level == 1:
            stored_hash = self.level_1_password_validation
            if stored_hash == b'\0' * 16:
                return False  # No password set
            return stored_hash == hashlib.sha256(key).digest()[:16]

        # For level 2, need to XOR with level 1 key
        if level == 2:
            if self.level_2_password_validation == b'\0' * 16:
                return False  # No level 2 password set

            # First verify level 1 password
            if not self.verify_password(password, level=1):
                return False

            level1_key = hashlib.sha256(key).digest()[:16]
            level2_hash = hashlib.sha256(key).digest()[:16]
            expected = bytes(a ^ b for a, b in zip(level1_key, level2_hash))
            return self.level_2_password_validation == expected

        return False

    def _calculate_crc(self, data: bytes) -> int:
        """Calculate the MEF 3.0 CRC-32 checksum."""
        # This is a placeholder - implement the actual MEF 3.0 CRC algorithm
        # The real implementation would use the CRC_KOOPMAN32_TABLE from the C code
        import zlib
        return zlib.crc32(data) & 0xFFFFFFFF


@dataclass
class TimeSeriesMetadataHeader(BaseHeader):
    """
    Header for time series metadata files in MEF 3.0 format.
    
    This header contains metadata specific to time series data, including recording
    parameters, filter settings, and block information.
    """
    HEADER_SIZE: ClassVar[int] = 512
    HEADER_TYPE: ClassVar[HeaderType] = HeaderType.TIME_SERIES_METADATA
    
    # Format string for struct.unpack/pack
    # Format: < for little-endian, d for double, q for int64, etc.
    FORMAT_STRING: ClassVar[str] = (
        "<"  # Little-endian
        "d"  # sampling_frequency (float64)
        "d"  # low_frequency_filter_setting (float64)
        "d"  # high_frequency_filter_setting (float64)
        "d"  # notch_filter_frequency_setting (float64)
        "d"  # ac_line_frequency (float64)
        "d"  # units_conversion_factor (float64)
        "128s"  # units_description (utf-8)
        "d"  # maximum_native_sample_value (float64)
        "d"  # minimum_native_sample_value (float64)
        "q"  # start_sample (int64)
        "q"  # number_of_samples (int64)
        "q"  # number_of_blocks (int64)
        "q"  # maximum_block_bytes (int64)
        "I"  # maximum_block_samples (uint32)
        "I"  # maximum_difference_bytes (uint32)
        "q"  # block_interval (int64)
        "q"  # number_of_discontinuities (int64)
        "q"  # maximum_contiguous_blocks (int64)
        "q"  # maximum_contiguous_block_bytes (int64)
        "q"  # maximum_contiguous_samples (int64)
        "64s"  # protected_region (64 bytes)
        "64s"  # discretionary_region (64 bytes)
    )
    
    # Header fields with their types and descriptions
    sampling_frequency: float  # Hz
    low_frequency_filter_setting: float  # Hz
    high_frequency_filter_setting: float  # Hz
    notch_filter_frequency_setting: float  # Hz
    ac_line_frequency: float  # Hz
    units_conversion_factor: float  # Multiply by this to convert to units in units_description
    units_description: str  # Description of units (e.g., "uV", "mV")
    maximum_native_sample_value: float  # Maximum sample value in native units
    minimum_native_sample_value: float  # Minimum sample value in native units
    start_sample: int  # Sample number of first sample in the file
    number_of_samples: int  # Total number of samples in the file
    number_of_blocks: int  # Total number of data blocks
    maximum_block_bytes: int  # Maximum size of any block in bytes
    maximum_block_samples: int  # Maximum number of samples in any block
    maximum_difference_bytes: int  # Maximum size of any difference block
    block_interval: int  # Time between blocks in microseconds
    number_of_discontinuities: int  # Number of time discontinuities
    maximum_contiguous_blocks: int  # Maximum number of contiguous blocks
    maximum_contiguous_block_bytes: int  # Maximum bytes in contiguous blocks
    maximum_contiguous_samples: int  # Maximum samples in contiguous blocks
    protected_region: bytes  # Application-specific protected data
    discretionary_region: bytes  # Application-specific discretionary data
    
    def __post_init__(self):
        """Post-initialization to clean up string fields."""
        # Clean up string fields by removing null terminators
        if isinstance(self.units_description, bytes):
            self.units_description = self.units_description.decode('utf-8', errors='ignore').rstrip('\x00')
    
    @classmethod
    def create_new(cls) -> 'TimeSeriesMetadataHeader':
        """Create a new TimeSeriesMetadataHeader with default values."""
        return cls(
            sampling_frequency=-1.0,  # Indicates no entry
            low_frequency_filter_setting=-1.0,  # No filter
            high_frequency_filter_setting=-1.0,  # No filter
            notch_filter_frequency_setting=-1.0,  # No notch filter
            ac_line_frequency=-1.0,  # Unknown
            units_conversion_factor=1.0,  # No conversion by default
            units_description="",  # Should be set by application
            maximum_native_sample_value=float('nan'),  # Will be updated with actual data
            minimum_native_sample_value=float('nan'),  # Will be updated with actual data
            start_sample=0,
            number_of_samples=0,  # Will be updated as data is written
            number_of_blocks=0,  # Will be updated as blocks are written
            maximum_block_bytes=0,  # Will be updated as blocks are written
            maximum_block_samples=0,  # Will be updated as blocks are written
            maximum_difference_bytes=0,  # Will be updated during compression
            block_interval=1000000,  # 1 second default block interval (in microseconds)
            number_of_discontinuities=0,  # No discontinuities initially
            maximum_contiguous_blocks=0,  # Will be updated during writing
            maximum_contiguous_block_bytes=0,  # Will be updated during writing
            maximum_contiguous_samples=0,  # Will be updated during writing
            protected_region=b'\0' * 64,  # Initialize to zeros
            discretionary_region=b'\0' * 64  # Initialize to zeros
        )
    
    def update_statistics(self, block_data: bytes, sample_count: int) -> None:
        """
        Update statistics based on a new block of data.
        
        Args:
            block_data: Raw bytes of the block
            sample_count: Number of samples in the block
        """
        import numpy as np
        
        # Update block statistics
        block_bytes = len(block_data)
        self.number_of_blocks += 1
        self.number_of_samples += sample_count
        self.maximum_block_bytes = max(self.maximum_block_bytes, block_bytes)
        self.maximum_block_samples = max(self.maximum_block_samples, sample_count)
        
        # For demonstration - in a real implementation, you would decode the samples
        # and update min/max values. This is a placeholder:
        # samples = np.frombuffer(block_data, dtype=np.int32)  # Assuming 32-bit samples
        # if len(samples) > 0:
        #     self.maximum_native_sample_value = max(self.maximum_native_sample_value, np.max(samples))
        #     self.minimum_native_sample_value = min(self.minimum_native_sample_value, np.min(samples))
    
    def to_dict(self) -> dict:
        """Convert the header to a dictionary."""
        return {
            'sampling_frequency': self.sampling_frequency,
            'low_frequency_filter_setting': self.low_frequency_filter_setting,
            'high_frequency_filter_setting': self.high_frequency_filter_setting,
            'notch_filter_frequency_setting': self.notch_filter_frequency_setting,
            'ac_line_frequency': self.ac_line_frequency,
            'units_conversion_factor': self.units_conversion_factor,
            'units_description': self.units_description,
            'maximum_native_sample_value': self.maximum_native_sample_value,
            'minimum_native_sample_value': self.minimum_native_sample_value,
            'start_sample': self.start_sample,
            'number_of_samples': self.number_of_samples,
            'number_of_blocks': self.number_of_blocks,
            'maximum_block_bytes': self.maximum_block_bytes,
            'maximum_block_samples': self.maximum_block_samples,
            'maximum_difference_bytes': self.maximum_difference_bytes,
            'block_interval': self.block_interval,
            'number_of_discontinuities': self.number_of_discontinuities,
            'maximum_contiguous_blocks': self.maximum_contiguous_blocks,
            'maximum_contiguous_block_bytes': self.maximum_contiguous_block_bytes,
            'maximum_contiguous_samples': self.maximum_contiguous_samples
        }


@dataclass
class TimeSeriesIndicesHeader(BaseHeader):
    """
    Header for time series indices files in MEF 3.0 format.
    
    This header contains metadata about the time series index entries that follow it.
    Each index entry provides information about a block of time series data.
    """
    HEADER_SIZE: ClassVar[int] = 256
    HEADER_TYPE: ClassVar[HeaderType] = HeaderType.TIME_SERIES_INDICES
    
    # Format string for struct.unpack/pack
    # Format: < for little-endian, q for int64, I for uint32, etc.
    FORMAT_STRING: ClassVar[str] = (
        "<"  # Little-endian
        "q"  # index_entries_count (int64)
        "q"  # maximum_entries (int64)
        "q"  # entry_size_bytes (int64)
        "q"  # entries_per_block (int64)
        "q"  # blocks_per_segment (int64)
        "q"  # maximum_block_bytes (int64)
        "q"  # maximum_block_samples (int64)
        "q"  # maximum_contiguous_blocks (int64)
        "q"  # maximum_contiguous_block_bytes (int64)
        "q"  # maximum_contiguous_samples (int64)
        "q"  # start_time (int64, microseconds since epoch)
        "q"  # end_time (int64, microseconds since epoch)
        "I"  # flags (uint32)
        "I"  # reserved1 (uint32)
        "q"  # reserved2 (int64)
        "q"  # reserved3 (int64)
        "64s"  # protected_region (64 bytes)
        "64s"  # discretionary_region (64 bytes)
    )
    
    # Header fields with their types and descriptions
    index_entries_count: int  # Number of index entries
    maximum_entries: int  # Maximum number of entries that can be stored
    entry_size_bytes: int  # Size of each index entry in bytes (typically 56)
    entries_per_block: int  # Number of entries per block
    blocks_per_segment: int  # Number of blocks per segment
    maximum_block_bytes: int  # Maximum size of any block in bytes
    maximum_block_samples: int  # Maximum number of samples in any block
    maximum_contiguous_blocks: int  # Maximum number of contiguous blocks
    maximum_contiguous_block_bytes: int  # Maximum bytes in contiguous blocks
    maximum_contiguous_samples: int  # Maximum samples in contiguous blocks
    start_time: int  # Start time of the time series (microseconds since epoch)
    end_time: int  # End time of the time series (microseconds since epoch)
    flags: int  # Bit flags for index file properties
    reserved1: int  # Reserved for future use
    reserved2: int  # Reserved for future use
    reserved3: int  # Reserved for future use
    protected_region: bytes  # Application-specific protected data
    discretionary_region: bytes  # Application-specific discretionary data
    
    @classmethod
    def create_new(cls, entry_size: int = 56) -> 'TimeSeriesIndicesHeader':
        """
        Create a new TimeSeriesIndicesHeader with default values.
        
        Args:
            entry_size: Size of each index entry in bytes (default: 56 for MEF 3.0)
            
        Returns:
            A new TimeSeriesIndicesHeader instance with default values
        """
        now = int(time.time() * 1_000_000)  # Current time in microseconds
        
        return cls(
            index_entries_count=0,  # Will be updated as entries are added
            maximum_entries=0,  # Will be set based on file size
            entry_size_bytes=entry_size,  # Typically 56 bytes per entry
            entries_per_block=0,  # Will be set based on block size
            blocks_per_segment=0,  # Will be set based on segment size
            maximum_block_bytes=0,  # Will be updated as blocks are added
            maximum_block_samples=0,  # Will be updated as blocks are added
            maximum_contiguous_blocks=0,  # Will be updated during writing
            maximum_contiguous_block_bytes=0,  # Will be updated during writing
            maximum_contiguous_samples=0,  # Will be updated during writing
            start_time=now,  # Will be updated with actual data start time
            end_time=0,  # Will be updated when file is closed
            flags=0,  # No flags set by default
            reserved1=0,  # Reserved
            reserved2=0,  # Reserved
            reserved3=0,  # Reserved
            protected_region=b'\0' * 64,  # Initialize to zeros
            discretionary_region=b'\0' * 64  # Initialize to zeros
        )
    
    def update_statistics(self, entry_count: int, block_bytes: int, sample_count: int) -> None:
        """
        Update header statistics based on a new block of data.
        
        Args:
            entry_count: Number of index entries
            block_bytes: Size of the block in bytes
            sample_count: Number of samples in the block
        """
        self.index_entries_count = entry_count
        self.maximum_block_bytes = max(self.maximum_block_bytes, block_bytes)
        self.maximum_block_samples = max(self.maximum_block_samples, sample_count)
    
    def set_time_range(self, start_time: int, end_time: int) -> None:
        """
        Set the time range for the time series data.
        
        Args:
            start_time: Start time in microseconds since epoch
            end_time: End time in microseconds since epoch
        """
        self.start_time = min(self.start_time, start_time) if self.start_time > 0 else start_time
        self.end_time = max(self.end_time, end_time)
    
    def to_dict(self) -> dict:
        """Convert the header to a dictionary."""
        return {
            'index_entries_count': self.index_entries_count,
            'maximum_entries': self.maximum_entries,
            'entry_size_bytes': self.entry_size_bytes,
            'entries_per_block': self.entries_per_block,
            'blocks_per_segment': self.blocks_per_segment,
            'maximum_block_bytes': self.maximum_block_bytes,
            'maximum_block_samples': self.maximum_block_samples,
            'maximum_contiguous_blocks': self.maximum_contiguous_blocks,
            'maximum_contiguous_block_bytes': self.maximum_contiguous_block_bytes,
            'maximum_contiguous_samples': self.maximum_contiguous_samples,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'flags': self.flags
        }
    
    def __str__(self) -> str:
        """Return a string representation of the header."""
        return (
            f"TimeSeriesIndicesHeader(entries={self.index_entries_count}, "
            f"entry_size={self.entry_size_bytes}, start={self.start_time}, "
            f"end={self.end_time}, max_block_bytes={self.maximum_block_bytes})"
        )


# Factory function to create the appropriate header
def create_header(header_type: HeaderType) -> BaseHeader:
    """Create a header instance of the specified type."""
    if header_type == HeaderType.UNIVERSAL:
        return UniversalHeader
    elif header_type == HeaderType.TIME_SERIES_METADATA:
        return TimeSeriesMetadataHeader
    elif header_type == HeaderType.TIME_SERIES_INDICES:
        return TimeSeriesIndicesHeader
    else:
        raise ValueError(f"Unknown header type: {header_type}")



