// mef3io — MEF 3.0 fixed-layout structures: parse/serialize against the
// on-disk little-endian byte layout. Offsets transcribed from the MEF 3.0
// spec (and cross-checked against meflib / pymef / reimplementation.py).
#pragma once

#include <array>
#include <span>
#include <string>
#include <vector>

#include "mef3io/types.hpp"

namespace mef3io::fmt {

// ---------------------------------------------------------------------------
// Universal header (1024 B). Prefixes every .tmet/.tidx/.tdat/.rdat/.ridx file.
// ---------------------------------------------------------------------------
struct UniversalHeader {
  ui4 header_crc = 0;
  ui4 body_crc = 0;
  std::string file_type_string;           // 4 chars (+ null) in a 5-byte field
  ui1 mef_version_major = MEF_VERSION_MAJOR;
  ui1 mef_version_minor = MEF_VERSION_MINOR;
  ui1 byte_order_code = MEF_LITTLE_ENDIAN;
  si8 start_time = UUTC_NO_ENTRY;
  si8 end_time = UUTC_NO_ENTRY;
  si8 number_of_entries = SI8_NO_ENTRY;
  si8 maximum_entry_size = SI8_NO_ENTRY;
  si4 segment_number = SI4_NO_ENTRY;
  std::string channel_name;               // utf8, 256-byte field
  std::string session_name;               // utf8, 256-byte field
  std::string anonymized_name;            // utf8, 256-byte field
  std::array<ui1, 16> level_uuid{};
  std::array<ui1, 16> file_uuid{};
  std::array<ui1, 16> provenance_uuid{};
  std::array<ui1, 16> level_1_password_validation_field{};
  std::array<ui1, 16> level_2_password_validation_field{};
  std::array<ui1, 60> protected_region{};
  std::array<ui1, 64> discretionary_region{};

  static UniversalHeader parse(std::span<const ui1> buf);   // buf.size() >= 1024
  void serialize(std::span<ui1> buf) const;                 // buf.size() >= 1024

  // CRC over bytes [4, 1024) matches the stored header_crc.
  bool header_crc_valid(std::span<const ui1> file_bytes) const;
  // Recompute and set header_crc from the current field values.
  void update_header_crc(std::span<ui1> file_bytes);

  bool is_password_protected() const;
};

// ---------------------------------------------------------------------------
// Metadata section 1 (1536 B): encryption levels for sections 2 and 3.
// ---------------------------------------------------------------------------
struct MetadataSection1 {
  si1 section_2_encryption = NO_ENCRYPTION;   // may be negative (_DECRYPTED)
  si1 section_3_encryption = NO_ENCRYPTION;
  // protected/discretionary regions omitted (zeros on write).

  static MetadataSection1 parse(std::span<const ui1> buf);  // section-relative
  void serialize(std::span<ui1> buf) const;
};

// ---------------------------------------------------------------------------
// Time-series metadata section 2 (10752 B).
// ---------------------------------------------------------------------------
struct TimeSeriesMetadataSection2 {
  std::string channel_description;
  std::string session_description;
  si8 recording_duration = SI8_NO_ENTRY;
  std::string reference_description;
  si8 acquisition_channel_number = SI8_NO_ENTRY;
  sf8 sampling_frequency = -1.0;
  sf8 low_frequency_filter_setting = -1.0;
  sf8 high_frequency_filter_setting = -1.0;
  sf8 notch_filter_frequency_setting = -1.0;
  sf8 ac_line_frequency = -1.0;
  sf8 units_conversion_factor = 0.0;
  std::string units_description;
  sf8 maximum_native_sample_value = 0.0;
  sf8 minimum_native_sample_value = 0.0;
  si8 start_sample = 0;
  si8 number_of_samples = 0;
  si8 number_of_blocks = 0;
  si8 maximum_block_bytes = 0;
  ui4 maximum_block_samples = 0;
  ui4 maximum_difference_bytes = 0;
  si8 block_interval = 0;
  si8 number_of_discontinuities = 0;
  si8 maximum_contiguous_blocks = 0;
  si8 maximum_contiguous_block_bytes = 0;
  si8 maximum_contiguous_samples = 0;

  static TimeSeriesMetadataSection2 parse(std::span<const ui1> buf);  // section-relative
  void serialize(std::span<ui1> buf) const;
};

// ---------------------------------------------------------------------------
// Metadata section 3 (3072 B).
// ---------------------------------------------------------------------------
struct MetadataSection3 {
  si8 recording_time_offset = UUTC_NO_ENTRY;
  si8 dst_start_time = UUTC_NO_ENTRY;
  si8 dst_end_time = UUTC_NO_ENTRY;
  si4 gmt_offset = GMT_OFFSET_NO_ENTRY;
  std::string subject_name_1;
  std::string subject_name_2;
  std::string subject_id;
  std::string recording_location;

  static MetadataSection3 parse(std::span<const ui1> buf);  // section-relative
  void serialize(std::span<ui1> buf) const;
};

// ---------------------------------------------------------------------------
// Time-series index entry (56 B). One per RED block in a .tidx file.
// ---------------------------------------------------------------------------
struct TimeSeriesIndex {
  si8 file_offset = SI8_NO_ENTRY;        // byte offset of the block in .tdat
  si8 start_time = UUTC_NO_ENTRY;        // uUTC of first sample (offset-relative)
  si8 start_sample = SI8_NO_ENTRY;       // sample index within the channel
  ui4 number_of_samples = UI4_NO_ENTRY;
  ui4 block_bytes = UI4_NO_ENTRY;
  si4 maximum_sample_value = RED_NAN;
  si4 minimum_sample_value = RED_NAN;
  ui1 red_block_flags = 0;

  static TimeSeriesIndex parse(std::span<const ui1> buf);  // 56-byte entry
  void serialize(std::span<ui1> buf) const;
};

// ---------------------------------------------------------------------------
// RED block header (304 B) at the start of each compressed block in .tdat.
// ---------------------------------------------------------------------------
struct RedBlockHeader {
  ui4 crc = 0;
  ui1 flags = 0;
  sf4 detrend_slope = 0.0f;
  sf4 detrend_intercept = 0.0f;
  sf4 scale_factor = 0.0f;
  ui4 difference_bytes = 0;
  ui4 number_of_samples = 0;
  ui4 block_bytes = 0;
  si8 start_time = UUTC_NO_ENTRY;
  std::array<ui1, 256> statistics{};  // symbol frequency table

  static RedBlockHeader parse(std::span<const ui1> buf);  // >= 304 bytes
  void serialize(std::span<ui1> buf) const;

  // RED block header flag bits (from meflib.h).
  static constexpr ui1 DISCONTINUITY_MASK = 0x01;
  static constexpr ui1 LEVEL_1_ENCRYPTION_MASK = 0x02;
  static constexpr ui1 LEVEL_2_ENCRYPTION_MASK = 0x04;
};

}  // namespace mef3io::fmt
