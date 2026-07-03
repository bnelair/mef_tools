// mef3io — load and decrypt a time-series metadata (.tmet) file.
#pragma once

#include <span>
#include <string>

#include "mef3io/headers.hpp"

namespace mef3io {

struct TimeSeriesMetadata {
  fmt::UniversalHeader universal_header;
  fmt::MetadataSection1 section1;
  fmt::TimeSeriesMetadataSection2 section2;
  fmt::MetadataSection3 section3;
  int access_level = fmt::LEVEL_0_ACCESS;  // level attained with the password
  bool section3_available = true;          // false if L2-encrypted and only L1 access
};

// Parse a 16 KB .tmet image. Validates the universal-header CRC (throws
// CrcError on mismatch), then, if encrypted, validates `password` and decrypts
// sections 2/3 in place before parsing. Section 3 requires L2 access when
// L2-encrypted; if the password only grants L1, section3_available is false
// and section3 holds parsed-but-still-encrypted garbage (callers should not
// use it in that case).
TimeSeriesMetadata load_time_series_metadata(std::span<const ui1> tmet_bytes,
                                             const std::string& password = "");

}  // namespace mef3io
