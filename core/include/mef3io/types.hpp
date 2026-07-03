// mef3io — MEF 3.0 primitive types and format constants.
//
// Type aliases mirror the meflib naming (si1, ui4, sf8, ...) so field tables
// transcribed from the spec read the same here as in the reference sources,
// but they are defined against fixed-width <cstdint> types rather than
// platform C types.
#pragma once

#include <cstdint>

namespace mef3io {

using si1 = std::int8_t;
using ui1 = std::uint8_t;
using si2 = std::int16_t;
using ui2 = std::uint16_t;
using si4 = std::int32_t;
using ui4 = std::uint32_t;
using si8 = std::int64_t;
using ui8 = std::uint64_t;
using sf4 = float;
using sf8 = double;

static_assert(sizeof(sf4) == 4, "sf4 must be 32-bit IEEE float");
static_assert(sizeof(sf8) == 8, "sf8 must be 64-bit IEEE double");

namespace fmt {

// --- Universal header ---
inline constexpr int UNIVERSAL_HEADER_BYTES = 1024;

// --- Metadata file layout (16 KB total) ---
inline constexpr int METADATA_FILE_BYTES = 16384;
inline constexpr int METADATA_SECTION_1_BYTES = 1536;
inline constexpr int TIME_SERIES_METADATA_SECTION_2_BYTES = 10752;
inline constexpr int METADATA_SECTION_3_BYTES = 3072;

inline constexpr int METADATA_SECTION_1_OFFSET = UNIVERSAL_HEADER_BYTES;             // 1024
inline constexpr int METADATA_SECTION_2_OFFSET =                                    // 2560
    METADATA_SECTION_1_OFFSET + METADATA_SECTION_1_BYTES;
inline constexpr int METADATA_SECTION_3_OFFSET =                                    // 13312
    METADATA_SECTION_2_OFFSET + TIME_SERIES_METADATA_SECTION_2_BYTES;

// --- Index + block ---
inline constexpr int TIME_SERIES_INDEX_BYTES = 56;
inline constexpr int RED_BLOCK_HEADER_BYTES = 304;

// --- Crypto ---
inline constexpr int PASSWORD_BYTES = 16;                  // AES-128 key length
inline constexpr int PASSWORD_VALIDATION_FIELD_BYTES = 16;
inline constexpr int ENCRYPTION_BLOCK_BYTES = 16;          // AES ECB block

// --- Version / byte order ---
inline constexpr ui1 MEF_VERSION_MAJOR = 3;
inline constexpr ui1 MEF_VERSION_MINOR = 0;
inline constexpr ui1 MEF_LITTLE_ENDIAN = 1;
inline constexpr ui1 MEF_BIG_ENDIAN = 0;

// --- Encryption levels ---
inline constexpr si1 NO_ENCRYPTION = 0;
inline constexpr si1 LEVEL_1_ENCRYPTION = 1;
inline constexpr si1 LEVEL_2_ENCRYPTION = 2;

inline constexpr int LEVEL_0_ACCESS = 0;
inline constexpr int LEVEL_1_ACCESS = 1;
inline constexpr int LEVEL_2_ACCESS = 2;

// --- "No entry" sentinels (from meflib.h) ---
inline constexpr si8 UUTC_NO_ENTRY = static_cast<si8>(0x8000000000000000ULL);  // INT64_MIN
inline constexpr si8 SI8_NO_ENTRY = -1;
inline constexpr si4 SI4_NO_ENTRY = -1;
inline constexpr ui4 UI4_NO_ENTRY = 0xFFFFFFFFu;
inline constexpr si4 GMT_OFFSET_NO_ENTRY = -86401;
inline constexpr si4 RED_NAN = static_cast<si4>(0x80000000);  // INT32_MIN

// --- CRC ---
inline constexpr ui4 CRC_START_VALUE = 0xFFFFFFFFu;

// --- File type strings (4 chars + null in a 5-byte field) ---
inline constexpr const char* FILE_TYPE_SESSION = "mefd";
inline constexpr const char* FILE_TYPE_TS_CHANNEL = "timd";
inline constexpr const char* FILE_TYPE_TS_SEGMENT = "segd";
inline constexpr const char* FILE_TYPE_TS_METADATA = "tmet";
inline constexpr const char* FILE_TYPE_TS_INDICES = "tidx";
inline constexpr const char* FILE_TYPE_TS_DATA = "tdat";
inline constexpr const char* FILE_TYPE_RECORD_DATA = "rdat";
inline constexpr const char* FILE_TYPE_RECORD_INDICES = "ridx";

}  // namespace fmt
}  // namespace mef3io
