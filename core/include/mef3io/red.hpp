// mef3io — RED (Range Encoded Differences) block decoding.
#pragma once

#include <span>
#include <vector>

#include "mef3io/crypto.hpp"
#include "mef3io/headers.hpp"
#include "mef3io/types.hpp"

namespace mef3io::red {

// Range-coder parameters (meflib.h).
inline constexpr int EXTRA_BITS = 7;
inline constexpr ui4 BOTTOM_VALUE = 0x800000u;  // 1 << 23
inline constexpr int STATISTICS_BYTES = 256;

// Round half away from zero, clamped to RED's si4 infinity sentinels
// (matches meflib RED_round).
si4 round_si4(sf8 val);

struct DecodedBlock {
  std::vector<si4> samples;
  si8 start_time = 0;      // block header start_time (offset-relative, as stored)
  bool discontinuity = false;
};

// Decode one RED block. `block` must span the whole block (header + payload,
// i.e. block_bytes long). If the block statistics are encrypted, `keys` must
// grant sufficient access or a PasswordError is thrown.
DecodedBlock decode_block(std::span<const ui1> block,
                          const crypto::AccessKeys& keys = {},
                          bool validate_crc = true);

}  // namespace mef3io::red
