// mef3io — RED block decoder. Faithful port of meflib RED_decode.
#include "mef3io/red.hpp"

#include <array>
#include <cstring>

#include "mef3io/byteio.hpp"
#include "mef3io/crc.hpp"
#include "mef3io/errors.hpp"

namespace mef3io::red {

si4 round_si4(sf8 val) {
  constexpr si4 POS_INF = 0x7FFFFFFF;
  constexpr si4 NEG_INF = static_cast<si4>(0x80000001);
  if (val >= 0.0) {
    val += 0.5;
    if (val >= static_cast<sf8>(POS_INF)) return POS_INF;
  } else {
    val -= 0.5;
    if (val <= static_cast<sf8>(NEG_INF)) return NEG_INF;
  }
  return static_cast<si4>(val);
}

DecodedBlock decode_block(std::span<const ui1> block, const crypto::AccessKeys& keys,
                          bool validate_crc) {
  using fmt::RED_BLOCK_HEADER_BYTES;
  if (block.size() < static_cast<std::size_t>(RED_BLOCK_HEADER_BYTES))
    throw FormatError("RED block smaller than header");

  fmt::RedBlockHeader bh = fmt::RedBlockHeader::parse(block);

  if (bh.block_bytes < static_cast<ui4>(RED_BLOCK_HEADER_BYTES) ||
      bh.block_bytes > block.size())
    throw FormatError("RED block_bytes inconsistent with buffer");

  if (validate_crc) {
    // CRC is over the block from byte 4 (after the stored crc) to block_bytes.
    ui4 calc = crc::calculate(block.subspan(4, bh.block_bytes - 4));
    if (calc != bh.crc) throw CrcError("RED block CRC mismatch");
  }

  DecodedBlock out;
  out.start_time = bh.start_time;
  out.discontinuity = (bh.flags & fmt::RedBlockHeader::DISCONTINUITY_MASK) != 0;

  // Decrypt the 256-byte statistics table if the block is encrypted.
  std::array<ui1, STATISTICS_BYTES> stats = bh.statistics;
  if (bh.flags & fmt::RedBlockHeader::LEVEL_1_ENCRYPTION_MASK) {
    if (keys.access_level < fmt::LEVEL_1_ACCESS || !keys.level1_key)
      throw PasswordError("RED block is level-1 encrypted; insufficient access");
    auto dec = crypto::aes128_ecb_decrypt(stats, *keys.level1_key);
    std::copy(dec.begin(), dec.end(), stats.begin());
  } else if (bh.flags & fmt::RedBlockHeader::LEVEL_2_ENCRYPTION_MASK) {
    if (keys.access_level < fmt::LEVEL_2_ACCESS || !keys.level2_key)
      throw PasswordError("RED block is level-2 encrypted; insufficient access");
    auto dec = crypto::aes128_ecb_decrypt(stats, *keys.level2_key);
    std::copy(dec.begin(), dec.end(), stats.begin());
  }

  if (bh.number_of_samples == 0) return out;  // empty block

  // Cumulative counts (257 entries).
  std::array<ui4, STATISTICS_BYTES + 1> cumulative{};
  cumulative[0] = 0;
  for (int i = 0; i < STATISTICS_BYTES; ++i) cumulative[i + 1] = cumulative[i] + stats[i];
  ui4 scaled_total = cumulative[STATISTICS_BYTES];
  if (scaled_total == 0) throw FormatError("RED block statistics sum to zero");

  // Difference buffer: implicit leading keysample marker, then decoded symbols.
  std::vector<si1> diff;
  diff.reserve(bh.difference_bytes + 1);
  diff.push_back(-128);  // keysample flag for the first sample (not coded)

  const ui1* base = block.data();
  const ui1* ib = base + RED_BLOCK_HEADER_BYTES;
  const ui1* ib_end = base + bh.block_bytes;

  ui4 in_byte = (ib < ib_end) ? *ib++ : 0;
  ui4 low_bound = in_byte >> (8 - EXTRA_BITS);
  ui4 range = 1u << EXTRA_BITS;

  for (ui4 n = 0; n < bh.difference_bytes; ++n) {
    while (range <= BOTTOM_VALUE) {
      low_bound = (low_bound << 8) | ((in_byte << EXTRA_BITS) & 0xFF);
      in_byte = (ib < ib_end) ? *ib++ : 0;
      low_bound |= in_byte >> (8 - EXTRA_BITS);
      range <<= 8;
    }
    ui4 range_per_count = range / scaled_total;
    ui4 temp = low_bound / range_per_count;
    ui4 cc = (temp >= scaled_total) ? (scaled_total - 1) : temp;

    ui4 symbol;
    if (cc > cumulative[128]) {
      ui4 s = STATISTICS_BYTES;
      while (cumulative[s] > cc) --s;
      symbol = s;
    } else {
      ui4 s = 0;
      while (cumulative[s + 1] <= cc) ++s;
      symbol = s;
    }
    ui4 sub = range_per_count * cumulative[symbol];
    low_bound -= sub;
    if (symbol < 255)
      range = range_per_count * stats[symbol];
    else
      range -= sub;
    diff.push_back(static_cast<si1>(symbol));  // 0..255 -> si1 (128..255 -> negative)
  }

  // Reconstruct samples from the difference stream.
  out.samples.resize(bh.number_of_samples);
  si4 current_val = 0;
  std::size_t di = 0;
  for (ui4 i = 0; i < bh.number_of_samples; ++i) {
    if (di >= diff.size()) throw FormatError("RED difference stream underrun");
    if (diff[di] == -128) {
      if (di + 5 > diff.size()) throw FormatError("RED keysample truncated");
      // Next 4 bytes are the little-endian si4 sample value.
      ui1 b0 = static_cast<ui1>(diff[di + 1]);
      ui1 b1 = static_cast<ui1>(diff[di + 2]);
      ui1 b2 = static_cast<ui1>(diff[di + 3]);
      ui1 b3 = static_cast<ui1>(diff[di + 4]);
      current_val = static_cast<si4>(static_cast<ui4>(b0) | (static_cast<ui4>(b1) << 8) |
                                     (static_cast<ui4>(b2) << 16) | (static_cast<ui4>(b3) << 24));
      di += 5;
    } else {
      current_val += diff[di];
      di += 1;
    }
    out.samples[i] = current_val;
  }

  // Unscale then retrend (order matches RED_decode).
  if (bh.scale_factor > 1.0f) {
    sf8 sf = bh.scale_factor;
    for (auto& s : out.samples) s = round_si4(static_cast<sf8>(s) * sf);
  }
  if (bh.detrend_slope != 0.0f || bh.detrend_intercept != 0.0f) {
    sf8 m = bh.detrend_slope, b = bh.detrend_intercept, c = 0.0;
    for (auto& s : out.samples) {
      c += 1.0;
      s = round_si4(static_cast<sf8>(s) + m * c + b);
    }
  }

  return out;
}

}  // namespace mef3io::red
