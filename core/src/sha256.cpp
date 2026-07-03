// mef3io — SHA-256 (FIPS 180-4). Compact reference implementation.
#include <cstring>

#include "mef3io/crypto.hpp"

namespace mef3io::crypto {
namespace {

constexpr ui4 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline ui4 rotr(ui4 x, ui4 n) { return (x >> n) | (x << (32 - n)); }

}  // namespace

std::array<ui1, 32> sha256(std::span<const ui1> data) {
  ui4 h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  const ui8 bitlen = static_cast<ui8>(data.size()) * 8;
  // Message + 0x80 + zero pad to 56 mod 64 + 8-byte big-endian length.
  std::vector<ui1> msg(data.begin(), data.end());
  msg.push_back(0x80);
  while (msg.size() % 64 != 56) msg.push_back(0x00);
  for (int i = 7; i >= 0; --i) msg.push_back(static_cast<ui1>((bitlen >> (i * 8)) & 0xFF));

  ui4 w[64];
  for (std::size_t chunk = 0; chunk < msg.size(); chunk += 64) {
    for (int i = 0; i < 16; ++i) {
      w[i] = (static_cast<ui4>(msg[chunk + i * 4]) << 24) |
             (static_cast<ui4>(msg[chunk + i * 4 + 1]) << 16) |
             (static_cast<ui4>(msg[chunk + i * 4 + 2]) << 8) |
             (static_cast<ui4>(msg[chunk + i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
      ui4 s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      ui4 s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    ui4 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
      ui4 S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      ui4 ch = (e & f) ^ (~e & g);
      ui4 t1 = hh + S1 + ch + K[i] + w[i];
      ui4 S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      ui4 maj = (a & b) ^ (a & c) ^ (b & c);
      ui4 t2 = S0 + maj;
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  std::array<ui1, 32> out{};
  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<ui1>((h[i] >> 24) & 0xFF);
    out[i * 4 + 1] = static_cast<ui1>((h[i] >> 16) & 0xFF);
    out[i * 4 + 2] = static_cast<ui1>((h[i] >> 8) & 0xFF);
    out[i * 4 + 3] = static_cast<ui1>(h[i] & 0xFF);
  }
  return out;
}

}  // namespace mef3io::crypto
