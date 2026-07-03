// mef3io — AES-128 (FIPS 197), ECB mode. Compact reference implementation.
// MEF encrypts metadata sections and record bodies with AES-128-ECB.
#include <cstring>

#include "mef3io/crypto.hpp"
#include "mef3io/errors.hpp"

namespace mef3io::crypto {
namespace {

constexpr int Nb = 4, Nk = 4, Nr = 10;  // AES-128

constexpr ui1 sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

ui1 rsbox[256];
bool rsbox_ready = false;
void init_rsbox() {
  if (rsbox_ready) return;
  for (int i = 0; i < 256; ++i) rsbox[sbox[i]] = static_cast<ui1>(i);
  rsbox_ready = true;
}

constexpr ui1 rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

inline ui1 xtime(ui1 x) { return static_cast<ui1>((x << 1) ^ ((x >> 7) * 0x1b)); }

ui1 mul(ui1 x, ui1 y) {
  ui1 r = 0;
  for (int i = 0; i < 8; ++i) {
    if (y & 1) r ^= x;
    ui1 hi = x & 0x80;
    x <<= 1;
    if (hi) x ^= 0x1b;
    y >>= 1;
  }
  return r;
}

using RoundKey = ui1[176];  // (Nr+1)*16

void key_expansion(RoundKey rk, std::span<const ui1> key) {
  for (int i = 0; i < 16; ++i) rk[i] = key[i];
  ui1 tmp[4];
  for (int i = Nk; i < Nb * (Nr + 1); ++i) {
    for (int j = 0; j < 4; ++j) tmp[j] = rk[(i - 1) * 4 + j];
    if (i % Nk == 0) {
      ui1 t = tmp[0];
      tmp[0] = static_cast<ui1>(sbox[tmp[1]] ^ rcon[i / Nk]);
      tmp[1] = sbox[tmp[2]];
      tmp[2] = sbox[tmp[3]];
      tmp[3] = sbox[t];
    }
    for (int j = 0; j < 4; ++j) rk[i * 4 + j] = static_cast<ui1>(rk[(i - Nk) * 4 + j] ^ tmp[j]);
  }
}

void add_round_key(ui1* s, const ui1* rk, int round) {
  for (int i = 0; i < 16; ++i) s[i] ^= rk[round * 16 + i];
}

void sub_bytes(ui1* s) { for (int i = 0; i < 16; ++i) s[i] = sbox[s[i]]; }
void inv_sub_bytes(ui1* s) { for (int i = 0; i < 16; ++i) s[i] = rsbox[s[i]]; }

// State is column-major: s[c*4 + r].
void shift_rows(ui1* s) {
  ui1 t;
  t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
  std::swap(s[2], s[10]); std::swap(s[6], s[14]);
  t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}
void inv_shift_rows(ui1* s) {
  ui1 t;
  t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
  std::swap(s[2], s[10]); std::swap(s[6], s[14]);
  t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

void mix_columns(ui1* s) {
  for (int c = 0; c < 4; ++c) {
    ui1* col = s + c * 4;
    ui1 a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
    col[0] = static_cast<ui1>(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
    col[1] = static_cast<ui1>(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
    col[2] = static_cast<ui1>(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
    col[3] = static_cast<ui1>((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
  }
}
void inv_mix_columns(ui1* s) {
  for (int c = 0; c < 4; ++c) {
    ui1* col = s + c * 4;
    ui1 a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
    col[0] = static_cast<ui1>(mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9));
    col[1] = static_cast<ui1>(mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13));
    col[2] = static_cast<ui1>(mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11));
    col[3] = static_cast<ui1>(mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14));
  }
}

void encrypt_block(ui1* s, const RoundKey rk) {
  add_round_key(s, rk, 0);
  for (int round = 1; round < Nr; ++round) {
    sub_bytes(s); shift_rows(s); mix_columns(s); add_round_key(s, rk, round);
  }
  sub_bytes(s); shift_rows(s); add_round_key(s, rk, Nr);
}
void decrypt_block(ui1* s, const RoundKey rk) {
  add_round_key(s, rk, Nr);
  for (int round = Nr - 1; round > 0; --round) {
    inv_shift_rows(s); inv_sub_bytes(s); add_round_key(s, rk, round); inv_mix_columns(s);
  }
  inv_shift_rows(s); inv_sub_bytes(s); add_round_key(s, rk, 0);
}

void check(std::span<const ui1> data, std::span<const ui1> key) {
  if (key.size() != fmt::PASSWORD_BYTES) throw PasswordError("AES-128 key must be 16 bytes");
  if (data.size() % fmt::ENCRYPTION_BLOCK_BYTES != 0)
    throw FormatError("AES-ECB data length must be a multiple of 16 bytes");
}

}  // namespace

std::vector<ui1> aes128_ecb_encrypt(std::span<const ui1> data, std::span<const ui1> key) {
  check(data, key);
  RoundKey rk;
  key_expansion(rk, key);
  std::vector<ui1> out(data.begin(), data.end());
  for (std::size_t i = 0; i < out.size(); i += 16) encrypt_block(out.data() + i, rk);
  return out;
}

std::vector<ui1> aes128_ecb_decrypt(std::span<const ui1> data, std::span<const ui1> key) {
  check(data, key);
  init_rsbox();
  RoundKey rk;
  key_expansion(rk, key);
  std::vector<ui1> out(data.begin(), data.end());
  for (std::size_t i = 0; i < out.size(); i += 16) decrypt_block(out.data() + i, rk);
  return out;
}

}  // namespace mef3io::crypto
