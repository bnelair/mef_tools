// mef3io — MEF two-level password scheme.
#include <algorithm>

#include "mef3io/crypto.hpp"

namespace mef3io::crypto {

std::array<ui1, fmt::PASSWORD_BYTES> extract_password_bytes(const std::string& password) {
  // Terminal byte of each UTF-8 character, up to 16, zero-padded.
  std::array<ui1, fmt::PASSWORD_BYTES> out{};
  const auto* p = reinterpret_cast<const ui1*>(password.data());
  std::size_t i = 0, n = 0;
  while (i < password.size() && n < fmt::PASSWORD_BYTES) {
    ui1 b = p[i];
    std::size_t len;
    if ((b & 0x80) == 0x00) len = 1;
    else if ((b & 0xE0) == 0xC0) len = 2;
    else if ((b & 0xF0) == 0xE0) len = 3;
    else if ((b & 0xF8) == 0xF0) len = 4;
    else len = 1;  // invalid start byte: treat as single, don't throw
    if (i + len > password.size()) len = password.size() - i;
    out[n++] = p[i + len - 1];  // terminal byte of the sequence
    i += len;
  }
  return out;
}

AccessKeys validate_password(const std::string& password,
                             std::span<const ui1> level1_validation_field,
                             std::span<const ui1> level2_validation_field) {
  AccessKeys keys;
  if (password.empty()) return keys;  // level 0

  auto pwd = extract_password_bytes(password);
  auto sha = sha256(pwd);

  // Level 1: SHA256(pwd)[:16] == L1 validation field.
  if (std::equal(level1_validation_field.begin(),
                 level1_validation_field.begin() + fmt::PASSWORD_VALIDATION_FIELD_BYTES,
                 sha.begin())) {
    keys.access_level = fmt::LEVEL_1_ACCESS;
    keys.level1_key = pwd;
    return keys;
  }

  // Level 2: putative L1 key = SHA256(pwd)[:16] XOR L2 field; if its hash
  // matches the L1 field, `pwd` is the L2 password and grants full access.
  std::array<ui1, fmt::PASSWORD_BYTES> putative_l1{};
  for (int i = 0; i < fmt::PASSWORD_VALIDATION_FIELD_BYTES; ++i)
    putative_l1[i] = static_cast<ui1>(sha[i] ^ level2_validation_field[i]);
  auto putative_sha = sha256(putative_l1);
  if (std::equal(level1_validation_field.begin(),
                 level1_validation_field.begin() + fmt::PASSWORD_VALIDATION_FIELD_BYTES,
                 putative_sha.begin())) {
    keys.access_level = fmt::LEVEL_2_ACCESS;
    keys.level1_key = putative_l1;
    keys.level2_key = pwd;
    return keys;
  }

  return keys;  // no match -> level 0, no keys
}

ValidationFields make_validation_fields(const std::string& password1,
                                        const std::string& password2) {
  ValidationFields vf;
  if (password1.empty()) return vf;  // all zero -> unencrypted

  auto l1 = extract_password_bytes(password1);
  auto l1_hash = sha256(l1);
  std::copy_n(l1_hash.begin(), fmt::PASSWORD_VALIDATION_FIELD_BYTES, vf.level1.begin());

  if (!password2.empty()) {
    auto l2 = extract_password_bytes(password2);
    auto l2_hash = sha256(l2);
    for (int i = 0; i < fmt::PASSWORD_VALIDATION_FIELD_BYTES; ++i)
      vf.level2[i] = static_cast<ui1>(l2_hash[i] ^ l1[i]);
  }
  return vf;
}

}  // namespace mef3io::crypto
