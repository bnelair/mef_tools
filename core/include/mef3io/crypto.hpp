// mef3io — cryptography for MEF: SHA-256, AES-128-ECB, and the two-level
// password scheme. Self-contained (no external crypto dependency); validated
// against NIST vectors and Python's `cryptography` in the test suite.
#pragma once

#include <array>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "mef3io/types.hpp"

namespace mef3io::crypto {

// --- SHA-256 ---
std::array<ui1, 32> sha256(std::span<const ui1> data);

// --- AES-128-ECB ---
// key must be 16 bytes; buffers must be a multiple of 16 bytes. Operates on a
// copy and returns it (metadata sections are small; clarity over in-place).
std::vector<ui1> aes128_ecb_encrypt(std::span<const ui1> data, std::span<const ui1> key);
std::vector<ui1> aes128_ecb_decrypt(std::span<const ui1> data, std::span<const ui1> key);

// --- Password scheme ---

// Terminal byte of each UTF-8 char, up to 16, zero-padded (meflib
// extract_terminal_password_bytes).
std::array<ui1, fmt::PASSWORD_BYTES> extract_password_bytes(const std::string& password);

// Result of validating a user password against a universal header's fields.
struct AccessKeys {
  int access_level = fmt::LEVEL_0_ACCESS;
  std::optional<std::array<ui1, fmt::PASSWORD_BYTES>> level1_key;  // decrypts L1 sections
  std::optional<std::array<ui1, fmt::PASSWORD_BYTES>> level2_key;  // decrypts L2 sections
};

// Validate `password` against the two 16-byte validation fields from a
// universal header. Empty/no password with all-zero fields -> level 0 (file
// unencrypted). Wrong password -> level 0 with no keys.
AccessKeys validate_password(const std::string& password,
                             std::span<const ui1> level1_validation_field,
                             std::span<const ui1> level2_validation_field);

// Build the validation fields for writing. l2 requires l1.
struct ValidationFields {
  std::array<ui1, fmt::PASSWORD_VALIDATION_FIELD_BYTES> level1{};
  std::array<ui1, fmt::PASSWORD_VALIDATION_FIELD_BYTES> level2{};
};
ValidationFields make_validation_fields(const std::string& password1, const std::string& password2);

}  // namespace mef3io::crypto
