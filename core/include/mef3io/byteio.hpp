// mef3io — little-endian field read/write over byte buffers.
//
// The MEF spec fixes little-endian on disk. We never reinterpret_cast packed
// structs (alignment/aliasing UB); every field goes through these helpers with
// an explicit offset, so the code is portable regardless of host endianness.
#pragma once

#include <cstring>
#include <span>
#include <string>
#include <type_traits>

#include "mef3io/errors.hpp"
#include "mef3io/types.hpp"

namespace mef3io::byteio {

constexpr bool host_is_little_endian() {
  // Compile-time on every compiler we target; avoids a runtime union hack.
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
  return __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__;
#else
  return true;  // all supported targets (x86_64, arm64, Win) are little-endian
#endif
}

template <typename T>
T byteswap(T v) {
  static_assert(std::is_trivially_copyable_v<T>);
  ui1 b[sizeof(T)];
  std::memcpy(b, &v, sizeof(T));
  for (std::size_t i = 0; i < sizeof(T) / 2; ++i) std::swap(b[i], b[sizeof(T) - 1 - i]);
  T out;
  std::memcpy(&out, b, sizeof(T));
  return out;
}

// Read a little-endian scalar of type T at `offset` in `buf`.
template <typename T>
T read(std::span<const ui1> buf, std::size_t offset) {
  static_assert(std::is_trivially_copyable_v<T>);
  if (offset + sizeof(T) > buf.size())
    throw FormatError("byteio::read out of range at offset " + std::to_string(offset));
  T v;
  std::memcpy(&v, buf.data() + offset, sizeof(T));
  if constexpr (sizeof(T) > 1)
    if (!host_is_little_endian()) v = byteswap(v);
  return v;
}

// Write a little-endian scalar of type T at `offset` in `buf`.
template <typename T>
void write(std::span<ui1> buf, std::size_t offset, T v) {
  static_assert(std::is_trivially_copyable_v<T>);
  if (offset + sizeof(T) > buf.size())
    throw FormatError("byteio::write out of range at offset " + std::to_string(offset));
  if constexpr (sizeof(T) > 1)
    if (!host_is_little_endian()) v = byteswap(v);
  std::memcpy(buf.data() + offset, &v, sizeof(T));
}

// Read a fixed-width, null-terminated UTF-8/ASCII string field.
inline std::string read_string(std::span<const ui1> buf, std::size_t offset, std::size_t max_len) {
  if (offset + max_len > buf.size())
    throw FormatError("byteio::read_string out of range at offset " + std::to_string(offset));
  const ui1* p = buf.data() + offset;
  std::size_t n = 0;
  while (n < max_len && p[n] != 0) ++n;
  return std::string(reinterpret_cast<const char*>(p), n);
}

// Write a string into a fixed-width field: null-padded, truncated to field_len.
// A field_len-length string is stored without a null terminator (matches MEF,
// where the max content length is field_len - 1 by convention but the last
// byte is still usable for exact-fit strings written by some tools).
inline void write_string(std::span<ui1> buf, std::size_t offset, std::size_t field_len,
                         const std::string& s) {
  if (offset + field_len > buf.size())
    throw FormatError("byteio::write_string out of range at offset " + std::to_string(offset));
  ui1* p = buf.data() + offset;
  std::memset(p, 0, field_len);
  std::size_t n = std::min(s.size(), field_len);
  std::memcpy(p, s.data(), n);
}

}  // namespace mef3io::byteio
