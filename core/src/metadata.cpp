// mef3io — .tmet loader with CRC validation, password check, decryption.
#include "mef3io/metadata.hpp"

#include <vector>

#include "mef3io/crypto.hpp"
#include "mef3io/errors.hpp"

namespace mef3io {

TimeSeriesMetadata load_time_series_metadata(std::span<const ui1> tmet_bytes,
                                             const std::string& password) {
  using namespace fmt;
  if (tmet_bytes.size() < METADATA_FILE_BYTES)
    throw FormatError("tmet file too small: expected " + std::to_string(METADATA_FILE_BYTES) +
                      " bytes, got " + std::to_string(tmet_bytes.size()));

  TimeSeriesMetadata md;
  md.universal_header = UniversalHeader::parse(tmet_bytes);
  if (!md.universal_header.header_crc_valid(tmet_bytes))
    throw CrcError("tmet universal header CRC mismatch");

  // Section 1 is never encrypted.
  auto s1_bytes = tmet_bytes.subspan(METADATA_SECTION_1_OFFSET, METADATA_SECTION_1_BYTES);
  md.section1 = MetadataSection1::parse(s1_bytes);

  // Only a strictly positive encryption level means the section is encrypted
  // on disk. A negative "_DECRYPTED" sentinel (e.g. -1) marks a section that is
  // conceptually encryptable but currently stored as plaintext (unencrypted
  // files), and 0 means never encrypted.
  int s2_enc = md.section1.section_2_encryption > 0 ? md.section1.section_2_encryption : 0;
  int s3_enc = md.section1.section_3_encryption > 0 ? md.section1.section_3_encryption : 0;
  const bool encrypted = s2_enc > 0 || s3_enc > 0;

  crypto::AccessKeys keys;
  if (encrypted) {
    keys = crypto::validate_password(
        password, md.universal_header.level_1_password_validation_field,
        md.universal_header.level_2_password_validation_field);
    if (keys.access_level == LEVEL_0_ACCESS)
      throw PasswordError("tmet is encrypted and the password is missing or incorrect");
  }
  md.access_level = keys.access_level;

  // Copy the two section images so we can decrypt without mutating the input.
  std::vector<ui1> s2(tmet_bytes.begin() + METADATA_SECTION_2_OFFSET,
                      tmet_bytes.begin() + METADATA_SECTION_2_OFFSET +
                          TIME_SERIES_METADATA_SECTION_2_BYTES);
  std::vector<ui1> s3(tmet_bytes.begin() + METADATA_SECTION_3_OFFSET,
                      tmet_bytes.begin() + METADATA_SECTION_3_OFFSET + METADATA_SECTION_3_BYTES);

  auto key_for = [&](int level) -> std::span<const ui1> {
    if (level == LEVEL_1_ENCRYPTION && keys.level1_key) return *keys.level1_key;
    if (level == LEVEL_2_ENCRYPTION && keys.level2_key) return *keys.level2_key;
    return {};
  };

  if (s2_enc > 0) {
    auto key = key_for(s2_enc);
    if (key.empty()) throw PasswordError("insufficient access to decrypt metadata section 2");
    auto dec = crypto::aes128_ecb_decrypt(s2, key);
    std::copy(dec.begin(), dec.end(), s2.begin());
  }
  md.section2 = TimeSeriesMetadataSection2::parse(s2);

  if (s3_enc > 0) {
    auto key = key_for(s3_enc);
    if (key.empty()) {
      // L2 section not accessible with an L1 password: leave section3 default.
      md.section3_available = false;
    } else {
      auto dec = crypto::aes128_ecb_decrypt(s3, key);
      std::copy(dec.begin(), dec.end(), s3.begin());
      md.section3 = MetadataSection3::parse(s3);
    }
  } else {
    md.section3 = MetadataSection3::parse(s3);
  }

  return md;
}

}  // namespace mef3io
