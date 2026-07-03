// mef3io — CRC-32 (Koopman polynomial) as used by MEF universal/body CRCs.
#pragma once

#include <cstddef>
#include <span>

#include "mef3io/types.hpp"

namespace mef3io::crc {

// CRC-32 over `data`, matching meflib's CRC_calculate (Koopman 0x741B8CD7,
// reflected, table-driven). `initial` defaults to the MEF start value.
ui4 calculate(std::span<const ui1> data, ui4 initial = fmt::CRC_START_VALUE);

}  // namespace mef3io::crc
