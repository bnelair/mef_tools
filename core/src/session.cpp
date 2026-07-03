// mef3io — session tree discovery and low-level indexed reads.
#include "mef3io/session.hpp"

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>

#include "mef3io/errors.hpp"
#include "mef3io/red.hpp"

namespace fs = std::filesystem;

namespace mef3io {
namespace {

std::vector<ui1> read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f) throw IoError("cannot open file: " + path);
  auto size = f.tellg();
  f.seekg(0);
  std::vector<ui1> buf(static_cast<std::size_t>(size));
  if (!f.read(reinterpret_cast<char*>(buf.data()), size))
    throw IoError("short read: " + path);
  return buf;
}

// Convert an on-disk MEF time to a user-facing absolute uUTC. meflib marks
// "recording-time-offset applied" times by negating them; the true time is
// recovered as (-stored + rto). Non-negative values are already user times
// (offset not applied). Mirrors meflib remove_recording_time_offset.
si8 to_user_time(si8 t, si8 rto) {
  if (t == fmt::UUTC_NO_ENTRY) return t;
  if (t >= 0) return t;
  return -t + rto;
}

int segment_number_from_name(const std::string& stem) {
  // "<channel>-000000" -> 0
  auto dash = stem.rfind('-');
  if (dash == std::string::npos) return 0;
  try {
    return std::stoi(stem.substr(dash + 1));
  } catch (...) {
    return 0;
  }
}

}  // namespace

Session::Session(const std::string& mefd_path, std::string password)
    : mefd_path_(mefd_path), password_(std::move(password)) {
  if (!fs::is_directory(mefd_path_)) throw IoError("session path is not a directory: " + mefd_path_);
  discover();
}

void Session::discover() {
  for (const auto& entry : fs::directory_iterator(mefd_path_)) {
    if (!entry.is_directory()) continue;
    const auto path = entry.path();
    const std::string ext = path.extension().string();
    if (ext == ".vidd") continue;  // video channels are out of scope; skip silently
    if (ext != ".timd") continue;

    Channel ch;
    ch.info.name = path.stem().string();

    for (const auto& seg_entry : fs::directory_iterator(path)) {
      if (!seg_entry.is_directory() || seg_entry.path().extension() != ".segd") continue;
      const auto seg_path = seg_entry.path();
      const std::string seg_stem = seg_path.stem().string();
      SegmentReader seg;
      seg.segment_number = segment_number_from_name(seg_stem);
      seg.tmet_path = (seg_path / (seg_stem + ".tmet")).string();
      seg.tidx_path = (seg_path / (seg_stem + ".tidx")).string();
      seg.tdat_path = (seg_path / (seg_stem + ".tdat")).string();
      if (fs::exists(seg.tmet_path) && fs::exists(seg.tidx_path) && fs::exists(seg.tdat_path))
        ch.segments.push_back(std::move(seg));
    }
    if (ch.segments.empty()) continue;

    std::sort(ch.segments.begin(), ch.segments.end(),
              [](const SegmentReader& a, const SegmentReader& b) {
                return a.segment_number < b.segment_number;
              });

    load_channel_basic_info(ch);
    channel_names_.push_back(ch.info.name);
    channels_.emplace(ch.info.name, std::move(ch));
  }
  std::sort(channel_names_.begin(), channel_names_.end());
}

TimeSeriesMetadata& Session::segment_metadata(SegmentReader& seg) {
  if (!seg.metadata) {
    auto bytes = read_file(seg.tmet_path);
    seg.metadata = load_time_series_metadata(bytes, password_);
  }
  return *seg.metadata;
}

std::span<const ui1> Session::segment_index(SegmentReader& seg) {
  if (seg.tidx_bytes.empty()) seg.tidx_bytes = read_file(seg.tidx_path);
  return seg.tidx_bytes;
}

void Session::load_channel_basic_info(Channel& ch) {
  ChannelInfo& info = ch.info;
  info.n_segments = static_cast<int>(ch.segments.size());
  bool first = true;
  for (auto& seg : ch.segments) {
    auto& md = segment_metadata(seg);
    si8 rto = md.section3_available ? md.section3.recording_time_offset : 0;
    if (rto == fmt::UUTC_NO_ENTRY) rto = 0;
    si8 seg_start = to_user_time(md.universal_header.start_time, rto);
    si8 seg_end = to_user_time(md.universal_header.end_time, rto);
    if (first) {
      info.sampling_frequency = md.section2.sampling_frequency;
      info.units_conversion_factor = md.section2.units_conversion_factor;
      info.units_description = md.section2.units_description;
      info.recording_time_offset = rto;
      info.start_time = seg_start;
      info.end_time = seg_end;
      first = false;
    } else {
      info.start_time = std::min(info.start_time, seg_start);
      info.end_time = std::max(info.end_time, seg_end);
    }
    info.number_of_samples += md.section2.number_of_samples;
  }
}

const ChannelInfo& Session::channel_info(const std::string& name) const {
  auto it = channels_.find(name);
  if (it == channels_.end()) throw std::out_of_range("no such channel: " + name);
  return it->second.info;
}

std::vector<DataRun> Session::read_runs(const std::string& channel, std::optional<si8> t0_opt,
                                        std::optional<si8> t1_opt) {
  auto it = channels_.find(channel);
  if (it == channels_.end()) throw std::out_of_range("no such channel: " + channel);
  Channel& ch = it->second;

  const si8 t0 = t0_opt.value_or(ch.info.start_time);
  const si8 t1 = t1_opt.value_or(ch.info.end_time + 1);
  const sf8 fs = ch.info.sampling_frequency;

  std::vector<DataRun> runs;
  DataRun* current = nullptr;
  si8 expected_next_sample = -1;

  for (auto& seg : ch.segments) {
    auto& md = segment_metadata(seg);
    si8 rto = md.section3_available ? md.section3.recording_time_offset : 0;
    if (rto == fmt::UUTC_NO_ENTRY) rto = 0;

    auto idx = segment_index(seg);
    const std::size_t n_entries =
        (idx.size() - fmt::UNIVERSAL_HEADER_BYTES) / fmt::TIME_SERIES_INDEX_BYTES;
    auto tdat = read_file(seg.tdat_path);

    crypto::AccessKeys keys = crypto::validate_password(
        password_, md.universal_header.level_1_password_validation_field,
        md.universal_header.level_2_password_validation_field);

    for (std::size_t i = 0; i < n_entries; ++i) {
      auto entry_bytes =
          idx.subspan(fmt::UNIVERSAL_HEADER_BYTES + i * fmt::TIME_SERIES_INDEX_BYTES,
                      fmt::TIME_SERIES_INDEX_BYTES);
      auto e = fmt::TimeSeriesIndex::parse(entry_bytes);
      if (e.file_offset < 0 || e.number_of_samples == 0) continue;

      si8 block_start = to_user_time(e.start_time, rto);
      si8 block_end = block_start + static_cast<si8>(std::llround(e.number_of_samples * 1e6 / fs));
      if (block_end <= t0 || block_start >= t1) continue;  // outside requested range

      if (static_cast<std::size_t>(e.file_offset) + e.block_bytes > tdat.size())
        throw FormatError("index points past end of .tdat");
      std::span<const ui1> block(tdat.data() + e.file_offset, e.block_bytes);
      auto decoded = red::decode_block(block, keys);

      // Start a new run on discontinuity or a sample-index gap.
      bool contiguous = current != nullptr && !decoded.discontinuity &&
                        e.start_sample == expected_next_sample;
      if (!contiguous) {
        runs.push_back(DataRun{block_start, e.start_sample, {}});
        current = &runs.back();
      }
      current->samples.insert(current->samples.end(), decoded.samples.begin(),
                              decoded.samples.end());
      expected_next_sample = e.start_sample + e.number_of_samples;
    }
  }
  return runs;
}

}  // namespace mef3io
