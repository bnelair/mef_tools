// mef3io — session/channel/segment tree and low-level indexed reads.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "mef3io/headers.hpp"
#include "mef3io/metadata.hpp"
#include "mef3io/types.hpp"

namespace mef3io {

// A contiguous run of decoded samples starting at an absolute uUTC time.
// Discontinuities produce separate runs.
struct DataRun {
  si8 start_uutc = 0;      // absolute (recording_time_offset applied)
  si8 start_sample = 0;    // channel-wide sample index of the first sample
  std::vector<si4> samples;
};

struct SegmentReader {
  std::string tmet_path;
  std::string tidx_path;
  std::string tdat_path;
  int segment_number = 0;
  std::optional<TimeSeriesMetadata> metadata;      // loaded lazily
  std::vector<ui1> tidx_bytes;                      // loaded lazily (whole file)
};

struct ChannelInfo {
  std::string name;
  sf8 sampling_frequency = 0.0;
  sf8 units_conversion_factor = 1.0;
  std::string units_description;
  si8 start_time = 0;      // absolute uUTC
  si8 end_time = 0;        // absolute uUTC
  si8 number_of_samples = 0;
  si8 recording_time_offset = 0;
  int n_segments = 0;
};

class Session {
 public:
  // Discover the session tree and load per-channel basic info (lazy on data).
  Session(const std::string& mefd_path, std::string password = "");

  const std::vector<std::string>& channels() const { return channel_names_; }
  const ChannelInfo& channel_info(const std::string& name) const;

  // Decode all blocks of `channel` overlapping [t0, t1] (absolute uUTC;
  // defaults span the whole channel). Returns contiguous runs split on
  // discontinuities. Samples are the raw int32 stored values (no scaling,
  // no trimming to exact sample yet — that is the high-level Reader's job).
  std::vector<DataRun> read_runs(const std::string& channel,
                                 std::optional<si8> t0 = std::nullopt,
                                 std::optional<si8> t1 = std::nullopt);

 private:
  struct Channel {
    ChannelInfo info;
    std::vector<SegmentReader> segments;  // sorted by segment number
  };

  void discover();
  void load_channel_basic_info(Channel& ch);
  TimeSeriesMetadata& segment_metadata(SegmentReader& seg);
  std::span<const ui1> segment_index(SegmentReader& seg);

  std::string mefd_path_;
  std::string password_;
  std::vector<std::string> channel_names_;
  std::map<std::string, Channel> channels_;
};

}  // namespace mef3io
