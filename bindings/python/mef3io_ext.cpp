// mef3io — nanobind bindings. Fleshed out per phase; P0 exposes just enough
// (crc + version) to prove the toolchain end to end.
#include <nanobind/nanobind.h>
#include <nanobind/ndarray.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include <span>
#include <vector>

#include "mef3io/crc.hpp"
#include "mef3io/crypto.hpp"
#include "mef3io/metadata.hpp"
#include "mef3io/session.hpp"
#include "mef3io/types.hpp"

namespace nb = nanobind;

namespace {
// Move a vector<T> onto the heap and hand numpy ownership via a capsule.
template <typename T>
nb::ndarray<nb::numpy, T> vec_to_numpy(std::vector<T>&& v) {
  auto* heap = new std::vector<T>(std::move(v));
  nb::capsule owner(heap, [](void* p) noexcept { delete static_cast<std::vector<T>*>(p); });
  size_t n = heap->size();
  return nb::ndarray<nb::numpy, T>(heap->data(), {n}, owner);
}
}  // namespace

namespace {
std::span<const mef3io::ui1> as_span(nb::bytes b) {
  return {reinterpret_cast<const mef3io::ui1*>(b.c_str()), b.size()};
}
nb::bytes to_bytes(std::span<const mef3io::ui1> s) {
  return nb::bytes(reinterpret_cast<const char*>(s.data()), s.size());
}
}  // namespace

NB_MODULE(_mef3io, m) {
  m.doc() = "mef3io C++ backend (nanobind extension)";
  m.attr("__mef_version_major__") = mef3io::fmt::MEF_VERSION_MAJOR;
  m.attr("__mef_version_minor__") = mef3io::fmt::MEF_VERSION_MINOR;

  // Exposed for parity tests against the Python oracles.
  m.def(
      "crc32", [](nb::bytes data) { return mef3io::crc::calculate(as_span(data)); },
      nb::arg("data"), "CRC-32 (Koopman) over the given bytes.");

  m.def(
      "sha256",
      [](nb::bytes data) {
        auto h = mef3io::crypto::sha256(as_span(data));
        return to_bytes(h);
      },
      nb::arg("data"));

  m.def(
      "aes128_ecb_encrypt",
      [](nb::bytes data, nb::bytes key) {
        return to_bytes(mef3io::crypto::aes128_ecb_encrypt(as_span(data), as_span(key)));
      },
      nb::arg("data"), nb::arg("key"));

  m.def(
      "aes128_ecb_decrypt",
      [](nb::bytes data, nb::bytes key) {
        return to_bytes(mef3io::crypto::aes128_ecb_decrypt(as_span(data), as_span(key)));
      },
      nb::arg("data"), nb::arg("key"));

  m.def("extract_password_bytes", [](const std::string& p) {
    auto b = mef3io::crypto::extract_password_bytes(p);
    return to_bytes(b);
  });

  m.def("validate_password", [](const std::string& password, nb::bytes l1, nb::bytes l2) {
    auto keys = mef3io::crypto::validate_password(password, as_span(l1), as_span(l2));
    return keys.access_level;
  });

  // Parse a .tmet image -> dict of the fields the reader cares about. Used by
  // the P1 test to validate struct layout + decryption against golden files.
  m.def(
      "parse_tmet",
      [](nb::bytes tmet, const std::string& password) {
        auto md = mef3io::load_time_series_metadata(as_span(tmet), password);
        nb::dict d;
        d["channel_name"] = md.universal_header.channel_name;
        d["session_name"] = md.universal_header.session_name;
        d["segment_number"] = md.universal_header.segment_number;
        d["start_time"] = md.universal_header.start_time;
        d["end_time"] = md.universal_header.end_time;
        d["access_level"] = md.access_level;
        d["section3_available"] = md.section3_available;
        d["sampling_frequency"] = md.section2.sampling_frequency;
        d["units_conversion_factor"] = md.section2.units_conversion_factor;
        d["units_description"] = md.section2.units_description;
        d["number_of_samples"] = md.section2.number_of_samples;
        d["number_of_blocks"] = md.section2.number_of_blocks;
        d["start_sample"] = md.section2.start_sample;
        d["recording_time_offset"] = md.section3.recording_time_offset;
        d["gmt_offset"] = md.section3.gmt_offset;
        return d;
      },
      nb::arg("tmet"), nb::arg("password") = "");

  // Round-trip the universal header (parse -> serialize) and return the 1024
  // re-serialized bytes; the P1 test checks they equal the original, which
  // validates the serialize-side field offsets ahead of the write phase.
  m.def("roundtrip_universal_header", [](nb::bytes file_bytes) {
    auto uh = mef3io::fmt::UniversalHeader::parse(as_span(file_bytes));
    std::vector<mef3io::ui1> out(mef3io::fmt::UNIVERSAL_HEADER_BYTES);
    uh.serialize(out);
    return to_bytes(out);
  });

  // --- Session (P2 low-level reads) ---
  nb::class_<mef3io::Session>(m, "Session")
      .def(nb::init<const std::string&, std::string>(), nb::arg("path"), nb::arg("password") = "")
      .def_prop_ro("channels", &mef3io::Session::channels)
      .def("channel_info",
           [](mef3io::Session& s, const std::string& name) {
             const auto& ci = s.channel_info(name);
             nb::dict d;
             d["name"] = ci.name;
             d["sampling_frequency"] = ci.sampling_frequency;
             d["units_conversion_factor"] = ci.units_conversion_factor;
             d["units_description"] = ci.units_description;
             d["start_time"] = ci.start_time;
             d["end_time"] = ci.end_time;
             d["number_of_samples"] = ci.number_of_samples;
             d["recording_time_offset"] = ci.recording_time_offset;
             d["n_segments"] = ci.n_segments;
             return d;
           })
      .def(
          "read_runs",
          [](mef3io::Session& s, const std::string& channel, nb::object t0, nb::object t1) {
            std::optional<mef3io::si8> a, b;
            if (!t0.is_none()) a = nb::cast<mef3io::si8>(t0);
            if (!t1.is_none()) b = nb::cast<mef3io::si8>(t1);
            auto runs = s.read_runs(channel, a, b);
            nb::list out;
            for (auto& r : runs) {
              nb::dict d;
              d["start_uutc"] = r.start_uutc;
              d["start_sample"] = r.start_sample;
              d["samples"] = vec_to_numpy(std::move(r.samples));
              out.append(d);
            }
            return out;
          },
          nb::arg("channel"), nb::arg("t0") = nb::none(), nb::arg("t1") = nb::none());
}
