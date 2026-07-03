# mef3io — Design & Implementation Plan

**Status:** agreed design, 2026-07-02
**Supersedes:** `requirements/requirements.md` (pure-Python plan, deleted)

## 1. Goal

A single C++ core implementing MEF 3.0 read **and** write, wrapped thinly for
Python (now) and MATLAB (later), with the high-level semantics of today's
`mef_tools` (`MefReader`/`MefWriter`) living **in the C++ layer** so every
language binding behaves identically. A pure-Python backend with the same API
ships in the package as fallback, benchmark reference, and test oracle.

Non-goals: MEF video files (`.vidd/.vmet/.vidx`) are dropped from the library
entirely — never used in practice; could be reconsidered in the future if
worthwhile. The only footprint in the code: session traversal silently ignores
`.vidd` directories (with a debug-level note), and video structs/APIs from
meflib/pymef are simply not mirrored. Also out of scope (v1): lossy RED
**encoding** (decode is supported), performance parity guarantees against
original meflib (we expect to beat it on open time; decode should be
comparable).

## 2. Architecture

```
┌─ python: mef3io pkg (nanobind) ─┐  ┌─ MATLAB toolbox (MEX, later) ─┐  ┌─ viewer (later)
│  numpy in/out, GIL released     │  │                               │  │
└──────────────┬──────────────────┘  └──────────────┬────────────────┘  │
               │                 stable C ABI shim (later, for MATLAB)  │
┌──────────────┴─────────────────────────────────────┴──────────────────┴───┐
│  HIGH-LEVEL C++ API — mef3io::Reader / mef3io::Writer                     │
│  float64 + NaN-gap semantics, ufact scaling, precision inference,         │
│  int32+ufact primitive write path, append logic, annotations, cache       │
├────────────────────────────────────────────────────────────────────────────┤
│  CORE C++ (format codec, no policy)                                       │
│  fmt structs + CRC · AES + password scheme · RED codec ·                  │
│  mmap IO + dir traversal · Session/Channel/Segment · records ·            │
│  RAII, exceptions, zero globals, thread pool                              │
└────────────────────────────────────────────────────────────────────────────┘
```

Key decisions (agreed):

1. High-level ("smart") semantics live in C++, wrappers are thin (<~500 lines).
2. On-disk format stays byte-identical to meflib output. Code is written from
   the spec (field tables), **not** ported from meflib. meflib/pymef,
   `mef3_dump`, and `mef_tools/reimplementation.py` serve as three independent
   oracles.
3. Dropped from meflib: global state, exit-on-error, `FILT_*` filters, `e_*`
   allocator wrappers, lossy RED encode, video.
4. Added: thread safety (immutable-after-open readers), context-managed
   resources, exception-based errors, mmap'd binary-searchable indices,
   lazy metadata, metadata cache, internal parallelism.

## 3. Repo layout (monorepo, this repository)

```
mef_tools/                        (repo root — name unchanged for now)
├── core/                         C++17 library "mef3io_core"
│   ├── include/mef3io/           public headers
│   ├── src/
│   ├── third_party/              tiny-AES-c (vendored, public domain)
│   └── tests/                    Catch2 unit tests
├── bindings/python/              nanobind extension "_mef3io"
├── python/mef3io/                Python package
│   ├── __init__.py               Reader / Writer (C++ backend)
│   ├── pure/                     pure-Python backend (same API)
│   │                             (from reimplementation.py + mef3_dump decode)
│   ├── compat.py                 drop-in MefReader/MefWriter (mef_tools.io API)
│   └── cache.py                  cache location/policy helpers
├── mef_tools/                    legacy package — unchanged, used as oracle
├── tests/                        cross-implementation compatibility matrix
├── benchmarks/                   C++ vs pure vs legacy pymef
└── reference_files/              meflib, pymef, mef3_dump (read-only oracles)
```

## 4. C++ core design

### 4.1 Modules (namespaces)

| Namespace | Contents |
|---|---|
| `mef3io::fmt` | POD-ish structs with exact-layout (de)serialization: `UniversalHeader` (1024 B), `MetadataSection1` (1536 B), `TimeSeriesMetadataSection2` (10752 B), `MetadataSection3` (3072 B), `TimeSeriesIndex` (56 B), `RedBlockHeader` (304 B), record header/index + all record types from `mefrec.h` (Note, EDFA, Seiz+SeizCh, SyLg, LNTP, CSti, ESti, Curs, Epoc) |
| `mef3io::crc` | CRC-32 Koopman (table-driven), header/body CRC helpers |
| `mef3io::crypto` | AES-128-ECB (vendored tiny-AES-c, validated against NIST vectors and `cryptography` in tests), terminal-byte password extraction, L1/L2 validation-field scheme, key derivation |
| `mef3io::red` | RED decode (range decoder + diff reconstruction + unscale/retrend, incl. lossy-written blocks) and lossless RED encode (diff + range coder, keysamples, per-block stats) |
| `mef3io::io` | mmap file abstraction (POSIX/Win32), `.mefd/.timd/.segd` discovery, path/name rules |
| `mef3io::(Session,Channel,Segment)` | lazy object tree over the directory structure |
| top level | `Reader`, `Writer`, `Cache`, `ThreadPool`, error hierarchy |

### 4.2 Serialization approach

No `reinterpret_cast` of packed structs (alignment/UB trap that meflib dances
around); each struct has explicit `parse(span<const byte>)` /
`serialize(span<byte>)` against a field table with static offsets — the same
tables already validated in `reimplementation.py::FIELD_DEFINITIONS` and the
deleted requirements doc. `static_assert` on all offsets/sizes.

### 4.3 Error handling

Exception hierarchy: `MefError` ← `{FormatError, CrcError, PasswordError,
IoError, WriteConflictError}`. No error-code returns in the public API; the C
ABI shim (later) converts to codes. Bindings map to Python exceptions.

### 4.4 Reading — designed around partial access

- `Reader::open()` reads only: directory tree + the `.tmet` files needed for
  channel list, fs, ufact, start/end, nsamp (last-segment shortcut where
  possible). No `.tidx` is touched at open.
- `.tidx` files are **mmap'd, never materialized**: entries are fixed 56 B and
  time/sample ordered → binary search directly on raw bytes for
  `[t0, t1]` / `[s0, s1]` block ranges. O(log n) seek, zero parse cost.
- `read_raw(channel, t0, t1)` → preallocated int32 buffer sized
  `round((t1-t0)*fs/1e6)`; blocks decode in parallel into disjoint slices;
  gap samples flagged (output carries a validity mask + ufact + actual start).
- `read(channel, t0, t1)` → float64 = int32 · ufact, gaps = NaN.
- `toc(channel)` → block-level table (start_time, start_sample, n_samples,
  offset) for viewers/dataloaders.
- Discontinuity gap length rounds to nearest sample (sub-sample gaps
  tolerated; never accumulate rounded periods — always
  `t = start_uutc + round(n * 1e6 / fs)` with fs as double).
- `recording_time_offset`: apply per spec (stored = actual − offset). The
  "corrupted" convention observed in the wild (stored = offset − actual,
  handled heuristically in mef3_dump) is behind an opt-in leniency flag, off
  by default, warning when triggered.

### 4.5 Writing

- Primitive path: `write(channel, span<int32>, ufact, start_uutc, fs)` —
  amplifier counts + V/bit conversion factor stored as
  `units_conversion_factor`. No transformation of samples.
- Convenience path: `write(channel, span<double>, start_uutc, fs, precision?)`
  — quantizes to int32 with `10^precision` (inferred if absent, same
  algorithm as mef_tools incl. int32 dynamic-range guard).
- **NaN policy** (float path; NaN = discontinuity, blocks are tiled within the
  segment — NaNs never create new `.segd` segments, matching current behavior):
  - Default (new API): **strict split** — every NaN run becomes a true on-disk
    gap (discontinuous blocks, nothing stored for the gap). No sentinels, no
    compression penalty.
  - `max_nans_allowed=<n>` opt-in: NaN runs shorter than n are embedded as the
    `RED_NAN` sentinel (`INT32_MIN`, reads back as NaN) to reduce block count.
    Today's mef_tools does this implicitly (default `'fs'` = 1 s) via the
    NaN→int32 cast coincidentally hitting `RED_NAN`; here it is explicit.
    The compat shim keeps the legacy `'fs'` default.
  - **All-NaN input: no-op on disk, but explicit** — every write returns a
    summary (samples_written, blocks, gaps_skipped) and warns when
    samples_written == 0 (today this is silent).
  - int32 primitive path has no NaN: gaps are structural (separate `write`
    calls, each an implicit discontinuity, or an optional validity mask).
    `INT32_MIN` in int32 input is rejected by default (collides with
    `RED_NAN`); opt-in flag to treat it as NaN sentinel.
  - Read side: `read()` (float64) → NaN for both true gaps and stored
    `RED_NAN`; `read_raw()` (int32) → validity mask distinguishes
    gap / sentinel / data.
- Segment control: `new_segment` flag; append goes to last segment with
  end-time/fs/ufact consistency checks (same guards as mef_tools).
- Records: write all supported types at session or channel level; merge with
  existing records on append (as mef_tools does).
- Encryption on write: none / L1 / L2, including section encryption flags,
  validation fields, and encrypted record bodies.
- Float fs fully supported (sf8 end-to-end); block length heuristic from fs
  kept but overridable (`mef_block_len`).
- Any write invalidates caches for the session (see §6).

### 4.6 Threading

- Internal `ThreadPool`, size set at `open()` (`n_threads`, default `auto` =
  hardware concurrency), per-call override on read/write calls.
- Parallel units: (1) RED block decode/encode — independent blocks, disjoint
  output slices ⇒ deterministic, race-free; (2) per-channel/per-segment file
  IO; (3) metadata open (parallel stat+read of `.tmet`s).
- Reader is immutable after open ⇒ safe concurrent calls from user threads.
  Python bindings release the GIL for all C++ work.
- Writer is single-writer per session (documented; guarded by a lock file or
  advisory check — TBD in implementation), but **internally parallel**:
  block boundaries are computed up front (from `mef_block_len` and the NaN/
  discontinuity split), then blocks are RED-encoded + encrypted + CRC'd by the
  pool in parallel, and a single sequencer thread appends the finished blocks
  to `.tdat` and emits `.tidx` entries **in order**. Output is byte-identical
  regardless of `n_threads`. A bounded queue caps memory so writing a long
  signal never holds the whole encoded stream in RAM.

## 5. Python package

```python
import mef3io

with mef3io.Reader("/data/session.mefd", password="...", n_threads=8) as r:
    r.channels                       # list[str]
    r.info("ch1")                    # dict: fs, ufact, start, end, nsamp, units...
    x  = r.read("ch1", t0, t1)       # float64, NaN gaps
    xi = r.read_raw("ch1", t0, t1)   # int32 + mask + ufact
    r.toc("ch1")                     # block table (numpy structured / DataFrame)
    r.records()                      # annotations

with mef3io.Writer("/data/session.mefd", password1=..., password2=...) as w:
    w.write("ch1", counts_int32, ufact=2.5e-7, start=t0, fs=1024.5)
    w.write("ch2", volts_float64, start=t0, fs=256.0, precision=3)
    w.write_records(df)
```

- `mef3io.pure` — same `Reader`/`Writer` API, pure Python+numpy(+numba
  optional). Backend selectable: `mef3io.Reader(..., backend="pure")`.
  v1: pure read path complete (exists already across reimplementation.py +
  mef3_dump); pure write path is a stretch goal after C++ write lands.
- `mef3io.compat` — `MefReader`/`MefWriter` matching `mef_tools.io` signatures,
  defaults, and quirks (e.g. `get_data` list/str return-shape asymmetry,
  `max_nans_written='fs'` default) so it's a drop-in import change; the legacy
  `mef_tools` package itself stays untouched in the repo as oracle.

## 6. Metadata cache ("warm start")

Purpose: collapse the many-small-file cost of session open (mainly on network
storage; lazy open + mmap indices already fix the pathological local case).

- **Modes:**
  - `cache="auto"` (default): per-user OS cache dir
    (`platformdirs`-style: `~/Library/Caches/mef3io`, `$XDG_CACHE_HOME`,
    `%LOCALAPPDATA%`), entry keyed by hash of absolute session path. Works
    with read-only sessions.
  - `cache=<path>` / explicit persistent: user-requested dump file (e.g. next
    to the `.mefd`). **Never discovered or used unless explicitly passed** —
    a foreign/stale cache file inside a session dir cannot surprise a
    default-configured reader.
  - `cache=None`: off.
- **Contents:** format version, directory tree, per-file (relpath, size,
  mtime) fingerprints, and **raw bytes of all `.tmet` files with encrypted
  sections still encrypted** (decryption happens at load with the user's
  password — cache never weakens the password scheme). Optional per-channel
  block-count summaries. No `.tidx` contents (mmap makes that unnecessary).
- **Correctness:** cache is purely an accelerator. On open, real files are
  stat'd; any size/mtime/tree mismatch ⇒ affected entries ignored and
  refreshed. A wrong cache can cost time, never correctness.
- **Write interaction:** any `Writer` operation on a session **removes** the
  auto-cache entry and any known persistent cache for it (removal, not
  in-place update — updating duplicates reader logic and risks silent
  divergence). Removal is best-effort cleanup; stat validation remains the
  guarantee for caches the writer couldn't see or delete.

## 7. Build & distribution

- C++17, CMake ≥ 3.26. Dependencies: none beyond vendored tiny-AES-c and the
  test framework (Catch2, fetched for tests only).
- Python: nanobind + scikit-build-core; `cibuildwheel` wheels for
  manylinux (x86_64/aarch64), macOS (arm64/x86_64), Windows (x86_64),
  CPython 3.10+.
- `mef3io` installs with the compiled backend; if the extension is missing
  (exotic platform), package still imports with `backend="pure"`.
- MATLAB (later): flat `extern "C"` ABI shim over the high-level API + MEX
  wrappers; packaged toolbox. Deferred by agreement.

## 8. Testing strategy

1. **Struct layout goldens:** byte-level fixtures generated once via legacy
   pymef/mef_tools; `static_assert` + parse/serialize round-trip per struct.
2. **The ultimate gate — legacy cross-compatibility matrix (CI):**
   - legacy `mef_tools` writes → `mef3io` reads (values, times, gaps equal)
   - `mef3io` writes → legacy `mef_tools`/pymef reads
   - crossed over: encryption {none, L1, L2} × input {float64+precision,
     int32+ufact} × NaN/discontinuity patterns × {1, n} segments ×
     fs {integer, fractional} × records {none, mixed types}.
   Legacy stack runs in a pinned py3.10 CI env (pymef wheel availability).
3. **Backend equivalence:** pure vs C++ backend bit-identical outputs on the
   full matrix.
4. **Codec robustness:** RED encode→decode property tests (random signals,
   extremes, constant, saturating int32), fuzzed truncated/corrupted blocks
   must raise `MefError`, never crash; CRC tampering detection.
5. **Crypto vectors:** AES-128 NIST vectors; password scheme fixtures
   generated by meflib.
6. **Concurrency:** TSAN job; deterministic-output test across n_threads ∈
   {1, 2, max}; parallel-readers stress test.
7. **Benchmarks** (`benchmarks/`): open time (cold/warm/cached), bulk read,
   random-window read (DL access pattern), write throughput — mef3io-C++ vs
   mef3io-pure vs legacy pymef.

## 9. Phases

| Phase | Deliverable | Gate |
|---|---|---|
| P0 | Scaffolding: CMake, nanobind hello-world wheel, CI skeleton, golden-file generation script (uses legacy mef_tools) | wheel builds on 3 OSes |
| P1 | `fmt` structs + CRC + password/AES (read side) | parses all golden `.tmet/.tidx` byte-identically to oracles |
| P2 | RED decode, mmap IO, lazy Session tree, index binary search | reads golden sessions == pymef output exactly |
| P3 | High-level `Reader` (uutc reads, NaN gaps, scaling, toc) + records read | compat matrix read-direction green |
| P4 | RED encode + low-level write path (segments, append, indices, CRCs, encryption write, records write) | legacy pymef reads mef3io-written sessions |
| P5 | High-level `Writer` semantics (precision inference, int32+ufact path, NaN splitting, guards) | full compat matrix green |
| P6 | Threading + metadata cache | TSAN clean; benchmark targets met |
| P7 | Python package polish: `compat` shim, `pure` backend integrated, wheels via cibuildwheel | existing mef_tools test suite passes against `mef3io.compat` |
| P8 | Benchmarks, docs, examples | — |
| P9+ | MATLAB C ABI + MEX toolbox; pure write path; viewer TOC API hardening | — |

## 10. Open items / risks

- `recording_time_offset` corrupted-convention heuristic: opt-in flag (§4.4);
  confirm against real affected datasets before P3 closes.
- Exotic record types (LNTP, CSti, ESti): implemented from `mefrec.h` layouts,
  round-trip-tested only; Note/EDFA/Seiz/SyLg get full oracle coverage.
- Writer concurrent-access guard (lock file vs advisory): decide in P4.
- Legacy pymef in CI depends on installability in a pinned env; fallback is
  pre-generated golden sessions committed as fixtures.
- pandas is a dependency only of the compat shim/records convenience, not the
  core package (numpy-only core).
