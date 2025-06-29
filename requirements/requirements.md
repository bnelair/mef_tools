# Project Requirements - MEF 3.0 Python Library Refactor
## 1. High-Level Goals
The primary goal of this project is to re-implement the existing MEF 3.0 libraries (meflib, pymef, and mef_tools) in a more modern, high-level, maintainable and user-friendly Python library. The new library must correctly read and write files compliant with the MEF 3.0 specification, ensuring interoperability with the existing ecosystem. The project will prioritize safety, stability, and ease of use over the brittle performance optimizations of the original C library.

The key objectives are:

Improve Maintainability: Create a clean, well-documented, and modular codebase that is easy for future developers to understand and extend.

Enhance Robustness and Safety: Eliminate sources of undefined behavior, memory leaks, and platform-dependent failures present in the original implementation.

Provide a Modern API: Offer a high-level, object-oriented Python API that is intuitive, hard to use incorrectly, and handles resources automatically (RAII).

Enable High-Quality Wrappers: The Python API must be designed to include user-friendly tools similar to the existing MefReader/MefWriter classes.

Ensure Thread Safety: The library must be fully thread-safe to allow for concurrent reading and processing of MEF data.

## 2. General Architectural Requirements

GA-1 - The library shall be written in Python 3.10 or newer. 

GA-2 - The library shall have no global mutable state. All state (e.g., configuration, file handles, cached data) must be encapsulated within library-defined objects. 

GA-3 - The library will depend on a minimal, well-defined set of third-party libraries, primarily NumPy for numerical operations and cryptography for cryptographic operations. 

GA-4 - All file resources must be managed automatically. The library's file-handling classes shall implement the context manager protocol (i.e., support the with statement) to ensure files are properly closed. 

GA-5 - The library's public API shall be organized into a distinct package structure (e.g., pymef.io, pymef.crypto) to prevent name collisions and promote modularity.

GA-6 - The library and its dependencies must be installable via pip from a standard pyproject.toml configuration. Dependencies must not be vendored (copied directly) into the source tree. 

GA-7 - The library shall be designed for testability, with a clear separation of concerns (e.g., I/O, parsing, cryptography) to facilitate isolated unit testing using the pytest framework. 

GA-8 - The library's internal modules shall be designed with clear boundaries to allow performance-critical components (e.g., decompression, cryptography) to be optionally replaced by C++ extension modules in the future without altering the public Python API.

## 3. Core Library API Design Principles

| Requirement ID | Description                                                                                                                                                                                                                     |
|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| API-1          | The library's primary public interface shall be exposed through two main classes: MefReader for reading MEF data and MefWriter for writing MEF data.                                                                            |
| API-2          | The public methods, properties, and parameter names of the MefReader and MefWriter classes shall maintain backward compatibility with the corresponding classes in the mef_tools.io module.                                     |
| API-3          | The library shall abstract away the low-level details of the MEF format (e.g., file handles, byte parsing, block indexing). User interaction should be based on high-level concepts like channels, timestamps, and data arrays. |
| API-4          | Both MefReader and MefWriter shall function as context managers, allowing for their use in a with statement to ensure automatic and deterministic resource cleanup.                                                             |


## 4. MEF 3.0 Format Specification

This section codifies the low-level binary layout of the MEF 3.0 file format. The library must read and write data according to these specifications to ensure compatibility. All multi-byte numerical values are stored in  little-endian byte order.

### 4.1. Data Hierarchy & Naming

- Session (.mefd)
  - The top-level directory for a recording session. Contains one or more channel directories. 


- Channel (.timd)
  - A directory representing a single time series data stream. Contains one or more segment directories. 

- Segment (.segd)
  - A directory representing a continuous time-chunk of a channel's data. Segment directories are named with the channel name, a hyphen, and a sequential 6-digit number (e.g., Chan_01-000000.segd). 

### 4.2. File Types & Naming

File names are derived from the name of their containing segment directory. 

- Time Series Metadata (.tmet)
  - Contains technical and subject-specific metadata for a segment. 

- Time Series Data (.tdat) 
  - Contains the actual time series data, stored in compressed RED blocks. 

- Time Series Indices (.tidx)
  - Contains an index for each RED block in the 
  - .tdat file for fast seeking. 

### 4.3. Data Types
The specification defines the following primitive data types.

| MEF Type | C typedef         | Python struct Format | Description                                           |
|----------|-------------------|----------------------|-------------------------------------------------------|
| si1      | char              | <b                   | 1-byte signed integer                                 |
| ui1      | unsigned char     | <B                   | 1-byte unsigned integer                               |
| si4      | int               | <i                   | 4-byte signed integer                                 |
| ui4      | unsigned int      | <I                   | 4-byte unsigned integer                               |
| sf4      | float             | <f                   | 4-byte single-precision float                         |
| si8      | long int          | <q                   | 8-byte signed integer                                 |
| ui8      | long unsigned int | <Q                   | 8-byte unsigned integer                               |
| sf8      | double            | <d                   | 8-byte double-precision float                         |
| utf8[n]  | char[n]           | Ns                   | UTF-8 encoded, null-terminated string of max length n |
| ascii[n] | char[n]           | Ns                   | ASCII encoded, null-terminated string of max length n |

### 4.4. Universal Header Specification

- Size: 1024 bytes.
- Presence: Every .tmet, .tidx, and .tdat file begins with this header.
- Encryption: The universal header is never encrypted. 


| Field                | Offset (bytes) | Size (bytes) | Data Type | Description                                                                           |
|----------------------|----------------|--------------|-----------|---------------------------------------------------------------------------------------|
| Header CRC           | 0              | 4            | ui4       |                                                                                       |
| Body CRC             | 4              | 4            | ui4       |                                                                                       |
| File Type String     | 8              | 5            | ascii[4]  |                                                                                       |
| MEF Version Major    | 13             | 1            | ui1       |                                                                                       |
| MEF Version Minor    | 14             | 1            | ui1       |                                                                                       |
| Byte Order Code      | 15             | 1            | ui1       |                                                                                       |
| Start Time           | 16             | 8            | si8       |                                                                                       |
| End Time             | 24             | 8            | si8       |                                                                                       |
| Number of Entries    | 32             | 8            | si8       |                                                                                       |
| Maximum Entry Size   | 40             | 8            | si8       |                                                                                       |
| Segment Number       | 48             | 4            | si4       |                                                                                       |
| Channel Name         | 52             | 256          | utf8[63]  |                                                                                       |
| Session Name         | 308            | 256          | utf8[63]  |                                                                                       |
| Anonymized Name      | 564            | 256          | utf8[63]  |                                                                                       |
| Level UUID           | 820            | 16           | ui1[16]   | 16 random bytes shared by all files in the same level.                                |
| File UUID            | 836            | 16           | ui1[16]   | 16 random bytes unique to this specific file.                                         |
| Provenance UUID      | 852            | 16           | ui1[16]   | File UUID of the originating file. Identical to File UUID if this is the source.      |
| Lvl 1 Pwd Validation | 868            | 16           | ui1[16]   | First 16 bytes of the SHA-256 hash of the Level 1 password.                           |
| Lvl 2 Pwd Validation | 884            | 16           | ui1[16]   | XOR of the L1 password and the first 16 bytes of the SHA-256 hash of the L2 password. |
| Protected Region     | 900            | 60           | -         | Reserved for future use; filled with zeros.                                           |
| Discretionary Region | 960            | 64           | -         | Reserved for end-user use; filled with zeros if unused.                               |


## 5. Functional Requirements

### 5.1. MefReader Class

The MefReader class provides a read-only interface to an existing MEF 3.0 session.

Here is the table format for the provided information:

| Req. ID | Method/Property                   | Parameters                                     | Return Value           | Description                                                                                                                                                                                                                                                                                                                                                                           |
|---------|-----------------------------------|------------------------------------------------|------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| FR-R-1  | `__init__`                        | `session_path: str, password: str = None`      | `MefReader`            | The constructor shall open the MEF session at the given path. It must validate the password if the session is encrypted. It shall pre-load basic channel information.                                                                                                                                                                                                                 |
| FR-R-2  | `@property channels`              | `-`                                            | `list[str]`            | Shall return a sorted list of all time series channel names in the session.                                                                                                                                                                                                                                                                                                           |
| FR-R-3  | `get_channel_info`                | `channel: str = None`                          | `dict` or `list[dict]` | Shall return a dictionary of metadata properties for the specified channel. If no channel is provided, it returns a list of dictionaries for all channels.                                                                                                                                                                                                                            |
| FR-R-4  | `get_data`                        | `channels: list/str, t_start: int, t_end: int` | `np.ndarray`           | Shall read time series data for the given channel(s) between `t_start` and `t_end` (in µUTC). The method must return a NumPy array of `float64` where the raw integer data has been multiplied by the channel's `units_conversion_factor`.                                                                                                                                            |
| FR-R-5  | `get_raw_data`                    | `channels: list/str, t_start: int, t_end: int` | `np.ndarray`           | Shall read time series data as above, but must return a NumPy array of the raw `int32` values without applying the conversion factor.                                                                                                                                                                                                                                                 |
| FR-R-6  | `get_annotations`                 | `channel: str = None`                          | `list[dict]`           | Shall read all records from the specified level (session or channel) and return them as a list of dictionaries.                                                                                                                                                                                                                                                                       |
| FR-R-7  | Sub-Sample Discontinuity Handling | `-`                                            | `-`                    | When reading data that spans a discontinuity, the reader must correctly calculate the number of samples corresponding to the time gap. If the time gap is not an integer multiple of the sampling period, the library should handle this gracefully (e.g., by rounding to the nearest sample) to ensure the output array has the correct number of `NaN` values representing the gap. |


### 5.1. MefWriter Class

The MefWriter class provides an interface for creating or appending to a MEF 3.0 session.

| Req. ID | Method/Property                   | Parameters                                                                                   | Return Value | Description                                                                                                                                                                                                                                                                                                                          |
|---------|-----------------------------------|----------------------------------------------------------------------------------------------|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| FR-W-1  | `__init__`                        | `session_path: str, overwrite: bool = False, password_1: str = None, password_2: str = None` | `MefWriter`  | The constructor shall prepare a MEF session for writing. If `overwrite` is `True`, it must delete any existing session at the path. If `False`, it will prepare for appending to an existing session.                                                                                                                                |
| FR-W-2  | `write_data`                      | See below                                                                                    | `-`          | The core writing method. It must support multiple calling signatures to handle different data input types as specified in FR-W-4 and FR-W-7.                                                                                                                                                                                         |
| FR-W-3  | `write_annotations`               | `annotations: pd.DataFrame, channel: str = None`                                             | `-`          | Shall write records to the specified level. It must accept a pandas DataFrame as input and handle the conversion to the MEF record format internally.                                                                                                                                                                                |
| FR-W-4  | Floating-Point Data Input         | `data: np.ndarray (float), precision: int = None, ...`                                       | `-`          | The `write_data` method must accept a floating-point NumPy array. If `precision` is `None`, it must automatically infer an optimal `units_conversion_factor`. If `precision` is an integer, it must be used to calculate the factor (e.g., `10**-precision`).                                                                        |
| FR-W-5  | NaN Discontinuity Handling        | `-`                                                                                          | `-`          | The `write_data` method must treat any `np.nan` value in the input data array as a discontinuity. The contiguous non-NaN portions of the array shall be written as separate, discontinuous data blocks in the `.tdat` file. The `max_nans_written` property shall not be implemented.                                                |
| FR-W-6  | New Segment Creation              | `new_segment: bool = False`                                                                  | `-`          | The `write_data` method must support a `new_segment` parameter. If `True`, a new segment directory shall be created for the new data. If `False`, the data shall be appended to the latest existing segment for that channel.                                                                                                        |
| FR-W-7  | Integer Data Input                | `data: np.ndarray (int32), scaling_factor: float, ...`                                       | `-`          | The `write_data` method must support an alternative calling signature to accept a NumPy array of type `int32` and a corresponding floating-point `scaling_factor`. This data will be written directly without further conversion, and the provided `scaling_factor` will be stored in the metadata as the `units_conversion_factor`. |
| FR-W-8  | Sub-Sample Discontinuity Handling | `-`                                                                                          | `-`          | When appending data that creates a discontinuity, the writer must correctly calculate the `start_time` of the new block based on the provided timestamp. It must not assume the time gap since the previous block is an integer multiple of the sampling period.                                                                     |

## 6. Non-Functional Requirements

This section defines the quality attributes and constraints of the library.


| Req. ID | Category           | Description                                                                                                                                                                                                                                                                                                                      |
|---------|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| NFR-1   | Performance        | The library shall be implemented to be as efficient as is reasonable in pure Python. There is no strict quantitative performance target relative to the original C implementation. Implementation should favor vectorized NumPy operations over Python loops for data manipulation where possible.                               |
| NFR-2   | Portability        | As a pure Python library with cross-platform dependencies (numpy, cryptography), the library must be platform-independent and run on Windows, macOS, and major Linux distributions.                                                                                                                                              |
| NFR-3   | Concurrency Design | The initial implementation is only required to support single-threaded read/write operations. However, the architectural design (object-oriented, no global state) must be compatible with future extensions for multi-processing or multi-threading to allow for parallel operations (e.g., reading multiple channels at once). |
| NFR-4   | Error Handling     | The library must use standard Python exception handling (try...except). Errors (e.g., file not found, invalid password, corrupted data) shall raise specific and informative exceptions (e.g., FileNotFoundError, ValueError, a custom MefCRCError).                                                                             |
| NFR-5   | API Safety         | The API should be designed to prevent common errors. For example, file handles must be managed internally and not exposed to the user. Methods should validate critical inputs (e.g., ensuring timestamps are in the correct order).                                                                                             |



## 7. Out of Scope

The following features and functionalities are explicitly out of scope for the initial version of this library:

MEF Video Format: The library will not support reading or writing MEF video data (.vidd, .vmet, .vidx files). The focus is exclusively on time series data.

Extensible User-Defined Records: The library will support reading and writing the specific, known record types from the mef_tools package (Note, Seizure, etc.). A generic framework for users to define and register their own custom record types (the functionality provided by mefrec.c) is not required.

C++ Backend: The initial deliverable is a pure-Python library. A C++ backend for performance optimization is a potential future enhancement, not a requirement for this project.

Performance Parity with C: Achieving the same performance as the original C meflib is not a goal. The primary goals are maintainability, safety, and usability in Python.

