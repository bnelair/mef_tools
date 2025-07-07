[![Build Status](https://github.com/mselair/mef_tools/actions/workflows/test_publish.yml/badge.svg)](https://pypi.org/project/mef-tools/)
[![Documentation Status](https://readthedocs.org/projects/mef-tools/badge/?version=latest)](https://mef-tools.readthedocs.io/en/latest/?badge=latest)
[![Python Versions](https://img.shields.io/pypi/pyversions/Django)](https://pypi.org/project/mef-tools/)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey)](https://pypi.org/project/mef-tools/)

# MEF_Tools

This package provides tools for easier [Multiscale Electrophysiology Format (MEF)](https://doi.org/10.1016%2Fj.jneumeth.2009.03.022) data saving and reading. See the example below and [documentation](https://mef-tools.readthedocs.io/en/latest/?badge=latest).

## Multiscale Electrophysiology Format (MEF)

[Multiscale Electrophysiology Format (MEF)](https://doi.org/10.1016%2Fj.jneumeth.2009.03.022) is a specialized file format designed for storing electrophysiological data. This format is capable of storing multiple channels of data in a single file, with each channel storing a time series of data points.

MEF is particularly useful for handling large volumes of electrophysiological data, as it employs a variety of techniques such as lossless and lossy compression, data encryption and data de-identification to make the storage and transmission of such data more efficient and secure.

Python's pymef library provides a set of tools for working with MEF files, including reading from and writing to these files. Below are examples demonstrating the use of these tools.

## Dependencies
- [meflib](https://github.com/msel-source/meflib) - binaries are included in the pymef package
- [pymef](https://github.com/msel-source/pymef)
- [numpy](https://numpy.org/)
- [pandas](https://pandas.pydata.org/)

## Installation

See installation instructions [INSTALL.md](INSTALL.md).

## License

This software is licensed under the Apache-2.0 License. See [LICENSE](https://github.com/xmival00/MEF_Tools/blob/master/LICENSE) file in the root directory of this project.

## Reference

* Brinkmann BH, Bower MR, Stengel KA, Worrell GA, Stead M. Large-scale electrophysiology: acquisition, compression, encryption, and storage of big data. J Neurosci Methods. 2009;180(1):185‐192. doi:10.1016/j.jneumeth.2009.03.022

## Examples

First, we need to import the necessary libraries:

```python
import os
import time
import numpy as np
import pandas as pd
from mef_tools.io import MefWriter, MefReader, create_pink_noise
```

Next, we define the path to our MEF file, and the amount of data (in seconds) we want to write:

```python
session_name = 'session'
session_path = os.getcwd() + f'/{session_name}.mefd'
mef_session_path = session_path
secs_to_write = 30
```

We also need to specify the start and end times of our data in uUTC time. uUTC time is the number of microseconds since January 1, 1970, 00:00:00 UTC. We can use the [time](https://docs.python.org/3/library/time.html) library to convert between UTC time and other time formats. In this example, we will use the current time as the start time, and the start time plus the number of seconds we want to write as the end time:

```python
start_time = int(time.time() * 1e6)
end_time = int(start_time + 1e6*secs_to_write)
```

With our file path and timing details set, we can now create our MEFWriter instance:

```python
pass1 = 'pass1' # password needed for writing to file
pass2 = 'pass2' # password needed for every read/write operation
Wrt = MefWriter(session_path, overwrite=True, password1=pass1, password2=pass2)
Wrt.max_nans_written = 0
Wrt.data_units = 'mV'
```

We then create some test data to write to our file:

```python
fs = 500
low_b = -10
up_b = 10
data_to_write = create_pink_noise(fs, secs_to_write, low_b, up_b)
```

This data is written to a channel in our MEF file:

```python
channel = 'channel_1'
precision = 3
Wrt.write_data(data_to_write, channel, start_time, fs, precision=precision)
```

## Appending Data to an Existing MEF File

To append data to an existing MEF file, we first need to create a new writer:

```python
secs_to_append = 5
discont_length = 3
append_time = end_time + int(discont_length*1e6)
append_end = append_time + 1e6*secs_to_append
data = create_pink_noise(fs, secs_to_append, low_b, up_b)
Wrt2 = MefWriter(session_path, overwrite=False, password1=pass1, password2=pass2)
Wrt2.write_data(data, channel, append_time, fs)
```

## Creating a New Segment in the MEF File

To create a new segment, we simply need to change the new_segment flag to True:

```python
secs_to_write_seg2 = 10
gap_time = 3.36*1e6
newseg_time = append_end + int(gap_time)
newseg_end = newseg_time + 1e6*secs_to_write_seg2
data = create_pink_noise(fs, secs_to_write_seg2, low_b, up_b)
data[30:540] = np.nan
data[660:780] = np.nan
Writer2.write_data(data, channel, newseg_time, fs, new_segment=True)
```

We can also write data to a new channel with inferred precision:

```python
channel = 'channel_2'
Wrt2.write_data(data, channel, newseg_time, fs, new_segment=True)
```

## Writing Annotations to the MEF File

Annotations can also be added to the MEF file at both the session and channel levels. Here's an example of how to do this:

```python
start_time = start_time
end_time = start_time + 1e6 * 300
offset = start_time - 1e6
starts = np.arange(start_time, end_time, 2e6)
text = ['test'] * len(starts)
types = ['Note'] * len(starts)
note_annotations = pd.DataFrame(data={'time': starts, 'text': text, 'type': types})
Wrt2.write_annotations(note_annotations)

starts = np.arange(start_time, end_time, 1e5)
text = ['test'] * len(starts)
types = ['EDFA'] * len(starts)
duration = [10025462] * len(starts)
note_annotations = pd.DataFrame(data={'time': starts, 'text': text, 'type': types, 'duration':duration})
Wrt2.write_annotations(note_annotations, channel=channel )
```

## Reading from an MEF File

In this example, we create a MefReader instance, print out the properties of the MEF file, and then read the first 10 seconds of data from each channel. The data from each channel is appended to a list.

```python
Reader = MefReader(session_path, password2=pass2)
signals = []

properties = Reader.properties
print(properties)

for channel in Reader.channels:
    start_time = Reader.get_property('start_time', channel)
    end_time = Reader.get_property('end_time', channel)
    x = Reader.get_data(channel, start_time, start_time+10*1e6)
    signals.append(x)
```
