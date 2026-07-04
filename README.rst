.. image:: https://github.com/mselair/mef_tools/actions/workflows/test_publish.yml/badge.svg
    :target: https://pypi.org/project/mef-tools/

.. image:: https://readthedocs.org/projects/mef-tools/badge/?version=latest
    :target: https://mef-tools.readthedocs.io/en/latest/?badge=latest

.. image:: https://img.shields.io/pypi/pyversions/Django
    :target: https://pypi.org/project/mef-tools/

.. image:: https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey
    :target: https://pypi.org/project/mef-tools/


.. warning::

   **mef-tools is deprecated and no longer maintained.**

   It has been superseded by **mef3io** — a from-scratch C++ implementation of
   MEF 3.0 with Python bindings. mef3io offers the same high-level API (a
   drop-in ``mef3io.compat`` mirrors ``mef_tools.io``), plus faster reads and
   writes, parallel block decoding/encoding, and no ``pymef`` build dependency.

   **➡️  Please migrate to mef3io:** https://github.com/bnelair/mef3io
   (``pip install mef3io``)

   This repository remains available for reference and backwards compatibility,
   but will not receive further updates.


MEF_Tools
----------------

This package provides tools for easier `Multiscale Electrophysiology Format (MEF) <https://doi.org/10.1016%2Fj.jneumeth.2009.03.022>`_ data saving and reading. See the example below and `documentation <https://mef-tools.readthedocs.io/en/latest/?badge=latest>`_.


Multiscale Electrophysiology Format (MEF)
-------------------------------------------

`Multiscale Electrophysiology Format (MEF) <https://doi.org/10.1016%2Fj.jneumeth.2009.03.022>`_ is a specialized file format designed for storing electrophysiological data. This format is capable of storing multiple channels of data in a single file, with each channel storing a time series of data points.

MEF is particularly useful for handling large volumes of electrophysiological data, as it employs a variety of techniques such as lossless and lossy compression, data encryption and data de-identification to make the storage and transmission of such data more efficient and secure.

Python's pymef library provides a set of tools for working with MEF files, including reading from and writing to these files. Below are examples demonstrating the use of these tools.

* BH Brinkmann et al., “Large-scale electrophysiology: acquisition, compression, encryption, and storage of big data,“ J. Neurosci Methods. 2009;180(1):185‐192. doi:10.1016/j.jneumeth.2009.03.022

Dependencies
----------------
- `meflib <https://github.com/msel-source/meflib>`_ - binaries are included in the pymef package
- `pymef <https://github.com/msel-source/pymef>`_
- `numpy <https://numpy.org/>`_
- `pandas <https://pandas.pydata.org/>`_


Installation
----------------

See installation instructions `INSTALL.rst <https://github.com/xmival00/MEF_Tools/blob/master/INSTALL.rst>`_.

License
----------------

This software is licensed under the Apache-2.0 License. See `LICENSE <https://github.com/xmival00/MEF_Tools/blob/master/LICENSE>`_ file in the root directory of this project.


Cite
----------------
This toolbox was developed as a part of the following projects. When use whole, parts, or are inspired by, we appreciate you acknowledge and refer these journal papers:

* V. Sladky et al., “Distributed brain co-processor for tracking spikes, seizures and behaviour during electrical brain stimulation,” Brain Commun., vol. 4, no. 3, May 2022, doi: 10.1093/braincomms/fcac115.

* F. Mivalt et al., “Electrical brain stimulation and continuous behavioral state tracking in ambulatory humans,” J. Neural Eng., vol. 19, no. 1, p. 016019, Feb. 2022, doi: 10.1088/1741-2552/ac4bfd.


Example 1
----------------


.. code-block:: python

    import numpy as np
    from tqdm import tqdm
    from datetime import datetime
    from mef_tools.io import MefWriter, MefReader
    
    path = '/mnt/some/path/mef_test.mefd' # Update this !!!
    password_write = 'pwd_write'
    password_read = 'pwd_read'
    
    
    chnames = ['test_channel_1', 'test_channel_2']
    fsamp = 1000 # Hz
    start = datetime.now().timestamp()
    x = [np.random.randn(fsamp*3600), np.random.randn(fsamp*3600)]
    
    Wrt = MefWriter(path, overwrite=True, password1=password_write, password2=password_read) # if overwrite is True, any file with the same name will be overwritten, otherwise the data is appended to the existing file
    Wrt.mef_block_len = int(fsamp)
    Wrt.max_nans_written = 0
    
    
    for idx, ch in tqdm(list(enumerate(chnames))):
        x_ = x[idx]
        Wrt.write_data(x_, ch, start_uutc=start * 1e6, sampling_freq=fsamp, reload_metadata=False, )
    
    
    Rdr = MefReader(path, password_read)
    channels_read = Rdr.channels
    
    print("All properties", Rdr.properties)
    print(f"Sampling rate for channel {channels_read[0]}", Rdr.get_property('fsamp', channels_read[0]))
    x_read = Rdr.get_data(channels_read[0]) # read full length length
    x_read_1s = Rdr.get_data(channels_read[0], start*1e6, (start+1)*1e6) # read 1 second - reading limited data is useful for really huge files.

See more `examples <https://github.com/mselair/mef_tools/tree/master/examples>`_.

Example 2
----------------

See more `examples <https://github.com/mselair/mef_tools/tree/master/examples>`_.

First, we need to import the necessary libraries:

.. code-block:: python

    import os
    import time
    import numpy as np
    import pandas as pd
    from mef_tools.io import MefWriter, MefReader, create_pink_noise

Next, we define the path to our MEF file, and the amount of data (in seconds) we want to write:

.. code-block:: python

    session_name = 'session'
    session_path = os.getcwd() + f'/{session_name}.mefd'
    mef_session_path = session_path
    secs_to_write = 30

We also need to specify the start and end times of our data in uUTC time. uUTC time is the number of microseconds since January 1, 1970, 00:00:00 UTC. We can use the `time <https://docs.python.org/3/library/time.html>`_ library to convert between UTC time and other time formats. In this example, we will use the current time as the start time, and the start time plus the number of seconds we want to write as the end time:

.. code-block:: python

    start_time = int(time.time() * 1e6)
    end_time = int(start_time + 1e6*secs_to_write)


With our file path and timing details set, we can now create our MEFWriter instance:

.. code-block:: python
    pass1 = 'pass1' # password needed for writing to file
    pass2 = 'pass2' # password needed for every read/write operation
    Wrt = MefWriter(session_path, overwrite=True, password1=pass1, password2=pass2)
    Wrt.max_nans_written = 0
    Wrt.data_units = 'mV'

We then create some test data to write to our file:

.. code-block:: python

    fs = 500
    low_b = -10
    up_b = 10
    data_to_write = create_pink_noise(fs, secs_to_write, low_b, up_b)

This data is written to a channel in our MEF file:

.. code-block:: python
    channel = 'channel_1'
    precision = 3
    Wrt.write_data(data_to_write, channel, start_time, fs, precision=precision)

Appending Data to an Existing MEF File
________________________________________

To append data to an existing MEF file, we first need to create a new writer:

.. code-block:: python

    secs_to_append = 5
    discont_length = 3
    append_time = end_time + int(discont_length*1e6)
    append_end = append_time + 1e6*secs_to_append
    data = create_pink_noise(fs, secs_to_append, low_b, up_b)
    Wrt2 = MefWriter(session_path, overwrite=False, password1=pass1, password2=pass2)
    Wrt2.write_data(data, channel, append_time, fs)

Creating a New Segment in the MEF File
________________________________________

To create a new segment, we simply need to change the new_segment flag to True:

.. code-block:: python

    secs_to_write_seg2 = 10
    gap_time = 3.36*1e6
    newseg_time = append_end + int(gap_time)
    newseg_end = newseg_time + 1e6*secs_to_write_seg2
    data = create_pink_noise(fs, secs_to_write_seg2, low_b, up_b)
    data[30:540] = np.nan
    data[660:780] = np.nan
    Writer2.write_data(data, channel, newseg_time, fs, new_segment=True)

We can also write data to a new channel with inferred precision:

.. code-block:: python

    channel = 'channel_2'
    Wrt2.write_data(data, channel, newseg_time, fs, new_segment=True)


Writing Annotations to the MEF File
________________________________________

Annotations can also be added to the MEF file at both the session and channel levels. Here's an example of how to do this:

.. code-block:: python

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


Reading from MEF File
________________________________________


In this example, we create a MefReader instance, print out the properties of the MEF file, and then read the first 10 seconds of data from each channel. The data from each channel is appended to a list.

.. code-block:: python

    Reader = MefReader(session_path, password2=pass2)
    signals = []

    properties = Reader.properties
    print(properties)

    for channel in Reader.channels:
        start_time = Reader.get_property('start_time', channel)
        end_time = Reader.get_property('end_time', channel)
        x = Reader.get_data(channel, start_time, start_time+10*1e6)
        signals.append(x)

