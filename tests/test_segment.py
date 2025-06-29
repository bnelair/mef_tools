from mef_tools import MefReader, MefWriter
import os
import numpy as np
from datetime import datetime
import time

from mef_tools.reimplementation import (
    TimeSeriesMetadataFile, EncryptionHandler, UniversalHeader,
    TimeSeriesMetadataFile, TimeSeriesMetadataSection2,
    TimeSeriesIndicesFile, TimeSeriesIndexEntry
)

def test_try():
    path = '/Users/mivalt.filip/mef_tools_new/mef_tools_new/test.mefd'

    wrt = MefWriter(path, overwrite=True)

    wrt = MefWriter(path, overwrite=True, password1='kokot', password2='kokot.')
    wrt.mef_block_len = 100
    wrt.data_units = 'µV'
    wrt.max_nans_written = 0

    start = datetime.now().timestamp() * 1e6
    x = np.random.randn(1005)
    wrt.write_data(x, 'ch1', start, 250, precision=3)

    t1 = time.time()
    rdr = MefReader(path, 'kokot.')
    t2 = time.time()
    print(f"Time to read file: {t2 - t1:.4f} seconds")

    pth_tmet = os.path.join(path, 'ch1.timd', 'ch1-000000.segd', 'ch1-000000.tmet')
    pth_tidx = os.path.join(path, 'ch1.timd', 'ch1-000000.segd', 'ch1-000000.tidx')

    # self = UniversalHeader(filepath=pth)

    t1 = time.time()
    tmet_file = TimeSeriesMetadataFile(pth_tmet, 'kokot.')
    tidx_file = TimeSeriesIndicesFile(pth_tidx, 'kokot.')
    t2 = time.time()
    print(f"Time to read metadata files: {t2 - t1:.4f} seconds")

    print('\n\n######## Universal #############')
    for k, v in tmet_file.universal_header.data.items():
        print(f"{k}: {v}")

    print('\n\n######## Section 1 #############')
    for k, v in tmet_file.section1.data.items():
        print(f"{k}: {v}")

    print('\n\n######## Section 2 #############')
    print(tmet_file.section2)
    for k, v in tmet_file.section2.data.items():
        print(f"{k}: {v}")

    print('\n\n######## Section 3 #############')
    print(tmet_file.section3)
    for k, v in tmet_file.section3.data.items():
        print(f"{k}: {v}")


    self = TimeSeriesIndicesFile(pth_tidx, 'kokot.')

    print('\n\n######## TIDX UH #############')
    for k, v in self.universal_header.data.items():
        print(f"{k}: {v}")

    print('\n\n######## TIDX Entry #############')
    for entry in self.entries:
        print(entry)
        print('---')
        for k, v in entry.data.items():
            print(f"{k}: {v}")


    new_entry = TimeSeriesIndexEntry(create_new=True)


    print('kokooot')
    #
    # self.section2.units_conversion_factor = 0.1
