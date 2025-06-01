from mef_tools import MefReader, MefWriter
import os
import numpy as np
from datetime import datetime

from mef_tools.reimplementation import TimeSeriesMetadataFile, EncryptionHandler, UniversalHeader, TimeSeriesMetadataFile, TimeSeriesMetadataSection2

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

    rdr = MefReader(path, 'kokot.')

    pth = os.path.join(path, 'ch1.timd', 'ch1-000000.segd', 'ch1-000000.tmet')

    # self = UniversalHeader(filepath=pth)

    self = TimeSeriesMetadataFile(pth, 'kokot.')

    # print(self)

    print('\n\n######## Universal #############')
    for k, v in self.universal_header.data.items():
        print(f"{k}: {v}")

    print('\n\n######## Section 1 #############')
    for k, v in self.section1.data.items():
        print(f"{k}: {v}")

    print('\n\n######## Section 2 #############')
    print(self.section2)
    for k, v in self.section2.data.items():
        print(f"{k}: {v}")

    print('\n\n######## Section 3 #############')
    print(self.section3)
    for k, v in self.section3.data.items():
        print(f"{k}: {v}")


    print(self.section2.channel_description)
    print('done')

    print(self.section3.gmt_offset)

    self.section2._data_raw.keys()
    #
    # # self.section2.number_of_discontinuities_raw =

    section2 = TimeSeriesMetadataSection2(create_new=True)

    self.section2.channel_description = 'kokooo999999999ot'


    #
    # self.section2.units_conversion_factor = 0.1
