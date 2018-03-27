<h1>SerialiseNetworkCaptureFile</h1>

This program pulls the protocol headers from pcap files and writes them to
a csv file.

Instructions:
```python
from SerialiseNetworkCaptureFile import SerialiseNetworkCaptureFile
input_dirctory_name = '~/directory/containing/pcap/files/'
input_file_name  = 'filename.pcap'
output_directory_name = '~/directory/where/you/want/to/save/csv/'
output_file_name = 'filename.csv'

sncf = SerialiseNetworkCaptureFile(input_dirctory_name, input_file_name, output_directory_name, output_file_name)
sncf.serialise()
```

The Ethernet frame has the following headers:

Header | Data Type | Description
---------- | ---------- | ----------------
time_stamp | int |Number of seconds since Unix epoch
destination | bytes string | Might be a MAC address
source | bytes string | I can't decode. Might be a MAC address
type | int | IP/MAC version being used