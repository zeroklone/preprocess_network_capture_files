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
destination | bytes string | MAC address
source | bytes string | MAC address
type | int | IP/MAC version being used

The IP frame has the following headers:

Header | Data Type | Description
--- | --- | ---     
_v_hl | int | Contains version and IHL bit strings.
version | str | (4 bits) The IP version number bit string.
ihl | str  | (4 bits) Internet Header Length.
tos | int | (8 bits) Type of Service. Now deprecated. Before it was deprecated the first three bits indicated Precedence and the next five TOS. Bits 0-5 now contain DSCP, bits 6-7 ECN.
dscp | str | (6 bits) Six-bit Differentiated Services Code Point (DSCP). Extracted from tos.
ecn | str | (2 bits) two-bit Explicit Congestion Notification (ECN). Extracted from tos
length | int | number of octets that the IP datagram takes up including the header. The maximum size that an IP datagram can be is 65,535 octets.
identification | int | The Identification is a unique number assigned to a datagram fragment to help in the reassembly of fragmented datagrams.
offset | int | (64 bits) In units of 8 octets this specifies a value for each data fragment in the reassembly process. Different sized Maximum Transmission Units (MTUs) can be used throughout the Internet.
ttl | int | The time that the datagram is allowed to exist on the network. A router that processes the packet decrements this by one. Once the value reaches 0, the packet is discarded.
protocol | int | Layer 4 protocol sending the datagram, UDP uses the number 17, TCP uses 6, ICMP uses 1, IGRP uses 88 and OSPF uses 89.
checksum | int | Error control for the header only.
source | str | Source IP address
destination | str | Destination IP address.

All binary data is written the the csv as an int. The **__to_bits function** can be used to unpack a bit string from any given int. 
It is advised to use the **__pad_string** function to get the string to the necessary length before attempting to interpret it. The bit strings are written as integers because the **read_csv()** function in the Python implementation of Pandas cannot be set to treat fields containing numbers as strings, which leads it to strip the leading zeros from bit strings. 