#!/usr/bin/env python3

'''
This program pulls the protocol headers from pcap files and writes them to
a csv file.

instructions:

from SerialiseNetworkCaptureFile import SerialiseNetworkCaptureFile
input_dirctory_name = '~/directory/containing/pcap/files/'
input_file_name  = 'filename.pcap'
output_directory_name = '~/directory/where/you/want/to/save/csv/'
output_file_name = 'filename.csv'

sncf = SerialiseNetworkCaptureFile(input_dirctory_name, input_file_name, output_directory_name, output_file_name)
sncf.serialise()
'''
__author__ = 'Motse Lehata'
__email__ = 'mmlehata@me.com'

import dpkt
import socket
import json
from struct import pack,unpack
import logging
#-----------------------------------------------------------------------------
class SerialiseNetworkCaptureFile:
    def __init__(self, pcap_path, pcap_filename, output_path, output_filename):
        #The init
        self.pcap_path = pcap_path
        self.output_path = output_path
        self.pcap_filename = pcap_filename
        self.output_filename = output_filename

        with open(self.pcap_path+self.pcap_filename, 'rb') as capture_file:
            self.pcap = dpkt.pcap.Reader(capture_file)

        
    #-------------------------------------------------------------------------
    def __inet_to_ip(self, address, version):
        if version == '0100':
            string_address = socket.inet_ntoa(address)
        else:
            string_address = socket.inet_ntop(socket.AF_INET6, address)

        return string_address
    #-------------------------------------------------------------------------
    def __bytes_mac_to_string_mac(self, bytes_mac_address):
        mac_address = ''
        for element in bytes_mac_address:
            hex_element = format(element,'02x')
            mac_address = mac_address + ':' + str(hex_element)
        mac_address = mac_address[1:]
        return mac_address
    #-------------------------------------------------------------------------
    def __to_bits(self, number):
        bits = '{0:b}'.format(number)
        return bits
    #-------------------------------------------------------------------------
    def __expand_v_hl(self, _v_hl):
        #Hmm
        bit_string = self.__to_bits(_v_hl)
        bit_string = self.__pad_string(bit_string, 8, '0', 'left')
        version = bit_string[0:4]
        ihl = bit_string[4:8]
        return version, ihl
    #-------------------------------------------------------------------------
    def __expand_tos(self, tos):
        bit_string = self.__to_bits(tos)
        bit_string = self.__pad_string(bit_string, 8, '0', 'left')
        dscp = bit_string[0:6]
        ecn = bit_string[6:8]
        return dscp, ecn
    #-------------------------------------------------------------------------
    def __bit_to_int(self, bit_string):
        number = int(bit_string, 2)
        return number
    #-------------------------------------------------------------------------
    def __expand_tcp_flags(self, flags):
        bit_string = self.__to_bits(flags)
        bit_string = self.__pad_string(bit_string, 8, '0', 'left')
        
        CWR = bit_string[0]
        ECE = bit_string[1]
        URG = bit_string[2]
        ACK = bit_string[3]
        PSH = bit_string[4]
        RST = bit_string[5]
        SYN = bit_string[6]
        FIN = bit_string[7]
        # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
        return bit_string
    #-------------------------------------------------------------------------
    def __pad_string(self, string, target_length, replacement, side):
        #Things may go badly of the string is longer that the target length.
        if side == 'left':
            string = replacement*(target_length - len(string)) + string
        elif side == 'right':
            string = string + replacement*(target_length - len(string))

        return string
    #-------------------------------------------------------------------------
    def __serialise_icmp(self, eth):
        try:
            icmp = eth.ip.icmp
            icmp_contents = [icmp.type, icmp.code, icmp.sum]
        except AttributeError:
            icmp_contents = ['' for i in range(3)]
        
        return icmp_contents
    #-------------------------------------------------------------------------
    def __serialise_tcp(self, eth):
        try:
            tcp = eth.ip.tcp
            # options_list = dpkt.tcp.parse_opts(tcp.opts)
            options_list = ''
            tcp_flags  = self.__expand_tcp_flags(tcp.flags)
            tcp_contents = [tcp.sport, tcp.dport, tcp.seq, tcp.ack, tcp.off,
                            self.__bit_to_int(tcp_flags), tcp.sum, tcp.urp, 
                            options_list]
        except AttributeError:
            tcp_contents = ['' for i in range(9)]

        return tcp_contents
    #-------------------------------------------------------------------------
    def __serialise_udp(self, eth):
        try:
            udp = eth.ip.udp
            udp_contents =[udp.sport, udp.dport, udp.sum, udp.ulen]
        except AttributeError:
            udp_contents = ['' for i in range(4)]
        return udp_contents
    #-------------------------------------------------------------------------
    def __serialise_ethernet(self, ts, eth):
        ''' ethernet has the following in it:
            
            time_stamp
            int
            Number of seconds since Unix epoch
            
            destination
            bytes string
            I can't decode it. Might be a MAC address
            
            source
            bytes string
            I can't decode. Might be a MAC address
            
            Type
            int
            IP/MAC version being used
        '''
        try:
            src = self.__bytes_mac_to_string_mac(eth.src)
            dst = self.__bytes_mac_to_string_mac(eth.dst)
            eth_contents = [ts, src, dst, eth.type]
        except AttributeError:
            eth_contents = ['' for i in range(4)]

        return eth_contents
    #-------------------------------------------------------------------------
    def __serialise_ip(self, eth):
        ''' ip  has the following in it:
        
            _v_hl
            int (representing 8 bits)
            Contains version and IHL
            
            version
            str (binary, representing 4 bits)
            The IP version number (currently binary 0100 (4), but can now also be version
            6). All nodes must use the same version.
            
            ihl
            str (binary, reprenting 4 bits)
            The length of the entire IP header in 32-bit words
            
            tos
            int (representing 8 bits)
            Type of Service. Now deprecated. Before it was deprecated the first three bits
            indicated Precedence and the next five TOS.
            Bits 0-5 now contain DSCP, bits 6-7 ECN.(will split)
            
            dscp
            str (representing 6 bits)
            six-bit Differentiated Services Code Point (DSCP). Extracted from tos.
            
            ecn (representing 2 bits)
            str
            two-bit Explicit Congestion Notification (ECN). Extracted from tos
            
            length
            int
            number of octets that the IP datagram takes up including the header.
            The maximum size that an IP datagram can be is 65,535 octets.
            
            identification
            int
            The Identification is a unique number assigned to a datagram fragment to help
            in the reassembly of fragmented datagrams.
            
            offset
            int
            in units of 8 octets (64 bits) this specifies a value for each data fragment in
            the reassembly process. Different sized Maximum Transmission Units (MTUs)
            can be used throughout the Internet.
            
            ttl
            int
            The time that the datagram is allowed to exist on the network. A router that
            processes the packet decrements this by one. Once the value reaches 0, the
            packet is discarded.
            
            protocol
            int
            Layer 4 protocol sending the datagram, UDP uses the number 17, TCP uses 6, 
            ICMP uses 1, IGRP uses 88 and OSPF uses 89.
            
            checksum
            int
            Error control for the header only.
            
            source
            str
            Source IP address
            
            destination
            str
            Destination IP address 
        '''
        try:
            ip = eth.ip
            version, ihl = self.__expand_v_hl(ip._v_hl)
            dscp, ecn = self.__expand_tos(ip.tos)
            src = self.__inet_to_ip(ip.src, version)
            dst = self.__inet_to_ip(ip.dst, version)
            ip_contents = [ip._v_hl, self.__bit_to_int(version),
                            self.__bit_to_int(ihl), ip.tos, 
                            self.__bit_to_int(dscp), 
                            self.__bit_to_int(ecn), ip.len,
                            ip.id, ip.off, ip.ttl, ip.p, ip.sum, src, dst]
        except AttributeError:
            ip_contents = ['' for i in range(14)]
        return ip_contents
    #-------------------------------------------------------------------------       
    def serialise(self):
        logger = logging.getLogger()
        index = 0
        columns = ('time_stamp,eth.source,eth.destination,'
            'eth.type,ip._v_hl,ip.version,ip.ihl,ip.tos,'
            'ip.dscp,ip.ecn,ip.length,ip.identification,'
            'ip.offset,ip.ttl,ip.protocol,ip.checksum,'
            'ip.source,ip.destination,icmp.type,icmp.code,'
            'icmp.checksum,tcp.source_port,'
            'tcp.destination_port,tcp.sequence,tcp.acknowledge,'
            'tcp.offset,tcp.flags,tcp.checksum,tcp.urgent_point,'
            'tcp.options,udp.source_port,udp.destination_port,'
            'udp.checksum,udp.ulen,filename,index_in_file')

        with open(self.output_path+self.output_filename, 'a') as text_file:
            # columns_as_string = str(columns)[1:len(str(columns))-1] + '\n'
            print("printing columns")
            text_file.write(columns+'\n')
            for ts,buf in self.pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)

                    packet = self.__serialise_ethernet(ts, eth)
                    packet += self.__serialise_ip(eth)
                    packet += self.__serialise_icmp(eth)
                    packet += self.__serialise_tcp(eth)
                    packet += self.__serialise_udp(eth)
                    packet += [self.pcap_filename, index] 
                except TypeError:
                    packet = ['' for i in range(34)]
                    packet += [self.pcap_filename, index]
                except Exception as e:
                    logger.error('{}'.format(str(e)))
                    print("probable blank line, skipping")
                    continue
                # print("Building packet string...")
                packet_as_string = (str(packet)[1:len(str(packet))-1]).replace('\'','') + '\n'
                text_file.write(packet_as_string)
                index += 1

#-----------------------------------------------------------------------------
def main():
    print("Read the docstring...")

#-----------------------------------------------------------------------------
if __name__ == '__main__':
    print("SerialiseNetworkCaptureFile is being run directly")
    main()
else:
    print("SerialiseNetworkCaptureFile is being imported into another module")