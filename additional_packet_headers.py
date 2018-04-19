# Data structures
import pandas as pd
import datetime
import numpy as np
import csv
import itertools as IT
from collections import OrderedDict
# Web tools
import urllib3
import json
import http
# Plotting
from bokeh.plotting import figure, show, ColumnDataSource
from bokeh.io import output_notebook
from bokeh.models import HoverTool
# Model libraries
from kmodes import kprototypes
# Other
import math
import random
import geoip2.database
#-----------------------------------------------------------------------------
def get_country(dataframe):
    first = dataframe.index[0]
    n = dataframe.index[-1]
    reader = geoip2.database.Reader('/home/motse/mirage_data/GeoLite2-Country.mmdb')
    # print(dataframe.shape)
    print("Processing {} records".format(n-first +1))
    count = 0
    for i in range(first,n+1):
        if count%10000 == 0:
            print(" {}% of records processed".format(round(count/n)))
        try:
            current_ip = dataframe.loc[i,("ip.source")]
            response = reader.country(current_ip)
            name  = response.country.name
            iso = response.country.iso_code
        except:
            name = ""
            iso = ""
        dataframe.loc[i,("country")] = name
        dataframe.loc[i,("country_iso")] = iso
        count += 1
    return dataframe
#-----------------------------------------------------------------------------
def same_source(dataframe):
    seconds = datetime.timedelta(seconds=2)
    first = dataframe.index[0]
    n = dataframe.index[-1]
    
    time_lambda = lambda x: x["time_index"] > (x["time_index"][x.index[-1]]-seconds)
    dataframe.loc[first,("same_source")] = 0 
    for i in range(first+1,n+1,1):
        current_ip = dataframe.loc[i,("ip.source")]        
        ip_lambda = lambda x: x["ip.source"] == current_ip
        same_source = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[ip_lambda,("ip.source")]))
        dataframe.loc[i,("same_source")] = same_source
    return dataframe
#-----------------------------------------------------------------------------
def same_destination_portion(dataframe):
    seconds = datetime.timedelta(seconds=2)
    first = dataframe.index[0]
    n = dataframe.index[-1]
    
    time_lambda = lambda x: x["time_index"] > (x["time_index"][x.index[-1]]-seconds)
    dataframe.loc[first,("same_destination_portion")] = 0
    for i in range(first+1, n+1):
        current_ip = dataframe.loc[i,("ip.destination")]
        
        ip_lambda = lambda x: x["ip.destination"] == current_ip
        total_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,("time_stamp")]))
        same_destination = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[ip_lambda,("ip.destination")]))
        dataframe.loc[i,("same_destination_portion")] = same_destination/total_packets
        
    return dataframe
#-----------------------------------------------------------------------------
def diff_port_portion(dataframe):
    # non-(TCP or UDP or ICMP) are zero
    seconds = datetime.timedelta(seconds=2)
    first = dataframe.index[0]
    n = dataframe.index[-1]
    time_lambda = lambda x: x["time_index"] > (x["time_index"][x.index[-1]]-seconds)
    dataframe.loc[first,("diff_port_portion")] = 0
    for i in range(first+1, n+1):
        total_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,("time_stamp")]))
        if dataframe.loc[i,("ip.protocol")] == "6":
            port = "tcp.destination_port"
        elif dataframe.loc[i,("ip.protocol")] == "17":
            port = "udp.destination_port"
        elif dataframe.loc[i,("ip.protocol")] == "1":
            icmp_lambda = lambda x: x["ip.protocol"] == "1" 
            icmp_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[icmp_lambda,("time_stamp")]))
            dataframe.loc[i,("diff_port_portion")] = (total_packets-icmp_packets)/total_packets
            continue
        else:
            # Do something about icmp
            dataframe.loc[i,("diff_port_portion")] = 0
            continue
        current_port = dataframe.loc[i,(port)]
        port_lambda = lambda x: x[port] != current_port    
        different_port = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[port_lambda,(port)]))
        
        dataframe.loc[i,("diff_port_portion")] = different_port/total_packets      
    return dataframe
#-----------------------------------------------------------------------------
def same_port_portion(dataframe):
    # non-(TCP or UDP or ICMP) are zero
    seconds = datetime.timedelta(seconds=2)
    first = dataframe.index[0]
    n = dataframe.index[-1]
    time_lambda = lambda x: x["time_index"] > (x["time_index"][x.index[-1]]-seconds)
    dataframe.loc[first,("same_port_portion")] = 0
    for i in range(first+1, n+1):
        total_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,("time_stamp")]))
        if dataframe.loc[i,("ip.protocol")] == "6":
            port = "tcp.destination_port"
        elif dataframe.loc[i,("ip.protocol")] == "17":
            port = "udp.destination_port"
        elif dataframe.loc[i,("ip.protocol")] == "1":
            icmp_lambda = lambda x: x["ip.protocol"] == "1" 
            icmp_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[icmp_lambda,("time_stamp")]))
            dataframe.loc[i,("same_port_portion")] = icmp_packets/total_packets
            continue
        else:
            # Do something about icmp
            dataframe.loc[i,("same_port_portion")] = 0
            continue
        current_port = dataframe.loc[i,(port)]
        port_lambda = lambda x: x[port] == current_port    
        same_port = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[port_lambda,(port)]))
        
        dataframe.loc[i,("same_port_portion")] = same_port/total_packets      
    return dataframe
#-----------------------------------------------------------------------------
def same_dest_same_port_portion(dataframe):
    # non-(TCP or UDP or ICMP) are zero
    seconds = datetime.timedelta(seconds=2)
    first = dataframe.index[0]
    n = dataframe.index[-1]
    time_lambda = lambda x: x["time_index"] > (x["time_index"][x.index[-1]]-seconds)
    dataframe.loc[first,("same_dest_same_port_portion")] = 0
    for i in range(first+1, n+1):
        total_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,("time_stamp")]))
        current_ip = dataframe.loc[i,("ip.destination")]
        if dataframe.loc[i,("ip.protocol")] == "6":
            port = "tcp.destination_port"
        elif dataframe.loc[i,("ip.protocol")] == "17":
            port = "udp.destination_port"
        elif dataframe.loc[i,("ip.protocol")] == "1":
            icmp_lambda = lambda x: (x["ip.protocol"] == "1") & (x["ip.destination"] == current_ip)
            icmp_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[icmp_lambda,("time_stamp")]))
            dataframe.loc[i,("same_dest_same_port_portion")] = icmp_packets/total_packets
            continue
        else:
            # Do something about icmp
            dataframe.loc[i,("same_dest_same_port_portion")] = 0
            continue
        current_port = dataframe.loc[i,(port)]
        
        single_lambda = lambda x: (x[port] == current_port) & (x["ip.destination"] == current_ip)

        same_dest_same_port = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[single_lambda,(port)]))
        dataframe.loc[i,("same_dest_same_port_portion")] = same_dest_same_port/total_packets
    return dataframe
#-----------------------------------------------------------------------------
def same_dest_diff_port_portion(dataframe):
    # non-(TCP or UDP or ICMP) are zero
    seconds = datetime.timedelta(seconds=2)
    first = dataframe.index[0]
    n = dataframe.index[-1]
    time_lambda = lambda x: x["time_index"] > (x["time_index"][x.index[-1]]-seconds)
    dataframe.loc[first,("same_dest_diff_port_portion")] = 0
    for i in range(first+1, n+1):
        total_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,("time_stamp")]))
        current_ip = dataframe.loc[i,("ip.destination")]
        if dataframe.loc[i,("ip.protocol")] == "6":
            port = "tcp.destination_port"
        elif dataframe.loc[i,("ip.protocol")] == "17":
            port = "udp.destination_port"
        elif dataframe.loc[i,("ip.protocol")] == "1":
            icmp_lambda = lambda x: (x["ip.protocol"] != "1") & (x["ip.destination"] == current_ip)
            icmp_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[icmp_lambda,("time_stamp")]))
            dataframe.loc[i,("same_dest_diff_port_portion")] = icmp_packets/total_packets
            continue
        else:
            # Do something about icmp
            dataframe.loc[i,("same_dest_diff_port_portion")] = 0
            continue
        current_port = dataframe.loc[i,(port)]
        
        single_lambda = lambda x: (x[port] != current_port) & (x["ip.destination"] == current_ip)

        same_dest_diff_port = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[single_lambda,(port)]))
        dataframe.loc[i,("same_dest_diff_port_portion")] = same_dest_diff_port/total_packets      
    return dataframe
#-----------------------------------------------------------------------------
def diff_dest_same_port_portion(dataframe):
    # non-(TCP or UDP or ICMP) are zero
    seconds = datetime.timedelta(seconds=2)
    first = dataframe.index[0]
    n = dataframe.index[-1]
    time_lambda = lambda x: x["time_index"] > (x["time_index"][x.index[-1]]-seconds)
    dataframe.loc[first,("diff_dest_same_port_portion")] = 0
    for i in range(first+1, n+1):
        total_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,("time_stamp")]))
        current_ip = dataframe.loc[i,("ip.destination")]
        if dataframe.loc[i,("ip.protocol")] == "6":
            port = "tcp.destination_port"
        elif dataframe.loc[i,("ip.protocol")] == "17":
            port = "udp.destination_port"
        elif dataframe.loc[i,("ip.protocol")] == "1":
            icmp_lambda = lambda x: (x["ip.protocol"] == "1") & (x["ip.source"] == current_ip)
            icmp_packets = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[icmp_lambda,("time_stamp")]))
            dataframe.loc[i,("diff_dest_same_port_portion")] = (total_packets-icmp_packets)/total_packets
            continue
        else:
            # Do something about icmp
            dataframe.loc[i,("diff_dest_same_port_portion")] = 0
            continue
        current_port = dataframe.loc[i,(port)]
        
        single_lambda = lambda x: (x[port] == current_port) & (x["ip.destination"] != current_ip)

        diff_dest_same_port = len(list(dataframe.loc[:i-1,:].loc[time_lambda,:].loc[single_lambda,(port)]))
        dataframe.loc[i,("diff_dest_same_port_portion")] = diff_dest_same_port/total_packets      
    return dataframe
#-----------------------------------------------------------------------------
def time_of_day(dataframe):
    seconds = datetime.timedelta(seconds=2)
    first = dataframe.index[0]
    n = dataframe.index[-1]
    for i in range(first, n+1):
        timestamp = dataframe.loc[i,("time_stamp")]
        date_time = datetime.datetime.fromtimestamp(timestamp)
        time = date_time.time()
        dataframe.loc[i,("time_of_day")] = str(time)
    return dataframe
#-----------------------------------------------------------------------------
def polar_time(dataframe):
    first = dataframe.index[0]
    n = dataframe.index[-1]
    pi = 2*math.pi
    den = 86400
    for i in range(first, n+1):
        timestamp = dataframe.loc[i,("time_stamp")]
        date_time = datetime.datetime.fromtimestamp(timestamp)
        seconds = get_seconds(date_time)
        dataframe.loc[i,("sin_time")] = math.sin(pi*seconds/den)
        dataframe.loc[i,("cos_time")] = math.cos(pi*seconds/den)
    return dataframe
#-----------------------------------------------------------------------------
def get_seconds(dt_object):
    hour = dt_object.hour*3600
    minute = dt_object.minute*60
    second = dt_object.second
    seconds = hour + minute + second
    return seconds
#-----------------------------------------------------------------------------
def binary_to_int(dataframe):
    first = dataframe.index[0]
    n = dataframe.index[-1]
    for i in range(first, n+1):
        dataframe.loc[i,("ip.ecn")] = int((dataframe.loc[i,("ip.ecn")]), 2)
    return dataframe
#-----------------------------------------------------------------------------
def main():
    print("Nothing to execute...")
#-----------------------------------------------------------------------------
if __name__ == '__main__':
    print("additional_packet_headers is being run directly")
    main()
else:
    print("additional_packet_headers is being imported into another module")