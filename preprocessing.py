#!/usr/bin/env python3
# Data structures
import pandas as pd
import datetime
import numpy as np

# Other
import math
import random
import additional_packet_headers as aph
import time

#-----------------------------------------------------------------------------
def get_alpha_code(column):
    countries = pd.read_csv('/home/motse/mirage_data/2018/ISO.csv', sep=',',header=0, usecols=['country_iso','alpha_2_code'])
    values = countries.values.tolist()
    result = []
    for line in column:
        index = np.where(countries.values == [line])
        if len(index[0]) == 1:
            index = index[0][0]
            alpha_2_code = values[index][1]
        else:
            alpha_2_code = ''
        result.append(alpha_2_code)
    return result
#-----------------------------------------------------------------------------
def set_well_known(number):
    if number in range(1,20):
        return 1
    else:
        return 0
#-----------------------------------------------------------------------------
def set_registered(number):
    if number in range(1024,49152):
        return 1
    else:
        return 0
#-----------------------------------------------------------------------------
def set_ephemeral(number):
    if number in range(49152, 65535):
        return 1
    else:
        return 0
#-----------------------------------------------------------------------------
def set_options_binary_string(number):
    # print(number)
    number = int(number)
    length = len('{0:b}'.format(number))
    string = '0'*(9- length) + '{0:b}'.format(number)
    return string

#-----------------------------------------------------------------------------
def set_traffic_status(number):
    # print(number)
    number = int(number)
    length = len('{0:b}'.format(number))
    string = '0'*(9- length) + '{0:b}'.format(number)
    if string[4] == '1' and string[6] == '0':
        # print(string)
        status = 'Active'
    else:
        # print(string)
        status = 'Passive'
    return status
#-----------------------------------------------------------------------------
def filter_to_period(start, end, uri, new_uri):
    print("Opening csv file {}...".format(uri))
    df = pd.read_csv(uri, sep=',',header=0, skipinitialspace=True)
    print(df.shape)
    print("Filtering packets...")
    df = df.loc[lambda x: (x['time_stamp'] >= start ) & (x['time_stamp'] < end ),:]
    print(df.shape)
    print("Saving new csv file as {}...".format(new_uri))
    df.to_csv(new_uri, index=False)
    print("Complete...")
#-----------------------------------------------------------------------------
def augment_data(uri, new_uri):
    program_start_time = time.time()
    pop_cols = ['time_stamp',
     'ip.ecn',
     'ip.length',
     'ip.identification',
     'ip.offset',
     'ip.ttl',
     'ip.protocol',
     'ip.checksum',
     'ip.source',
     'ip.destination',
     'tcp.source_port',
     'tcp.destination_port',
     'tcp.sequence',
     'tcp.acknowledge',
     'tcp.offset',
     'tcp.flags',
     'tcp.checksum',
     'tcp.urgent_point']
    print("Opening csv file...")
    start_time = time.time()
    df = pd.read_csv(uri, sep=',',header=0, skipinitialspace=True, usecols=pop_cols)
    print("--- {} seconds ---".format(round(time.time() - start_time)))
    print("Dataframe dimensions: {}".format(df.shape))

    print("Removing non TCP records...")
    tcp_only = lambda x: x['ip.protocol'] == 6
    df_tcp = df.loc[tcp_only,:].copy()
    df_tcp.reset_index(inplace=True, drop=True)
    print("Dataframe dimensions: {}".format(df_tcp.shape))

    print("Drop null values from tcp.flags...")
    df_tcp.dropna(subset=['tcp.flags'], inplace=True)
    df_tcp.reset_index(inplace=True, drop=True)
    print("Dataframe dimensions: {}".format(df_tcp.shape))
    
    print("Adding TCP Flags binary string as feature...")
    start_time = time.time()
    df_tcp.loc[:,'tcp_flags_binary_string'] = df_tcp.loc[:,'tcp.flags'].apply(set_options_binary_string)
    print("--- {} seconds ---".format(round(time.time() - start_time)))

    start_time = time.time()
    print("Adding traffic status as feature...")
    df_tcp.loc[:,'traffic_status'] = df_tcp.loc[:,'tcp.flags'].apply(set_traffic_status)
    print("Dataframe dimensions: {}".format(df_tcp.shape))
    print("--- {} seconds ---".format(round(time.time() - start_time)))

    print("Removing non active records (passive & other)...")
    active_only = lambda x: x.loc[:,'traffic_status'] == 'Active'

    df_tcp_active = df_tcp.loc[active_only,:]
    df_tcp_active.reset_index(inplace=True, drop=True)
    print("Dataframe dimensions: {}".format(df_tcp_active.shape))

    df_tcp_active = df_tcp_active.astype({'ip.identification':str, 'tcp.source_port':str,'tcp.destination_port':str })

    print("Setting country of origin...")
    start_time = time.time()
    df_tcp_active = aph.get_country(df_tcp_active.copy())
    print("--- {} seconds ---".format(round(time.time() - start_time)))
    # df_tcp_active.drop(columns=['index'], inplace=True)

    print("Converting time to polar values...")
    start_time = time.time()
    df_tcp_active = aph.polar_time(df_tcp_active.copy())
    df_tcp_active.loc[:,('time_index')] = pd.to_datetime(df_tcp_active.loc[:,('time_stamp')], unit='s')
    print("--- {} seconds ---".format(round(time.time() - start_time)))

    start_time = time.time()
    print("Setting fields based on previous 2 second window...")
    df_tcp_active = aph.same_source(df_tcp_active.copy())
    df_tcp_active = aph.same_destination_portion(df_tcp_active.copy())
    print("28% ...")
    df_tcp_active = aph.diff_port_portion(df_tcp_active.copy())
    df_tcp_active = aph.same_port_portion(df_tcp_active.copy())
    print("57% ...")
    df_tcp_active = aph.same_dest_same_port_portion(df_tcp_active.copy())
    df_tcp_active = aph.same_dest_diff_port_portion(df_tcp_active.copy())
    print("85% ...")
    df_tcp_active = aph.diff_dest_same_port_portion(df_tcp_active.copy())
    print("100% ...")
    print("--- {} seconds ---".format(round(time.time() - start_time)))
    df_tcp_active = df_tcp_active.astype({'tcp.source_port':float})
    df_tcp_active = df_tcp_active.astype({'tcp.destination_port':float})

    df_tcp_active.loc[:,'tcp.source_port'] = df_tcp_active.loc[:,'tcp.source_port'].fillna(0)
    df_tcp_active.loc[:,'tcp.destination_port'] = df_tcp_active.loc[:,'tcp.destination_port'].fillna(0)

    start_time = time.time()
    print("Setting port types...")
    df_tcp_active.loc[:,'well_known_src_port'] = df_tcp_active.loc[:,'tcp.source_port'].apply(set_well_known)
    df_tcp_active.loc[:,'well_known_dst_port'] = df_tcp_active.loc[:,'tcp.destination_port'].apply(set_well_known)
    print("33% ...")
    df_tcp_active.loc[:,'registered_src_port'] = df_tcp_active.loc[:,'tcp.source_port'].apply(set_registered)
    df_tcp_active.loc[:,'registered_dst_port'] = df_tcp_active.loc[:,'tcp.destination_port'].apply(set_registered)
    print("66% ...")
    df_tcp_active.loc[:,'ephemeral_src_port'] = df_tcp_active.loc[:,'tcp.source_port'].apply(set_ephemeral)
    df_tcp_active.loc[:,'ephemeral_dst_port'] = df_tcp_active.loc[:,'tcp.destination_port'].apply(set_ephemeral)
    print("100% ...")
    print("--- {} seconds ---".format(round(time.time() - start_time)))

    

    df_tcp_active.drop(columns=['tcp.source_port','tcp.destination_port'], inplace=True)
    df_tcp_active.drop(columns=['ip.ecn','ip.protocol'], inplace=True)

    df_tcp_active.loc[:,'tcp.acknowledge'] = df_tcp_active.loc[:,'tcp.acknowledge'].fillna(0)
    df_tcp_active.loc[:,'tcp.sequence'] = df_tcp_active.loc[:,'tcp.sequence'].fillna(0)
    df_tcp_active.loc[:,'tcp.offset'] = df_tcp_active.loc[:,'tcp.offset'].fillna(0)
    df_tcp_active.loc[:,'tcp.urgent_point'] = df_tcp_active.loc[:,'tcp.urgent_point'].fillna(0)

    data = df_tcp_active.loc[:,['time_stamp','sin_time','cos_time','ip.length','ip.identification','ip.offset','ip.ttl',
                             'tcp.acknowledge','tcp.sequence','tcp.offset','tcp.urgent_point', 
                             'well_known_src_port', 'well_known_dst_port','registered_src_port',
                             'registered_dst_port','ephemeral_src_port','ephemeral_dst_port', 
                             'same_source','same_destination_portion','diff_port_portion','same_port_portion',
                             'same_dest_same_port_portion','same_dest_diff_port_portion','diff_dest_same_port_portion',
                             'ip.source','ip.destination', 'country', 'country_iso']].copy()
    
    print("Setting country alpha 2 codes ...")
    start_time = time.time()
    data.loc[:,'alpha_2_code'] = pd.DataFrame(get_alpha_code(df_tcp_active.loc[:,'country_iso']),columns=['alpha_2_code'])
    print("--- {} seconds ---".format(round(time.time() - start_time)))
    
    print("Writing rows to disk...")
    start_time = time.time()
    data.to_csv(new_uri, index=False)
    print("--- {} seconds ---".format(round(time.time() - start_time)))

    print("Total time: {} minutes ---".format(round(time.time() - program_start_time)/60))
    
#-----------------------------------------------------------------------------  
def main():
    print("Nothing to run...")
#-----------------------------------------------------------------------------
if __name__ == '__main__':
    print("preprocessing is being run directly")
    main()
else:
    print("preprocessing is being imported into another module")