# -*- coding: utf-8 -*-
"""
Created on Mon Aug 10 22:12:06 2020

@author: Rolando Inglés
"""
import pandas as pd

# UNSW-NB15 specific imports
import unsw_nb15_utils as unswutils

##
# features descriptions:
# https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/NUSW-NB15_features.csv
#
unsw_nb15_all_columns = [
    'srcip',
    'sport',
    'dstip',
    'dsport',
    'proto',
    'state',
    'dur',
    'sbytes',
    'dbytes',
    'sttl',
    'dttl',
    'sloss',
    'dloss',
    'service',
    'Sload',
    'Dload',
    'Spkts',
    'Dpkts',
    'swin',
    'dwin',
    'stcpb',
    'dtcpb',
    'smeansz',
    'dmeansz',
    'trans_depth',
    'res_bdy_len',
    'Sjit',
    'Djit',
    'Stime',
    'Ltime',
    'Sintpkt',
    'Dintpkt',
    'tcprtt',
    'synack',
    'ackdat',
    'is_sm_ips_ports',
    'ct_state_ttl',
    'ct_flw_http_mthd',
    'is_ftp_login',
    'ct_ftp_cmd',
    'ct_srv_src',
    'ct_srv_dst',
    'ct_dst_ltm',
    'ct_src_ ltm',
    'ct_src_dport_ltm',
    'ct_dst_sport_ltm',
    'ct_dst_src_ltm',
    'attack_cat',
    'Label'
]

unsw_nb15_X_selected_columns = [
    'dsport',
    'proto',
    'state',
    'dur',
    'sbytes',
    'dbytes',
    'sttl',
    'dttl',
    'sloss',
    'dloss',
    'service',
    'Sload',
    'Dload',
    'Spkts',
    'Dpkts',
    'Sjit',
    'Djit',
    'Sintpkt',
    'Dintpkt',
    'synack',
    'ackdat'
]

unsw_nb15_y_selected_columns = [
    'attack_cat',
    'Label'
]

iot_23_X_selected_scalars_columns = [
                            'dur',
                            'sbytes',
                            'dbytes',
                            'sttl',
                            'dttl',
                            'sloss',
                            'dloss',
                            'Sload',
                            'Dload',
                            'Spkts',
                            'Dpkts',
                            'Sjit',
                            'Djit',
                            'Sinkpkt',
                            'Dintpkt',
                            'synack',
                            'ackdat'
                            ]


##
# @name get_data_set
#
# Objective: open CSV file based on the tag and return a dataframe object
#
# Parameters: The tag: 5K 10K 25K 50K 100K 
#
# Returns: raw_X    dataframe to be used as X_train
#           raw_y   dataframe to be used as y_train 
#   
def get_X_raw_y_raw(data_set_tag='notag'):
    data_set_input_filename = unswutils.get_unsw_nb15_output_filename(data_set_tag)
    
    # NOTE: 80 features are loaded
    raw_data_set_df = pd.read_csv(data_set_input_filename)
    raw_X = raw_data_set_df.filter(items=unsw_nb15_X_selected_columns)
    raw_y = raw_data_set_df.filter(items=unsw_nb15_y_selected_columns)
    
    return raw_X, raw_y

##
# @name get_wrangled_scalars
#
# Objective:    Munging columns with scalar content from the passed UNSW-NB15 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      scalars_df - the dataframe containing the wrangled
#                               'scalars' columns data
#                               
def get_wrangled_scalars(raw_df=None): 
    scalars_df = raw_df.filter(items=iot_23_X_selected_scalars_columns)
    
    return scalars_df

##
# @name dsport_normalizer
#
# Objective:    Converting into numeric the port value 
# Parameters:
#               row
# Returns:
#               the normalized port value
#
def dsport_normalizer(row):
    try:
        if row['dsport'].isnumeric():
            return int(row['dsport'])
        else:
            return int(row['dsport'], 16)
    except AttributeError:
        # is already int
        return row['dsport']
    except Exception:
        return -1
    
##
# @name get_wrangled_dsport
#
# Objective:    Munging the 'dsport' column from the passed UNSW_NB15 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      dsport_df - the dataframe containing the wrangled
#                               'dsport' column data
#                   
def get_ohe_from_dsport(raw_df=None):
    #
    # based on: https://tools.ietf.org/html/rfc1340
    
    dsport_df = raw_df[['dsport']].copy()
    
    dsport_df.loc[:, '_dsport_'] = 0
    
    dsport_df.loc[:, ('_dsport_')] = dsport_df.apply(dsport_normalizer, axis=1)
# =============================================================================
#     dsport_df.loc[:, ('_dsport_')] = dsport_df.apply(lambda row: 
#                                             int(row['dsport']) if row['dsport'].str.isnumeric() 
#                                             else int(row['dsport'], 16),
#                                             axis=1)
#     
# =============================================================================
    # RFC1340: The Registered Ports are in the range 1024-65535
    dsport_df.loc[:, ('dsport')] = 'gt_65535'
    dsport_df.loc[dsport_df._dsport_ < 65536, 'dsport'] = '1024_65535'
    dsport_df.loc[dsport_df._dsport_ < 1024, 'dsport'] = 'lt_1024'
    
    # reserved
    dsport_df.loc[dsport_df._dsport_ == 0, 'dsport'] = 'reserved'
    
    # ssh
    dsport_df.loc[dsport_df._dsport_ == 22, 'dsport'] = 'ssh'
    
    # telnet
    dsport_df.loc[dsport_df._dsport_ == 23, 'dsport'] = 'telnet'
    
    # smtp
    dsport_df.loc[dsport_df._dsport_ == 25, 'dsport'] = 'smtp'
    
    # Message Processing Module [recv]
    dsport_df.loc[dsport_df._dsport_ == 45, 'dsport'] = 'mpm'
    
    # Domain Name Server
    dsport_df.loc[dsport_df._dsport_ == 53, 'dsport'] = 'dns'
    
    # World Wide Web HTTP 
    dsport_df.loc[dsport_df._dsport_ == 80, 'dsport'] = 'http_80'
    
    # sunrpc
    dsport_df.loc[dsport_df._dsport_ == 111, 'dsport'] = 'sunrpc'
    
    # ntp
    dsport_df.loc[dsport_df._dsport_ == 123, 'dsport'] = 'ntp'
    
    # imap2
    dsport_df.loc[dsport_df._dsport_ == 143, 'dsport'] = 'imap2'
    
    # bgp
    dsport_df.loc[dsport_df._dsport_ == 179, 'dsport'] = 'bgp'
    
     # https
    dsport_df.loc[dsport_df._dsport_ == 443, 'dsport'] = 'https'
    
     # mdqs
    dsport_df.loc[dsport_df._dsport_ == 666, 'dsport'] = 'mdqs'
    
    # messenger
    dsport_df.loc[dsport_df._dsport_ == 5190, 'dsport'] = 'messenger'
    
    # bittorrent
    dsport_df.loc[dsport_df._dsport_ == 6881, 'dsport'] = 'bittorrent'
    
    # World Wide Web HTTP 
    dsport_df.loc[dsport_df._dsport_ == 8080, 'dsport'] = 'http_8080'
    
    # World Wide Web HTTP 
    dsport_df.loc[dsport_df._dsport_ == 8081, 'dsport'] = 'http_8081'
    
    dsport_df = pd.concat([dsport_df, pd.get_dummies(dsport_df['dsport'], prefix='dsport')], axis=1)
    dsport_df.drop(['dsport'], axis=1, inplace=True)
    dsport_df.drop(['_dsport_'], axis=1, inplace=True)
    
    return dsport_df

##
# @name get_wrangled_proto
#
# Objective:    Munging the 'proto' column from the passed UNSW-NB15 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      proto_df - the dataframe containing the wrangled
#                               'proto' column data
#                               
def get_ohe_from_proto(raw_df=None):
# df.loc[df['shield'] > 35] = 0
    # proto    
    proto_df = raw_df[['proto']].copy()
    
    #proto_df.loc[:, ('_proto_')] = proto_df.loc[:, ('proto')]
    proto_df.loc[:, '_proto_'] = 'other'
    
    # tcp
    #mask = proto_df['proto'].str.startswith('tcp')
    #proto_df.loc[mask, '_proto_'] = 'tcp'
    
    proto_df.loc[proto_df.proto == 'tcp', '_proto_'] = 'tcp'
    
    # udp
    proto_df.loc[proto_df.proto == 'udp', '_proto_'] = 'udp'
    
    proto_df = pd.get_dummies(proto_df['_proto_'], prefix='proto')
    
    return proto_df

##
# @name get_wrangled_state
#
# Objective:    Munging the 'state' column from the passed UNSW-NB15 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      state_df - the dataframe containing the wrangled
#                               'state' column data
#                               
def get_ohe_from_state(raw_df=None):
# 
    # state    
    state_df = raw_df[['state']].copy()
    
    state_df.loc[:, '_state_'] = 'other'
    
    # FIN
    state_df.loc[state_df.state == 'FIN', '_state_'] = 'fin'
    
    # CON
    state_df.loc[state_df.state == 'CON', '_state_'] = 'con'
    
    # INT
    state_df.loc[state_df.state == 'INT', '_state_'] = 'int'
    
    state_df = pd.get_dummies(state_df['_state_'], prefix='state')
    
    return state_df

##
# @name get_wrangled_column
#
# Objective: having opened the data set source file, filtering the column
#               base on the column_name parameter, then the munging process
#               is performed over the filtered column data 
#
# Parameters: 
#               raw_df - dataframe containing the raw column data from where
#                        the munging data will be performed
#               column_name - the name of the column  
#
# Returns: dataframe 
#   
def get_wrangled_column(raw_df=None, column_name='__no_name__'):
# =============================================================================
#     if 'id.resp_p' == column_name:
#         return get_ohe_from_id_resp_p(raw_df)
#     
#     elif 'service' == column_name:
#         return get_ohe_from_service(raw_df)
#     
#     elif 'history' == column_name:
#         return get_ohe_from_history(raw_df)
#     el
#     
# =============================================================================
    if 'scalars' == column_name:
        return get_wrangled_scalars(raw_df)
    elif 'dsport' == column_name:
         return get_ohe_from_dsport(raw_df)
    elif 'proto' == column_name:
         return get_ohe_from_proto(raw_df)
    elif 'state' == column_name:
         return get_ohe_from_state(raw_df)
    
    print('{} is an unrecognized value for column_name parameter'.format(column_name))
    return None
##
# @name get_wrangled_attack_cat
#
# Objective:    Munging the 'history' column from the passed UNSW-NB15 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      history_df - the dataframe containing the wrangled
#                               'history' column data
#                               
def get_wrangled_attack_cat(y_raw_df=None):    
    # history
    #       a SYN w/o the ACK bit set
    attack_cat_df = y_raw_df.loc[:,('attack_cat')].to_frame()
    attack_cat_df.fillna(value='bening', inplace=True)
    
    # removing both the leading and the trailing whitespaces
    attack_cat_df = attack_cat_df['attack_cat'].map(lambda x: x.strip()).to_frame()
    
    # converting into lowercase
    attack_cat_df = attack_cat_df['attack_cat'].map(lambda x: x.lower()).to_frame()
    
    # bening
    attack_cat_df['bening'] = attack_cat_df['attack_cat'].replace(regex='bening', value=1)
    attack_cat_df['bening'].replace(regex='[^1]', value=0, inplace=True)
    
    # exploit(s)
    attack_cat_df['exploits'] = attack_cat_df['attack_cat'].replace(regex='exploit', value=1)
    attack_cat_df['exploits'].replace(regex='[^1]', value=0, inplace=True)
    
    # generic
    attack_cat_df['generic'] = attack_cat_df['attack_cat'].replace(regex='generic', value=1)
    attack_cat_df['generic'].replace(regex='[^1]', value=0, inplace=True)
    
    # DoS
    attack_cat_df['dos'] = attack_cat_df['attack_cat'].replace(regex='^dos$', value=1)
    attack_cat_df['dos'].replace(regex='[^1]', value=0, inplace=True)
    
    # fuzzer(s)
    attack_cat_df['fuzzers'] = attack_cat_df['attack_cat'].replace(regex='fuzzer', value=1)
    attack_cat_df['fuzzers'].replace(regex='[^1]', value=0, inplace=True)
    
    # analysis
    attack_cat_df['analysis'] = attack_cat_df['attack_cat'].replace(regex='analysis', value=1)
    attack_cat_df['analysis'].replace(regex='[^1]', value=0, inplace=True)
    
    # backdoor
    attack_cat_df['backdoor'] = attack_cat_df['attack_cat'].replace(regex='backdoor', value=1)
    attack_cat_df['backdoor'].replace(regex='[^1]', value=0, inplace=True)
    
    # reconnaissance
    attack_cat_df['reconnaissance'] = attack_cat_df['attack_cat'].replace(regex='reconnaissance', value=1)
    attack_cat_df['reconnaissance'].replace(regex='[^1]', value=0, inplace=True)
    
    # shellcode
    attack_cat_df['shellcode'] = attack_cat_df['attack_cat'].replace(regex='shellcode', value=1)
    attack_cat_df['shellcode'].replace(regex='[^1]', value=0, inplace=True)
    
    # worm(s)
    attack_cat_df['worms'] = attack_cat_df['attack_cat'].replace(regex='worm', value=1)
    attack_cat_df['worms'].replace(regex='[^1]', value=0, inplace=True)
    
    attack_cat_df.drop(['attack_cat'], axis=1, inplace=True)
    
    return attack_cat_df

##
#  __main__
if __name__ == '__main__':
    print("it's a library, please use it by importing")