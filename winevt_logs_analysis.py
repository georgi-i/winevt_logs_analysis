
#[\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx]
#EventID 1149 - User authentication succeeded -> 2624 -> 21 -> 22

#[\winevt\Logs\Security.evtx]
#EventID 4624 - User successfully logged on to this system with the specified TargetUserName and TargetDomainName from the specified IpAddress
#EventID 4625 - User failed to log on to this system with the specified TargetUserName and TargetDomainName from the specified IpAddress
#EventID 4634 - A user disconnected from, or logged off, an RDP session
#EventID 4647 - The user initiated a formal logoff
#EventID 4778 - The user reconnected to an existing RDP session
#EventID 4779 - The user disconnected from from an RDP session

#[\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx] 
#EventID 21 - successful RDP logon (as long as Source Network Address is NOT local) 
#EventID 22 - successful RDP logon with GUI Desktop (as long as Source Network Address is NOT local) 
#EventID 23 - The user initiated a formal system logoff
#EventID 24 - user has disconnected from an RDP session (if NOT local IP)
#EventID 25 - user has reconnected to an existing RDP session (if NOT local IP)
#EventID 39 - The user formally disconnected from the RDP session
#EventID 40 - The user disconnected from or reconnected to an RDP session

import Evtx.Evtx as evtx
import re
import pandas as pd
from alive_progress import alive_bar

def write_results(df):

    with open('result.html', 'a') as result:
        
        df['SystemTime'] = pd.to_datetime(df['SystemTime'])
        df = df.sort_values(by="SystemTime").reset_index(drop=True)
        
        df.to_html(result, header=result)
        result.write('<br>')



def append_results(df, event_id, event_id_info, ip, sys_time, log_info):
    
    df = df._append({'EventID': event_id, 
                    'Info': event_id_info, 
                    'IP': ip, 
                    'SystemTime': sys_time, 
                    'Log': log_info}, 
                    ignore_index=True)
    
    return df
         
    

def read_data(df, path, input):

    event_data = ''

    re_system_time = r'SystemTime=\"(.+)\.'

    re_rcm_id = r'>(1149)<\/EventID'
    re_ip_rcm = r'<Param3>(.+)<'
    

    re_lsm_login = r'>(21)<\/EventID'
    re_lsm_login_gui = r'>(22)</EventID'
    re_lsm_disc = r'>(24)<\/EventID'
    re_lsm_rec = r'>(25)<\/EventID'
    re_ip_lsm = r'Address>(\d+\.\d+\.\d+\.\d+)<'

    re_sec_login = r'>(4624)<\/EventID'
    re_sec_reconnect = r'>(4778)<\/EventID'
    re_sec_disconnect = r'>(4779)<\/EventID'
    re_ip_login = r'\"IpAddress\">(\d+\.\d+\.\d+\.\d+)<'
    re_ip_rec = r'\"ClientAddress\">(\d+\.\d+\.\d+\.\d+)<'

    print_rcm = False
    print_lsm = False
    print_security = False


    with evtx.Evtx(path) as log:
        records = log.records()
        with alive_bar(len(list(records))) as bar:
            for record in log.records():
                bar()
                event_data = record.xml()
                match_sys_time = re.search(re_system_time, event_data)

                if input == 'rcm':

                    if not print_rcm: 
                        print('Searching for matching events in RemoteConnectionManager logs...')
                        print_rcm = True


                    match_id_1149 = re.search(re_rcm_id, event_data)
                    if match_id_1149 != None:

                        match_ip_1149 = re.search(re_ip_rcm, event_data)

                        df = append_results(df, 
                                            match_id_1149.group(1), 
                                            'User authentication succeeded', 
                                            match_ip_1149.group(1), 
                                            match_sys_time.group(1), 
                                            'RemoteConnectionManager_Operational')


                elif input == 'lsm':

                    if not print_lsm:
                        print('Searching for matching events in LocalSessionManager logs...')
                        print_lsm = True

                    match_id_21 = re.search(re_lsm_login, event_data)
                    match_id_22 = re.search(re_lsm_login_gui, event_data)
                    match_id_24 = re.search(re_lsm_disc, event_data)
                    match_id_25 = re.search(re_lsm_rec, event_data)
                    match_ip_lsm = re.search(re_ip_lsm, event_data)

                    if match_id_21 != None:

                        if match_ip_lsm != None:
                            df = append_results(df, 
                                                match_id_21.group(1), 
                                                'successful RDP logon', 
                                                match_ip_lsm.group(1), 
                                                match_sys_time.group(1), 
                                                'LocalSessionManager_Operational')
                    elif match_id_22 != None:

                        if match_ip_lsm != None:
                            df = append_results(df, 
                                                match_id_22.group(1), 
                                                'successful RDP logon with GUI Desktop', 
                                                match_ip_lsm.group(1),
                                                match_sys_time.group(1), 
                                                'LocalSessionManager_Operational')
                    elif match_id_24 != None:

                        if match_ip_lsm != None:
                            df = append_results(df, 
                                                match_id_24.group(1), 
                                                'user has disconnected from an RDP session', 
                                                match_ip_lsm.group(1), 
                                                match_sys_time.group(1), 
                                                'LocalSessionManager_Operational')
                    elif match_id_25 != None:

                        if match_ip_lsm != None:
                            df = append_results(df, 
                                                match_id_25.group(1), 
                                                'user has reconnected to an existing RDP session', 
                                                match_ip_lsm.group(1), 
                                                match_sys_time.group(1), 
                                                'LocalSessionManager_Operational')

                elif input == 'security':

                    if not print_security:
                        print('Searching for matching events in Security logs...This may take a while...')
                        print_security = True

                    match_id_4624 = re.search(re_sec_login, event_data)
                    match_id_4778 = re.search(re_sec_reconnect, event_data)
                    match_id_4779 = re.search(re_sec_disconnect, event_data)

                    if match_id_4624 != None:

                        match_ip_4624 = re.search(re_ip_login, event_data)
                        if match_ip_4624 != None:
                            df = append_results(df, match_id_4624.group(1), 
                                                    'User successfully logged on', 
                                                    match_ip_4624.group(1), 
                                                    match_sys_time.group(1), 
                                                    'Security')
                    elif match_id_4778 != None:

                        match_ip_4778 = re.search(re_ip_rec, event_data)
                        if match_ip_4778 != None:
                            df = append_results(df, 
                                                match_id_4778.group(1), 
                                                'The user reconnected', 
                                                match_ip_4778.group(1), 
                                                match_sys_time.group(1), 
                                                'Security')
                    elif match_id_4779 != None:

                        match_ip_4779 = re.search(re_ip_rec, event_data)
                        if match_ip_4779 != None:
                            df = append_results(df, 
                                                match_id_4779.group(1), 
                                                'The user disconnected', 
                                                match_ip_4779.group(1), 
                                                match_sys_time.group(1), 
                                                'Security')
        
    write_results(df)


df = pd.DataFrame(columns=['EventID', 'Info', 'IP', 'SystemTime', 'Log'])

path_prefix = 'winevt/Logs/'
log_prefix = 'Microsoft-Windows-TerminalServices-'
try:
    print('Reading data from RemoteConnectionManager%4Operational.evtx...')
    read_data(df, path_prefix + log_prefix + 'RemoteConnectionManager%4Operational.evtx', 'rcm')
except:
    print('Failed to read RemoteConnectionManager%4Operational.evtx')
try:
    print('Reading data from LocalSessionManager%4Operational.evtx...')
    read_data(df, path_prefix + log_prefix + 'LocalSessionManager%4Operational.evtx', 'lsm')
except:
    print('Failed to read LocalSessionManager%4Operational.evtx')
try:
    print('Reading data from Security.evtx...')
    read_data(df, path_prefix + 'Security.evtx', 'security')
except:
    print('Failed to read Security.evtx')


       
