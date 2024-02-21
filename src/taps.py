import datetime

# Paramètres
MU1 = 99 #borne supérieur du likelihood ratio pour considérer une source IP comme un scanner
MU0 = 0.01 #borne inférieur du likelihood ratio pour considérer une source IP comme étant bégnine 
P_Y_0_H_0 = 0.8 #probabilité de Y = 0 sachant H0
P_Y_1_H_0 = 0.2 #probabilité de Y = 1 sachant H0
P_Y_0_H_1 = 0.2 #probabilité de Y = 0 sachant H1
P_Y_1_H_1 = 0.8 #probabilité de Y = 1 sachant H1
N = 10 #number of seconds to update likelihood ratio
K = 3 #borne inférieure du ratio

# T = [[SrcAddr, [list of DstAddr], total of DstAddr, [list of Dport], total of Dport]]
def update_T(flow, T):
    src_addr_in_T = False
    for i, record in enumerate(T):
        src_addr = record[0]
        list_dst_addr = record[1] 
        list_dst_port = record[3]
        if flow["SrcAddr"] == src_addr:
            src_addr_in_T = True
            update_record = record
            if flow["DstAddr"] not in list_dst_addr:
                update_record[1].append(flow["DstAddr"])
                update_record[2] = update_record[2] + 1
            if flow["Dport"] not in list_dst_port:
                update_record[3].append(flow["Dport"])
                update_record[4] = update_record[4] + 1
            T[i] = update_record
    
    if not src_addr_in_T:
        T.append([flow["SrcAddr"], [flow["DstAddr"]], 1, [flow["Dport"]], 1])
    
    return T

def update_scan(S, scan):
    S_values_to_del = []
    for i, value in enumerate(S):
        srcIP = value[0]
        likelihood_ratio = value[1]
        if likelihood_ratio > MU1:
            if srcIP not in scan:
                scan.append(srcIP)
            S_values_to_del.append(value)
        elif likelihood_ratio < MU0:
            S_values_to_del.append(value)
    
    for value_to_del in S_values_to_del:
        S.remove(value_to_del)
    return S, scan

# S = [[SrcAddr,Likelihood ratio]]
def update_S(T, S, scan):
    # Update ST
    for record in T:
        is_in_S = False
        srcIP = record[0]
        destIP_to_port_ratio = record[2]/record[4]
        destport_to_ip_ratio = record[4]/record[2]
        for i, value in enumerate(S):
            if value[0] == srcIP:
                is_in_S = True
                new_value = value  
                if destIP_to_port_ratio > K or destport_to_ip_ratio > K:
                    new_value[1] = value[1]*(P_Y_1_H_1/P_Y_1_H_0)
                else:
                    new_value[1] = value[1]*(P_Y_0_H_1/P_Y_0_H_0)
                S[i] = new_value
                break
        if not is_in_S:
            new_value = [srcIP, 1]
            if destIP_to_port_ratio > K or destport_to_ip_ratio > K:
                new_value[1] = P_Y_1_H_1/P_Y_1_H_0
            else:
                new_value[1] = P_Y_0_H_1/P_Y_0_H_0
            S.append(new_value)
    for i, value in enumerate(S):
        is_in_T = False
        srcIP_in_S = value[0]
        for record in T:
            if srcIP_in_S == record[0]:
                is_in_T = True
                break
        if not is_in_T:
            new_value = value
            new_value[1] = value[1]*(P_Y_0_H_1/P_Y_0_H_0)
            S[i] = new_value
    
    S, scan = update_scan(S, scan)
            
    return S, scan

def TAPS(trace):
    trace = trace.sort_values('EndTime', ascending = True).reset_index(drop=True) #trie le DataFrame par ordre décroissant de EndTime et le réindex
    T = [] #Temp cache
    S = [] #list of sources undertest
    scan = [] # list of scanner
    start_time_trace = trace.iloc[0]["EndTime"] # first end time of the trace
    end_time_trace = trace.iloc[trace.shape[0] - 1]["EndTime"] # last end time of the trace
    t = datetime.datetime.utcfromtimestamp(start_time_trace.timestamp()+N) 
    trace_subset = trace[trace["EndTime"] < t]
    flow = trace.iloc[0]
    while flow["EndTime"] != end_time_trace:
        for i in range(len(trace_subset)):
            flow = trace_subset.iloc[i]
            T = update_T(flow, T)
        #print(f'T = {T}')
        if T == [] and S == []:
            old_t = trace.iloc[last_ind]["EndTime"]
            #print(f'old_t = {old_t}')
            t = datetime.datetime.fromtimestamp(old_t.timestamp() + N)
            #print(f't = {t}')
            trace_subset = trace[list((trace["EndTime"] < t) & (old_t <= trace["EndTime"]))]
        else :
            S, scan = update_S(T, S, scan)
            #print(f'S = {S}')
            #print(f'scan = {scan}')
            old_t = t
            #print(f'old_t = {old_t}')
            t = datetime.datetime.fromtimestamp(old_t.timestamp()+N)
            #print(f't = {t}')
            if trace_subset.shape[0] != 0:
                last_ind = trace_subset[trace_subset["EndTime"] == trace_subset["EndTime"].max()].index[0] + 1
            trace_subset = trace[list((trace["EndTime"] < t) & (old_t <= trace["EndTime"]))]
            T = []
    
    return scan