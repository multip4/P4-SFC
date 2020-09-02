import sys
import os
sde_install = os.environ['SDE_INSTALL']
sys.path.append('%s/lib/python2.7/site-packages/tofino'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages/p4testutils'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages'%(sde_install))
import grpc
import time
import datetime
import bfrt_grpc.client as gc
import port_mgr_pd_rpc as mr
from time import sleep

import socket, struct
import binascii
# Convert a hex to IP
def hex2ip(hex_ip):
    addr_long = int(hex_ip,16)
    hex(addr_long)
    hex_ip = socket.inet_ntoa(struct.pack(">L", addr_long))
    return hex_ip

# Convert IP to bin
def ip2bin(ip):
    ip1 = ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])
    return ip1

# Convert IP to hex
def ip2hex(ip):
    ip1 = ''.join([hex(int(x)+256)[3:] for x in ip.split('.')])
    return ip1

def table_add(target, table, keys, action_name, action_data=[]):
    keys = [table.make_key([gc.KeyTuple(*f)   for f in keys])]
    datas = [table.make_data([gc.DataTuple(*p) for p in action_data],
                                  action_name)]
    table.entry_add(target, keys, datas)

def table_mod(target, table, keys, action_name, action_data=[]):
    keys = [table.make_key([gc.KeyTuple(*f)   for f in keys])]
    datas = [table.make_data([gc.DataTuple(*p) for p in action_data],
                                  action_name)]
    table.entry_mod(target, keys, datas)

def table_del(target, table, keys):
    table.entry_del(target, keys)

def table_print(target, table, keys):
    keys = [table.make_key([gc.KeyTuple(*f)   for f in keys])]
    for data,key in table.entry_get(target,keys):
        key_fields = key.to_dict()
        data_fields = data.to_dict()
        return data_fields[b'$PORT_UP']

def table_clear(target, table):
    keys = []
    for data,key in table.entry_get(target):
        if key is not None:
            keys.append(key)
    table.entry_del(target, keys)

def fill_table_with_junk(target, table, table_size):
    table_clear(target, table)
    for i in range(table_size):
        table_add(target, table,
                  [("hdr.ethernet.dst_addr", i)],
                  "hit")

try:

    grpc_addr = "localhost:50052"
    client_id = 0
    device_id = 0
    pipe_id = 0xFFFF
    is_master = True
    client = gc.ClientInterface(grpc_addr, client_id, device_id,is_master)
    target = gc.Target(device_id, pipe_id)
    #lient.bind_pipeline_config("hasfc")
    client.bind_pipeline_config("hasfc")
    table = client.bfrt_info_get().table_get("pipe.SwitchIngress.ipv4_exact")
    #table2 = client.bfrt_info_get().table_get("pipe.SwitchIngress.ingress_sfc_counter")
    table3 = client.bfrt_info_get().table_get("$PORT")
    #sleep(10)
    table_clear(target, table)


finally:
    client._tear_down_stream()
