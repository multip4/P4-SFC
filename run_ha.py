#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep
# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../tutorials/utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

cnt = [0,0,0,0]
before = [-1,-1,-1,-1]
chain1 = [2,4,0,0]
chain1_len = len(list(filter(lambda x: (x > 0), chain1)))
chain2 = [3,4,0,0]
chain2_len = len(list(filter(lambda x: (x > 0), chain2)))
def writeIPv4Rules(p4info_helper, sw, dst_eth_addr, dst_ip_addr,port,update):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": port
        })
    if update == 1:
        sw.UpdateTableEntry(table_entry)
    else:
        sw.WriteTableEntry(table_entry)


def writeClassifierRules(p4info_helper,sw,tos,id,sc,sf1,sf2,sf3,sf4,update):

    # Classifier
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sfc_classifier",
        match_fields={
            "hdr.ipv4.tos": tos
        },
        action_name="MyIngress.sfc_encapsulation",
        action_params={
            "id": id,
            "sc": sc,
            "sf1": sf1,
            "sf2": sf2,
            "sf3": sf3,
            "sf4": sf4
        })
    if update == 1:
        sw.UpdateTableEntry(table_entry)
    else:
        sw.WriteTableEntry(table_entry)

def writeEgressRules(p4info_helper, sw, sf, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sfc_egress",
        match_fields={
            "hdr.sfc_chain[0].sf": sf
        },
        action_name="MyIngress.sfc_forward",
        action_params={
            "port": port
        })
    sw.WriteTableEntry(table_entry)


def writeProcessingRules(p4info_helper, sw):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sf_processing",
        match_fields={
        },
        action_name="MyIngress.sf_action",
        action_params={

        })
    sw.WriteTableEntry(table_entry)

def readTableRules(p4info_helper, sw):
    i=0
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            if table_name == "MyIngress.sfc_classifier":
                action = entry.action.action
                action_name = p4info_helper.get_actions_name(action.action_id)
                for p in action.params:
                    if str(p4info_helper.get_action_param_name(action_name, p.param_id))[0:2]=="sc":
                        print "%d" % int(repr(p.value)[-2:-1])
                    if str(p4info_helper.get_action_param_name(action_name, p.param_id))[0:2]=="sf":
                        print "%d" % int(repr(p.value)[-2:-1])


def printAlive(p4info_helper, sw, counter_name, index):
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "Swtich ID: %s Service Chain ID: %d: %d packets (%d bytes)" % (
                sw.name, index, counter.data.packet_count, counter.data.byte_count
            )
            before[sw.device_id] = counter.data.packet_count




def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s4',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s4-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s4.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s4.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)

        writeIPv4Rules(p4info_helper, sw=s1, dst_eth_addr="00:00:00:00:01:01", dst_ip_addr="10.0.1.1",port=1,update=0)
        writeIPv4Rules(p4info_helper, sw=s1, dst_eth_addr="00:00:00:00:20:01", dst_ip_addr="10.0.2.2",port=2,update=0)
        writeIPv4Rules(p4info_helper, sw=s2, dst_eth_addr="00:00:00:00:10:01", dst_ip_addr="10.0.1.1",port=1,update=0)
        writeIPv4Rules(p4info_helper, sw=s2, dst_eth_addr="00:00:00:00:40:01", dst_ip_addr="10.0.2.2",port=2,update=0)
        writeIPv4Rules(p4info_helper, sw=s3, dst_eth_addr="00:00:00:00:10:01", dst_ip_addr="10.0.1.1",port=1,update=0)
        writeIPv4Rules(p4info_helper, sw=s3, dst_eth_addr="00:00:00:00:40:01", dst_ip_addr="10.0.2.2",port=2,update=0)
        writeIPv4Rules(p4info_helper, sw=s4, dst_eth_addr="00:00:00:00:40:01", dst_ip_addr="10.0.1.1",port=2,update=0)
        writeIPv4Rules(p4info_helper, sw=s4, dst_eth_addr="00:00:00:00:02:02", dst_ip_addr="10.0.2.2",port=1,update=0)
        writeEgressRules(p4info_helper, sw=s1, sf=2,port=2)
        writeEgressRules(p4info_helper, sw=s1, sf=3,port=3)
        writeEgressRules(p4info_helper, sw=s2, sf=4,port=2)
        writeEgressRules(p4info_helper, sw=s3, sf=4,port=2)
        writeClassifierRules(p4info_helper,sw=s1,tos=1,id=1,sc=chain1_len,sf1=chain1[0],sf2=chain1[1],sf3=chain1[2],sf4=chain1[3],update=0)
        writeProcessingRules(p4info_helper, sw=s2)
        writeProcessingRules(p4info_helper, sw=s3)
        writeProcessingRules(p4info_helper, sw=s4)
        current_id=1
        used = 0
        while True:
            sleep(1)
            #readTableRules(p4info_helper, s1)
            printAlive(p4info_helper, s1, "MyIngress.ingressSFCCounter", current_id)
            #for sw in eval("chain" + str(current_id)):
            #    if sw !=0:
            #        printAlive(p4info_helper, eval("s" + str(sw)), "MyIngress.ingressSFCCounter", current_id)
            printAlive(p4info_helper, s4, "MyIngress.ingressSFCCounter", current_id)
            bb = list(filter(lambda num: num >= 0, before))
            if abs(bb[0] - bb[1]) < 3:
                print abs(bb[0] - bb[1])
            #if all(x==bb[0] for x in bb):
                print "True"
            else:
                print "False"
                if used == 0:
                    writeClassifierRules(p4info_helper,sw=s1,tos=1,id=2,sc=chain2_len,sf1=chain2[0],sf2=chain2[1],sf3=chain2[2],sf4=chain2[3],update=1)
                    writeIPv4Rules(p4info_helper, sw=s4, dst_eth_addr="00:00:00:00:40:01", dst_ip_addr="10.0.1.1",port=3,update=1)
                    current_id=2
                    used=1
                    before[0]=-1
                    before[1]=-1
                    before[2]=-1
                    before[3]=-1

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/ha-sfc.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/ha-sfc.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
