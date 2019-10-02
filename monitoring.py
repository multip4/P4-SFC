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

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2



def writeIPv4Rules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip_addr,port):
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
    ingress_sw.WriteTableEntry(table_entry)


def writeClassifierRules(p4info_helper,ingress_sw):

    # Classifier
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sfc_classifier",
        match_fields={
            "hdr.ipv4.tos": 1
        },
        action_name="MyIngress.sfc_encapsulation",
        action_params={
            "id": 100,
            "sc": 2,
            "sf1": 1,
            "sf2": 3,
            "sf3": 0,
            "sf4": 0
        })
    ingress_sw.WriteTableEntry(table_entry)

def writeEgressRules(p4info_helper, ingress_sw, sf, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sfc_egress",
        match_fields={
            "hdr.sfc_chain[0].sf": sf
        },
        action_name="MyIngress.sfc_forward",
        action_params={
            "port": port
        })
    ingress_sw.WriteTableEntry(table_entry)


def writeProcessingRules(p4info_helper, ingress_sw):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sf_processing",
        match_fields={
        },
        action_name="MyIngress.sf_action",
        action_params={

        })
    ingress_sw.WriteTableEntry(table_entry)

def readTableRules(p4info_helper, sw):
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def printCounter(p4info_helper, sw, counter_name, index):
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            )

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

        writeIPv4Rules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:00:01:01", dst_ip_addr="10.0.1.1",port=1)
        writeIPv4Rules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:00:20:01", dst_ip_addr="10.0.2.2",port=2)
        writeIPv4Rules(p4info_helper, ingress_sw=s2, dst_eth_addr="00:00:00:00:10:01", dst_ip_addr="10.0.1.1",port=1)
        writeIPv4Rules(p4info_helper, ingress_sw=s2, dst_eth_addr="00:00:00:00:40:01", dst_ip_addr="10.0.2.2",port=2)
        writeIPv4Rules(p4info_helper, ingress_sw=s3, dst_eth_addr="00:00:00:00:10:01", dst_ip_addr="10.0.1.1",port=1)
        writeIPv4Rules(p4info_helper, ingress_sw=s3, dst_eth_addr="00:00:00:00:40:01", dst_ip_addr="10.0.2.2",port=2)
        writeIPv4Rules(p4info_helper, ingress_sw=s4, dst_eth_addr="00:00:00:00:40:01", dst_ip_addr="10.0.1.1",port=2)
        writeIPv4Rules(p4info_helper, ingress_sw=s4, dst_eth_addr="00:00:00:00:02:02", dst_ip_addr="10.0.2.2",port=1)
        writeEgressRules(p4info_helper, ingress_sw=s1, sf=1,port=2)
        writeEgressRules(p4info_helper, ingress_sw=s1, sf=2,port=3)
        writeEgressRules(p4info_helper, ingress_sw=s2, sf=3,port=2)
        writeEgressRules(p4info_helper, ingress_sw=s3, sf=3,port=2)
        writeClassifierRules(p4info_helper, ingress_sw=s1)
        writeProcessingRules(p4info_helper, ingress_sw=s2)
        writeProcessingRules(p4info_helper, ingress_sw=s3)
        writeProcessingRules(p4info_helper, ingress_sw=s4)
        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)
        readTableRules(p4info_helper, s3)
        readTableRules(p4info_helper, s4)

        while True:
            sleep(2)
            print '\n----- Reading tunnel counters -----'
            printCounter(p4info_helper, s1, "MyIngress.ingressSFCCounter", 100)
            printCounter(p4info_helper, s4, "MyIngress.egressSFCCounter", 100)

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
