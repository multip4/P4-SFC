/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_SFC = 0x1212; // Define TYPE for SFC
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TUNNEL = 0x1;
#define MAX_HOPS 8 //  HA
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> tunnelAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header tunnel_t {
    tunnelAddr_t dst_id; // Next SF
}

header sfc_t {
    bit<24> SPI;
    bit<8> SI;
    bit<8> cur_idx; // HA counter
    bit<8> chain_len; // Chain length
}
header sfc_chain_t { //HA
    bit<8> SF; // Next SF
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    dscp; // We use DSCP field to assign SFP
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;

}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t ethernet;
    tunnel_t tunnel;
    sfc_t sfc;
    sfc_chain_t[MAX_HOPS] sfc_chain;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SFC: parse_tunnel;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_tunnel {
        packet.extract(hdr.tunnel);
        transition parse_sfc;

    }
    state parse_sfc {
        packet.extract(hdr.sfc);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action sfc_next_ha() {
          hdr.tunnel.dst_id = (bit<9>)hdr.sfc_chain[hdr.sfc.cur_idx].SF; // read next SF from SFC chian header
          hdr.sfc.cur_idx = hdr.sfc.cur_idx + 1; // HA Increase current index
      }
    action drop() {
        mark_to_drop();
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }




    action sfc_decapsulation() {
           hdr.ethernet.etherType = TYPE_IPV4;
           hdr.ipv4.dscp = 0;
           hdr.tunnel.setInvalid();
           hdr.sfc.setInvalid();
           hdf.sfc_chain.Invalid(); // HA
    }
    table sfc_termination {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            sfc_decapsulation;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    action sfc_encapsulation(bit<24> SPI) {
        hdr.ethernet.etherType = TYPE_SFC;
        hdr.sfc.setValid();
        hdr.sfc.SPI = SPI;
        hdr.sfc.SI = 255;
        hdr.sfc.cur_idx = 0; // HA
        hdr.sfc.chain_len = 0; //  from ruleTODO
        hdr.sfc_chain.setValid(); // HA;
        hdr.tunnel.setValid();
        hdr.tunnel.dst_id = 0;
    }
    table sfc_classifier {
        key = {
            hdr.ipv4.dscp: exact;
        }
        actions = {
            sfc_encapsulation;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action sfc_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table sfc_egress { // calculate (physical) output port from sfc tunneling header
        key = {
            hdr.tunnel.dst_id: exact;
        }
        actions = {
            sfc_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }


    apply {

        if (hdr.ipv4.isValid() && hdr.ipv4.dscp == 0) {   // Process only non-SFC packets
            ipv4_lpm.apply();
        }
        else{ // SFC packets
            if (!hdr.sfc.isValid()){ /// intial stage?
                sfc_classifier.apply(); // Encaps the packet
            }
            if (hdr.sfc.SI == 0){
                drop();
            }
            sfc_next_ha(); //HA; obtain next SF from  sfc chain header
            sfc_egress.apply();
            sfc_termination.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.tunnel);
        packet.emit(hdr.sfc);
        packet.emit(hdr.sfc_chain); // HA
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
