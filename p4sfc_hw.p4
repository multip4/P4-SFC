#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
#define MAX_LEN 11
#define MAX_HOPS 4
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<16> ether_type_t;
const ether_type_t TYPE_IPV4 = 0x800;
const ether_type_t TYPE_SFC = 0x1212;
const bit<32> MAX_SFC_ID = 1 << 16;
typedef bit<8> trans_protocol_t;
const trans_protocol_t TYPE_TCP = 6;
const trans_protocol_t TYPE_UDP = 17;

header port_metadata_t {
    bit<16> cnt;
};

header ethernet_h {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}

header sfc_h {
    bit<9> id;
    bit<7> pads;
    bit<8> sc;
}

header sfc_chain_h {
    bit<9> sf;
    bit<7> tail;

}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}

header tcp_h {
    bit<16> srcport;
    bit<16> dstport;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

struct header_t {
    ethernet_h ethernet;
    sfc_h sfc;
    sfc_chain_h[MAX_HOPS] sfc_chain;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}


struct custom_metadata_t {
}

struct metadata_t {
    port_metadata_t cnt;
}


struct empty_header_t {
    ethernet_h ethernet;
    sfc_h sfc;
    sfc_chain_h[MAX_HOPS] sfc_chain;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}

struct empty_metadata_t {
    custom_metadata_t custom_metadata;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    //TofinoIngressParser() tofino_parser;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SFC: parse_sfc;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_sfc {
        pkt.extract(hdr.sfc);
        transition parse_sfc_chain;
    }
    state parse_sfc_chain {
        pkt.extract(hdr.sfc_chain.next);
        transition select(hdr.sfc_chain.last.tail) {
            1: parse_ipv4;
            default: parse_sfc_chain;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP : parse_tcp;
            TYPE_UDP : parse_udp;
            default : accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    action set_egress(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl=1;
    }

    table set_egress_table {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            set_egress();
        }

    }

    action ipv4_forward(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table ipv4_exact {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }

        size = 1024;
        default_action = drop();
    }

    action sf_action() {
        hdr.sfc.sc = hdr.sfc.sc - 1;
        hdr.sfc.pads = 0;
        hdr.sfc_chain.pop_front(1);

    }
    table sf_processing {
        key = {
            hdr.sfc_chain[0].sf: exact;
        }
        actions = {
            sf_action;
            NoAction;
        }

        size = 1024;
        default_action = NoAction();
    }

    action sfc_decapsulation() {
           hdr.ethernet.etherType= TYPE_IPV4;
           hdr.ipv4.dscp = 0x01;
           hdr.sfc.setInvalid();
           hdr.sfc_chain[0].setInvalid();
           hdr.sfc_chain[1].setInvalid();
           hdr.sfc_chain[2].setInvalid();
           hdr.sfc_chain[3].setInvalid();
    }

    action sfc_encapsulation(bit<9> id, bit<8> sc, bit<9> sf1, bit<9> sf2,bit<9> sf3, bit<9> sf4) {
        hdr.ethernet.etherType = TYPE_SFC;
        hdr.sfc.setValid();
        hdr.sfc.id= id;
        hdr.sfc.sc = sc;
        hdr.sfc_chain[0].setValid();
        hdr.sfc_chain[1].setValid();
        hdr.sfc_chain[2].setValid();
        hdr.sfc_chain[3].setValid();
        hdr.sfc_chain[0].sf = sf1;
        hdr.sfc_chain[1].sf = sf2;
        hdr.sfc_chain[2].sf = sf3;
        hdr.sfc_chain[3].sf = sf4;
        hdr.sfc_chain[0].tail = 0;
        hdr.sfc_chain[1].tail = 0;
        hdr.sfc_chain[2].tail = 0;
        hdr.sfc_chain[3].tail = 1;
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

    action sfc_forward(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }
    table sfc_egress {
        key = {
            hdr.sfc_chain[0].sf: exact;
        }
        actions = {
            sfc_forward;
            drop;
        }

        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.dscp == 0)
            ipv4_exact.apply();
        else if (hdr.ipv4.dscp > 0){
            if (!hdr.sfc.isValid())
                sfc_classifier.apply();
            sf_processing.apply();
            if (hdr.sfc.sc == 0){
                sfc_decapsulation();
                ipv4_exact.apply();
            }
            else
                sfc_egress.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
parser EmptyEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control EmptyEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {
        pkt.emit(hdr);
    }
}

control EmptyEgress(
        inout empty_header_t hdr,
        inout empty_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    apply {
    }
}
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
