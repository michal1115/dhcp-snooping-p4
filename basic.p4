/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x0806;

const bit<8> PROTOCOL_UDP = 17;
const bit<16> DHCP_SERVER = 67;
const bit<16> DHCP_CLIENT = 68;
const bit<32> DHCP_MAGIC_COOKIE = 0x63825363;

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16> hdrType;
    bit<16> pType;
    bit<8> hdrSize;
    bit<8> pSize;
    bit<16> opCode;
    macAddr_t srcMAC;
    ip4Addr_t srcIP;
    macAddr_t  dstMAC;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header bootp_t {
    bit<8> opCode;
    bit<8> hType;
    bit<8> hLen;
    bit<8> hops;
    bit<32> xid;
    bit<16> secs;
    bit<16> flags;
    ip4Addr_t CIAddr;
    ip4Addr_t YIAddr;
    ip4Addr_t SIAddr;
    ip4Addr_t GIAddr;
    macAddr_t CHAddr;
    bit<80> CHAddrPadding;
    bit<512> sName;
    bit<1024> file;
    bit<32> magicCookie;
}

header dhcp_option_code_t {
    bit<8> option;
    bit<8> length;
}

header dhcp_subnet_mask_t {
    bit<8> option;
    bit<8> length;
    bit<32> address;
}

header dhcp_router_t {
    bit<8> option;
    bit<8> length;
    bit<32> address;
}

header dhcp_message_type_t {
    bit<8> option;
    bit<8> length;
    bit<8> type;
}

header dhcp_server_identifier_t {
    bit<8> option;
    bit<8> length;
    bit<32> address;
}

header dhcp_requested_ip_address_t {
    bit<8> option;
    bit<8> length;
    bit<32> address;
}

header dhcp_end_t {
    bit<8> option;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t                  ethernet;
    arp_t                       arp;
    ipv4_t                      ipv4;
    udp_t                       udp;
    bootp_t                     bootp;
    dhcp_subnet_mask_t          dhcp_subnet_mask;
    dhcp_router_t               dhcp_router;
    dhcp_message_type_t         dhcp_message_type;
    dhcp_server_identifier_t    dhcp_server_identifier;
    dhcp_requested_ip_address_t dhcp_requested_ip_address;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select (hdr.ipv4.protocol) {
            default: accept; 
        }
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

    action broadcast() {
        standard_metadata.mcast_grp=1;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ether_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }
    
    table ether_lpm {
        key = {
            hdr.ethernet.dstAddr: lpm;
        }
        actions = {
            broadcast;
            ether_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = broadcast();
    }

    apply {
        ether_lpm.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    apply {
        if(standard_metadata.egress_port == standard_metadata.ingress_port){
             drop();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
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
