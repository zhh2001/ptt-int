#ifndef PTT_HEADERS
#define PTT_HEADERS
#include <core.p4>
#include <v1model.p4>
#include <generated_params.p4>

#define PTT_MAGIC 0x5054
#define PTT_VERSION 1
#define STATE_QUIET 0
#define STATE_WATCH 1
#define STATE_BURST 2
#define REASON_PERIODIC_QUIET 0
#define REASON_PERIODIC_WATCH 1
#define REASON_PREDICTIVE_NEAR 2
#define REASON_EMERGENCY_THRESHOLD 3
#define REASON_FRESHNESS 4

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}
header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}
header ipv4_options_t { varbit<320> data; }
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}
// 64-bit shim.
header ptt_shim_t {
    bit<16> magic;
    bit<4> version;
    bit<4> flags;
    bit<8> hop_count;
    bit<16> original_udp_dport;
    bit<16> reserved;
}
// 96-bit record, most recently inserted hop first.
header ptt_hop_t {
    bit<12> switch_id;
    bit<9> egress_port;
    bit<2> state;
    bit<3> reason;
    bit<19> qdepth;
    bit<19> q_pred_far;
    bit<32> timestamp_low;
}
struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv4_options_t ipv4_options;
    udp_t udp;
    ptt_shim_t ptt_shim;
    ptt_hop_t[MAX_HOPS] hops;
}
struct local_metadata_t { bit<32> ip_header_bytes; }
error { InvalidIPv4, InvalidUDP, InvalidPTT }
#endif
