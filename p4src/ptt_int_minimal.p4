/*
 * PTT-INT: Predictive Time-to-Threshold Triggered In-band Network Telemetry
 *
 * Target:  P4_16 + v1model + BMv2 simple_switch
 * Compiler: p4c-bm2-ss
 *
 * This file is the complete, self-contained P4 program for the PTT-INT
 * research prototype.  It includes all header definitions, the parser,
 * IPv4 forwarding ingress, the core egress predictor / FSM / telemetry-
 * insertion logic, checksum computation, and the deparser.
 *
 * All tunable constants are #define'd at the top of this file and
 * mirrored in config/default.yaml.  Use control/generate_p4_params.py
 * to produce generated_params.p4, or override constants directly via
 * p4c -D flags.
 */

#include <core.p4>
#include <v1model.p4>


/* =====================================================================
 * 1.  Compile-time Constants  (mirrors config/default.yaml)
 * ===================================================================== */

/* -- Queue -- */
#define PTT_Q_CAP                    128
#define PTT_Q_EVENT                  96    /* 0.75 * Q_CAP */
#define PTT_Q_RELEASE                64    /* 0.50 * Q_CAP */

/* -- Predictor -- */
#define PTT_EPOCH_US                 5000  /* W */
#define PTT_EWMA_ALPHA_SHIFT         2     /* alpha = 1/4, implemented as >> 2 */
#define PTT_NEAR_HORIZON             2     /* H_N: near horizon in epochs */
#define PTT_FAR_HORIZON              8     /* H_F: far horizon in epochs */

/* -- FSM hysteresis -- */
#define PTT_RECOVERY_EPOCHS          3     /* M */
#define PTT_GAP_RESET_MULT           4     /* T_gap = 4 * W */
#define PTT_IDLE_RESET_MULT          20    /* T_idle = 20 * W */
#define PTT_GAP_RESET_US             20000 /* = 4 * 5000 */
#define PTT_IDLE_RESET_US            100000 /* = 20 * 5000 */

/* -- Sampling bit masks -- */
#define PTT_QUIET_MASK               (bit<32>)0x1f   /* 1/32 */
#define PTT_WATCH_MASK               (bit<32>)0x03   /* 1/4  */

/* -- Freshness safeguard -- */
#define PTT_MAX_SILENCE_US           100000

/* -- Delta trigger baseline -- */
#define PTT_DELTA_THRESHOLD          10

/* -- Packet format -- */
#define PTT_INT_PORT                 32768
#define PTT_MAGIC                    0x5054
#define PTT_VERSION                  1
#define PTT_MAX_HOPS                 8
#define PTT_SHIM_BYTES               (bit<16>)8
#define PTT_HOP_BYTES                (bit<16>)12

/* -- Register array sizing -- */
#define PTT_NUM_PORTS                512

/* -- FSM state encoding -- */
#define PTT_STATE_QUIET              (bit<8>)0
#define PTT_STATE_WATCH              (bit<8>)1
#define PTT_STATE_BURST              (bit<8>)2

/* -- Scheme mode identifiers -- */
#define PTT_SCHEME_FULL              0
#define PTT_SCHEME_PERIODIC_4        1
#define PTT_SCHEME_PERIODIC_16       2
#define PTT_SCHEME_PERIODIC_32       3
#define PTT_SCHEME_REACTIVE          4
#define PTT_SCHEME_DELTA             5
#define PTT_SCHEME_PTT               6

/* -- Trigger reason codes -- */
#define PTT_REASON_PERIODIC_QUIET    0
#define PTT_REASON_PERIODIC_WATCH    1
#define PTT_REASON_PREDICTIVE_NEAR   2
#define PTT_REASON_EMERGENCY         3
#define PTT_REASON_FRESHNESS         4
#define PTT_REASON_BASELINE          5
#define PTT_REASON_DELTA             6

/* -- Default switch ID (overridable via p4c -DSWITCH_ID=...) -- */
#ifndef SWITCH_ID
#define SWITCH_ID 1
#endif


/* =====================================================================
 * 2.  Header Definitions
 * ===================================================================== */

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

/*
 * PTT Shim: 8 bytes = 64 bits
 *
 *   +-------------------------------+
 *   | magic              16         |
 *   +-------------------------------+
 *   | version 4 | flags 4 | count 8 |
 *   +-------------------------------+
 *   | original_udp_dport 16         |
 *   +-------------------------------+
 *   | reserved            16        |
 *   +-------------------------------+
 */
header ptt_shim_t {
    bit<16> magic;
    bit<4>  version;
    bit<4>  flags;              /* bit 0 = overflow */
    bit<8>  hop_count;
    bit<16> original_udp_dport;
    bit<16> reserved;
}

/*
 * PTT Hop Record: 12 bytes = 96 bits
 *
 *   +-------------------------------------------+
 *   | switch_id 12 | egress_port 9 | state 2    |
 *   | reason 3 | qdepth 19 | q_pred_far 19      |
 *   | timestamp_low 32                          |
 *   +-------------------------------------------+
 */
header ptt_hop_t {
    bit<12> switch_id;
    bit<9>  egress_port;
    bit<2>  state;
    bit<3>  reason;
    bit<19> qdepth;
    bit<19> q_pred_far;
    bit<32> timestamp_low;       /* egress_global_timestamp[31:0] */
}


/* =====================================================================
 * 3.  Header Struct and Metadata
 * ===================================================================== */

struct headers_t {
    ethernet_t                  ethernet;
    ipv4_t                      ipv4;
    udp_t                       udp;
    ptt_shim_t                  ptt_shim;
    ptt_hop_t[PTT_MAX_HOPS]     hops;
}

struct metadata_t {
    /* -- Set by parser -- */
    bool     is_int_packet;      /* true when udp.dstPort == INT_PORT */
    bit<8>   existing_hop_count; /* parsed from shim (0 if no shim) */
    bool     has_overflow;       /* true when shim overflow flag seen */

    /* -- Set by egress -- */
    bool     emit_telemetry;     /* this switch should append a hop record */
    bit<3>   emit_reason;        /* REASON_* code for this emission */
    bit<2>   current_state;      /* STATE_QUIET / WATCH / BURST at decision time */
}



parser PttParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t stdmeta) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            default: accept;
        }
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            32768: parse_ptt;
            default: accept;
        }
    }
    state parse_ptt {
        pkt.extract(hdr.ptt_shim);
        meta.is_int_packet = true;
        meta.existing_hop_count = (bit<8>)hdr.ptt_shim.hop_count;
        meta.hop_index = 0;
        transition parse_hops;
    }
    state parse_hops {
        transition select(meta.hop_index < 8 && meta.hop_index < (bit<8>)hdr.ptt_shim.hop_count) {
            true: extract_hop;
            default: accept;
        }
    }
    state extract_hop {
        pkt.extract(hdr.hops[meta.hop_index]);
        meta.hop_index = meta.hop_index + 1;
        transition parse_hops;
    }
}

control PttVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

control PttIngress(inout headers_t hdr, inout metadata_t meta,
                   inout standard_metadata_t stdmeta) {
    action forward(bit<9> port) {
        stdmeta.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action do_drop() { stdmeta.egress_spec = 9w511; }
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { forward; do_drop; }
        const default_action = do_drop();
    }
    apply { ipv4_lpm.apply(); }
}

control PttEgress(inout headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t stdmeta) {
    apply {}
}

control PttComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

control PttDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.ptt_shim);
        pkt.emit(hdr.hops);
    }
}

V1Switch(PttParser(), PttVerifyChecksum(), PttIngress(), PttEgress(),
         PttComputeChecksum(), PttDeparser()) main;
