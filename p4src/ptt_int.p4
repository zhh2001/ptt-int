/*
 * PTT-INT: Predictive Time-to-Threshold Triggered In-band Network Telemetry
 *
 * Target:  P4_16 + v1model + BMv2 simple_switch
 * Compiler: p4c-bm2-ss
 *
 * This file is the complete, self-contained P4 program for the PTT-INT research prototype.  It includes all header definitions, the parser, IPv4 forwarding ingress, the core egress predictor / FSM / telemetry-insertion logic, checksum computation, and the deparser.
 *
 * All tunable constants are #define'd at the top of this file and mirrored in config/default.yaml.  Use control/generate_p4_params.py to produce generated_params.p4, or override constants directly via p4c -D flags.
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
#define PTT_SCHEME_BYPASS            7    /* diagnostic: forward only, no telemetry */

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


/* =====================================================================
 * 4.  Oracle Log Struct  (BMv2 simple_switch requires all bit<32> fields)
 * ===================================================================== */

struct oracle_log_t {
    bit<32> switch_id;
    bit<32> port;
    bit<32> ts;
    bit<32> q;
    bit<32> trend;
    bit<32> q_near;
    bit<32> q_far;
    bit<32> state;
    bit<32> target;
}


/* =====================================================================
 * 5.  Parser
 *
 * Parse graph:
 *   Ethernet -> IPv4 -> UDP -> [INT_PORT] -> PTT Shim -> Hop stack loop
 * ===================================================================== */

parser PttParser(
    packet_in  pkt,
    out        headers_t hdr,
    inout      metadata_t meta,
    inout      standard_metadata_t stdmeta)
{
    /* Loop index for hop-stack extraction */

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
            17: parse_udp;             /* UDP */
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            PTT_INT_PORT: parse_ptt_shim;
            default: accept;
        }
    }

    state parse_ptt_shim {
        meta.is_int_packet = true;
        pkt.extract(hdr.ptt_shim);
        /* Accept only valid magic+version; silently ignore mismatches */
        transition select(hdr.ptt_shim.magic, hdr.ptt_shim.version) {
            (PTT_MAGIC, PTT_VERSION): parse_hops_begin;
            default: accept;
        }
    }

    state parse_hops_begin {
        bit<8> wire_count = hdr.ptt_shim.hop_count;

        /* Clamp to MAX_HOPS for safety against malformed packets */
        bit<8> safe_count = wire_count;
        if (wire_count > PTT_MAX_HOPS) {
            safe_count = PTT_MAX_HOPS;
        }
        meta.existing_hop_count = safe_count;
        meta.has_overflow = (wire_count > PTT_MAX_HOPS)
                          || ((hdr.ptt_shim.flags & 0x1) != 0);

        /* Unrolled hop extraction: BMv2 simple_switch does not support pkt.extract(hdr.hops[variable]), so we use constant indices and chain 8 states (MAX_HOPS).  Each state extracts at a fixed index and uses safe_count to decide whether to continue. */
        transition select(safe_count) {
            0: accept;
            default: extract_hop_0;
        }
    }

    state extract_hop_0 {
        pkt.extract(hdr.hops[0]);
        transition select(meta.existing_hop_count) {
            1: accept;
            default: extract_hop_1;
        }
    }

    state extract_hop_1 {
        pkt.extract(hdr.hops[1]);
        transition select(meta.existing_hop_count) {
            2: accept;
            default: extract_hop_2;
        }
    }

    state extract_hop_2 {
        pkt.extract(hdr.hops[2]);
        transition select(meta.existing_hop_count) {
            3: accept;
            default: extract_hop_3;
        }
    }

    state extract_hop_3 {
        pkt.extract(hdr.hops[3]);
        transition select(meta.existing_hop_count) {
            4: accept;
            default: extract_hop_4;
        }
    }

    state extract_hop_4 {
        pkt.extract(hdr.hops[4]);
        transition select(meta.existing_hop_count) {
            5: accept;
            default: extract_hop_5;
        }
    }

    state extract_hop_5 {
        pkt.extract(hdr.hops[5]);
        transition select(meta.existing_hop_count) {
            6: accept;
            default: extract_hop_6;
        }
    }

    state extract_hop_6 {
        pkt.extract(hdr.hops[6]);
        transition select(meta.existing_hop_count) {
            7: accept;
            default: extract_hop_7;
        }
    }

    state extract_hop_7 {
        pkt.extract(hdr.hops[7]);
        transition accept;
    }
}


/* =====================================================================
 * 6.  Checksum Verification
 *     IPv4: verify; UDP: no-op (checksum may be zero after instrumentation)
 * ===================================================================== */

control PttVerifyChecksum(
    inout headers_t    hdr,
    inout metadata_t   meta)
{
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/* =====================================================================
 * 7.  Ingress Processing
 *     Simple IPv4 LPM forwarding.  All baselines share the same forwarding pipeline.
 * ===================================================================== */

control PttIngress(
    inout headers_t            hdr,
    inout metadata_t           meta,
    inout standard_metadata_t  stdmeta)
{
    action forward(bit<9> port) {
        stdmeta.egress_spec = port;
    }

    action do_drop() {
        mark_to_drop(stdmeta);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            do_drop;
        }
        size = 256;
        default_action = do_drop();
    }

    apply {
        /* Pass through non-IP traffic transparently so ARP / LLDP work. */
        if (!hdr.ipv4.isValid()) {
            return;
        }

        /* Decrement TTL; drop if expired. */
        if (hdr.ipv4.ttl <= 1) {
            do_drop();
            return;
        }
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        ipv4_lpm.apply();
    }
}


/* =====================================================================
 * 8.  Egress Processing: PTT-INT Core
 *
 * The egress pipeline runs after the packet has been enqueued and dequeued.  It has access to deq_qdepth, egress_global_timestamp, and egress_port (all read-only metadata).
 *
 * On each packet for which ipv4+udp are valid:
 *   1. Read per-port predictor state registers.
 *   2. If the measurement epoch W has elapsed, update the predictor:
 *      a. Compute positive queue delta.
 *      b. Apply Q8 EWMA.
 *      c. Compute near- and far-horizon predicted queue.
 *      d. Determine target state (QUIET/WATCH/BURST).
 *      e. Apply FSM transition with hysteresis.
 *   3. Log oracle trace (once per epoch per port).
 *   4. Decide whether to emit telemetry (scheme-dependent).
 *   5. Apply freshness safeguard.
 *   6. Insert / append telemetry headers when emitting.
 *   7. Write all updated registers back.
 * ===================================================================== */

control PttEgress(
    inout headers_t            hdr,
    inout metadata_t           meta,
    inout standard_metadata_t  stdmeta)
{
    /* --- 8.1  Global configuration registers --- */
    register<bit<12>>(1) switch_id_reg;
    register<bit<8>>(1)  scheme_mode_reg;       /* 0=FULL .. 6=PTT */

    /* --- 8.2  Per-port state registers (512 entries) --- */
    register<bit<32>>(PTT_NUM_PORTS) prev_q_reg;
    register<bit<32>>(PTT_NUM_PORTS) trend_q8_reg;
    register<bit<48>>(PTT_NUM_PORTS) last_epoch_reg;
    register<bit<8>>(PTT_NUM_PORTS)  state_reg;
    register<bit<8>>(PTT_NUM_PORTS)  recovery_cnt_reg;
    register<bit<32>>(PTT_NUM_PORTS) sample_ctr_reg;
    register<bit<48>>(PTT_NUM_PORTS) last_report_reg;
    register<bit<8>>(PTT_NUM_PORTS)  init_flag_reg;
    register<bit<32>>(PTT_NUM_PORTS) delta_last_q_reg;   /* DELTA baseline */

    /* --- 8.2b  Per-port telemetry sampling counters (for Gate B validation) --- */
    register<bit<32>>(PTT_NUM_PORTS) eligible_quiet_reg;    /* epochs in QUIET state */
    register<bit<32>>(PTT_NUM_PORTS) eligible_watch_reg;    /* epochs in WATCH state */
    register<bit<32>>(PTT_NUM_PORTS) eligible_burst_reg;    /* epochs in BURST state */
    register<bit<32>>(PTT_NUM_PORTS) sampled_quiet_reg;     /* normal samples in QUIET */
    register<bit<32>>(PTT_NUM_PORTS) sampled_watch_reg;     /* normal samples in WATCH */
    register<bit<32>>(PTT_NUM_PORTS) sampled_burst_reg;     /* normal samples in BURST */
    register<bit<32>>(PTT_NUM_PORTS) freshness_forced_reg;  /* freshness-forced samples */

    apply {
        /* Only operate on IPv4/UDP packets. */
        if (!hdr.ipv4.isValid() || !hdr.udp.isValid()) {
            return;
        }

        /* --- 8.3  Per-packet inputs from standard_metadata --- */
        bit<9>  eport = stdmeta.egress_port;
        bit<19> q     = stdmeta.deq_qdepth;
        bit<48> now   = stdmeta.egress_global_timestamp;
        bit<32> q32   = (bit<32>)q;

        /* --- 8.4  Read global configuration --- */
        bit<12> switch_id;
        bit<8>  scheme_mode;
        switch_id_reg.read(switch_id, 0);
        scheme_mode_reg.read(scheme_mode, 0);

        /* --- 8.5  Read all per-port state into locals --- */
        bit<32> prev_q;
        bit<32> trend_q8;
        bit<48> last_epoch;
        bit<8>  fsm_state;
        bit<8>  recovery_cnt;
        bit<32> sample_ctr;
        bit<48> last_report;
        bit<8>  init_flag;
        bit<32> delta_last_q;

        prev_q_reg.read(prev_q, (bit<32>)eport);
        trend_q8_reg.read(trend_q8, (bit<32>)eport);
        last_epoch_reg.read(last_epoch, (bit<32>)eport);
        state_reg.read(fsm_state, (bit<32>)eport);
        recovery_cnt_reg.read(recovery_cnt, (bit<32>)eport);
        sample_ctr_reg.read(sample_ctr, (bit<32>)eport);
        last_report_reg.read(last_report, (bit<32>)eport);
        init_flag_reg.read(init_flag, (bit<32>)eport);
        delta_last_q_reg.read(delta_last_q, (bit<32>)eport);

        /* --- 8.5b  Read Gate B validation counters --- */
        bit<32> eligible_quiet;
        bit<32> eligible_watch;
        bit<32> eligible_burst;
        bit<32> sampled_quiet;
        bit<32> sampled_watch;
        bit<32> sampled_burst;
        bit<32> freshness_forced;

        eligible_quiet_reg.read(eligible_quiet, (bit<32>)eport);
        eligible_watch_reg.read(eligible_watch, (bit<32>)eport);
        eligible_burst_reg.read(eligible_burst, (bit<32>)eport);
        sampled_quiet_reg.read(sampled_quiet, (bit<32>)eport);
        sampled_watch_reg.read(sampled_watch, (bit<32>)eport);
        sampled_burst_reg.read(sampled_burst, (bit<32>)eport);
        freshness_forced_reg.read(freshness_forced, (bit<32>)eport);

        /* --- 8.5c  BYPASS mode: forward without telemetry --- */
        if (scheme_mode == PTT_SCHEME_BYPASS) {
            return;
        }

        /* --- 8.6  Oracle / FSM tracking temporaries --- */
        bit<8>  target_state;
        bit<32> q_pred_near;
        bit<32> q_pred_far;
        bool    oracle_updated = false;

        /* --- 8.7  Initialization: first packet ever on this port --- */
        if (init_flag == 0) {
            prev_q      = q32;
            trend_q8    = 0;
            fsm_state   = PTT_STATE_QUIET;
            last_epoch  = now;
            last_report = now;
            recovery_cnt = 0;
            delta_last_q = q32;
            init_flag    = 1;
            sample_ctr   = 0;

            target_state = PTT_STATE_QUIET;
            q_pred_near  = q32;
            q_pred_far   = q32;
        } else {

            /* --- 8.8  Predictor epoch update --- */
            bit<48> elapsed = now - last_epoch;

            if (elapsed >= PTT_EPOCH_US) {
                oracle_updated = true;

                /* --- 8.8.1  Idle reset --- */
                if (elapsed >= PTT_IDLE_RESET_US && q32 < PTT_Q_RELEASE) {
                    trend_q8     = 0;
                    fsm_state    = PTT_STATE_QUIET;
                    recovery_cnt = 0;
                    prev_q       = q32;
                    target_state = PTT_STATE_QUIET;
                    q_pred_near  = q32;
                    q_pred_far   = q32;
                }
                /* --- 8.8.2  Long-gap reset --- */
                else if (elapsed > PTT_GAP_RESET_US) {
                    trend_q8     = 0;
                    prev_q       = q32;
                    recovery_cnt = 0;
                    target_state = fsm_state;
                    q_pred_near  = q32;
                    q_pred_far   = q32;
                }
                /* --- 8.8.3  Normal epoch --- */
                else {
                    /* Positive queue growth only */
                    bit<32> delta_q = 0;
                    if (q32 > prev_q) {
                        delta_q = q32 - prev_q;
                    }

                    /* Q8 one-sided EWMA
                     *   G_new = G_old - (G_old >> 2) + (delta_q << 6) */
                    bit<32> trend_new;
                    trend_new = trend_q8
                              - (trend_q8 >> PTT_EWMA_ALPHA_SHIFT)
                              + (delta_q << 6);

                    /* Near-horizon: q + H_N*g = q + G/128 */
                    q_pred_near = q32 + (trend_new >> 7);

                    /* Far-horizon:  q + H_F*g = q + G/32 */
                    q_pred_far  = q32 + (trend_new >> 5);

                    /* Target state */
                    if (q32 >= PTT_Q_EVENT) {
                        target_state = PTT_STATE_BURST;
                    } else if (q_pred_near >= PTT_Q_EVENT) {
                        target_state = PTT_STATE_BURST;
                    } else if (q_pred_far >= PTT_Q_EVENT) {
                        target_state = PTT_STATE_WATCH;
                    } else {
                        target_state = PTT_STATE_QUIET;
                    }

                    /* FSM transition */
                    if (target_state > fsm_state) {
                        /* Upward: immediate */
                        fsm_state    = target_state;
                        recovery_cnt = 0;
                    } else if (target_state == fsm_state) {
                        recovery_cnt = 0;
                    } else {
                        /* Downward: hysteresis */
                        recovery_cnt = recovery_cnt + 1;
                        if (recovery_cnt >= PTT_RECOVERY_EPOCHS) {
                            if (fsm_state > 0) {
                                fsm_state = fsm_state - 1;
                            }
                            recovery_cnt = 0;
                        }
                    }

                    trend_q8 = trend_new;
                    prev_q   = q32;
                }

                last_epoch = now;

                /* Increment eligible-epoch counter for current state */
                if (fsm_state == PTT_STATE_QUIET) {
                    eligible_quiet = eligible_quiet + 1;
                } else if (fsm_state == PTT_STATE_WATCH) {
                    eligible_watch = eligible_watch + 1;
                } else {
                    eligible_burst = eligible_burst + 1;
                }
            } else {
                /* Not an epoch: use current trend to predict.  State and trend are unchanged from their register values. */
                target_state = fsm_state;
                q_pred_near  = q32 + (trend_q8 >> 7);
                q_pred_far   = q32 + (trend_q8 >> 5);
            }
        }

        /* --- 8.9  Oracle logging ---
         * One log line per predictor epoch update, per port.
         * All schemes log the same oracle data for fair comparison. */
        if (oracle_updated) {
            /* BMv2 log_msg takes a single struct argument; we use bit<32> fields throughout to avoid "not convertible to string" errors. */
            oracle_log_t ol;
            ol.switch_id = (bit<32>)switch_id;
            ol.port      = (bit<32>)eport;
            ol.ts        = (bit<32>)now;
            ol.q         = (bit<32>)q;
            ol.trend     = trend_q8;
            ol.q_near    = q_pred_near;
            ol.q_far     = q_pred_far;
            ol.state     = (bit<32>)fsm_state;
            ol.target    = (bit<32>)target_state;
            log_msg("PTT_ORACLE sw={} port={} ts={} q={} trend={} qn={} qf={} state={} target={}",
                    ol);
        }

        /* --- 8.10  Increment sample counter --- */
        sample_ctr = sample_ctr + 1;

        /* --- 8.11  Telemetry emit decision --- */
        bool   emit   = false;
        bit<3> reason = PTT_REASON_PERIODIC_QUIET;

        if (scheme_mode == PTT_SCHEME_FULL) {
            /* B0: FULL-INT -- instrument every packet */
            emit   = true;
            reason = PTT_REASON_BASELINE;
        }
        else if (scheme_mode == PTT_SCHEME_PERIODIC_4) {
            emit   = ((sample_ctr & PTT_WATCH_MASK) == 0);
            reason = PTT_REASON_PERIODIC_WATCH;
        }
        else if (scheme_mode == PTT_SCHEME_PERIODIC_16) {
            emit   = ((sample_ctr & 0x0f) == 0);
            reason = PTT_REASON_PERIODIC_WATCH;
        }
        else if (scheme_mode == PTT_SCHEME_PERIODIC_32) {
            emit   = ((sample_ctr & PTT_QUIET_MASK) == 0);
            reason = PTT_REASON_PERIODIC_QUIET;
        }
        else if (scheme_mode == PTT_SCHEME_REACTIVE) {
            /* B2: REACTIVE-INT -- burst on threshold, background 1/32 */
            if (q32 >= PTT_Q_EVENT) {
                emit   = true;
                reason = PTT_REASON_EMERGENCY;
            } else {
                emit   = ((sample_ctr & PTT_QUIET_MASK) == 0);
                reason = PTT_REASON_PERIODIC_QUIET;
            }
        }
        else if (scheme_mode == PTT_SCHEME_DELTA) {
            /* B3: DELTA-TRIGGER
             * Emit when |q - last_q_reported| >= DELTA_THRESHOLD.
             * On trigger, update last_q_reported so the next trigger is measured from the new baseline.  Between triggers, fall back to background 1/32 sampling. */
            bit<32> diff;
            if (q32 > delta_last_q) {
                diff = q32 - delta_last_q;
            } else {
                diff = delta_last_q - q32;
            }
            if (diff >= PTT_DELTA_THRESHOLD) {
                emit          = true;
                reason        = PTT_REASON_DELTA;
                delta_last_q  = q32;
            } else {
                emit   = ((sample_ctr & PTT_QUIET_MASK) == 0);
                reason = PTT_REASON_PERIODIC_QUIET;
            }
        }
        else {
            /* B4: PTT-INT -- state-dependent sampling */
            if (fsm_state == PTT_STATE_BURST) {
                emit   = true;
                reason = (q32 >= PTT_Q_EVENT) ? (bit<3>)PTT_REASON_EMERGENCY
                                              : (bit<3>)PTT_REASON_PREDICTIVE_NEAR;
            } else if (fsm_state == PTT_STATE_WATCH) {
                emit   = ((sample_ctr & PTT_WATCH_MASK) == 0);
                reason = PTT_REASON_PERIODIC_WATCH;
            } else {
                emit   = ((sample_ctr & PTT_QUIET_MASK) == 0);
                reason = PTT_REASON_PERIODIC_QUIET;
            }
        }

        /* --- 8.12  Freshness safeguard --- */
        if (emit == false && (now - last_report) >= PTT_MAX_SILENCE_US) {
            emit   = true;
            reason = PTT_REASON_FRESHNESS;
        }

        /* --- 8.12b  Increment Gate B validation counters --- */
        if (emit == true) {
            if (reason == PTT_REASON_FRESHNESS) {
                freshness_forced = freshness_forced + 1;
            } else {
                /* Normal sampling: count by current state */
                if (fsm_state == PTT_STATE_QUIET) {
                    sampled_quiet = sampled_quiet + 1;
                } else if (fsm_state == PTT_STATE_WATCH) {
                    sampled_watch = sampled_watch + 1;
                } else {
                    sampled_burst = sampled_burst + 1;
                }
            }
        }

        /* --- 8.13  Store decision in metadata for downstream analysis --- */
        meta.emit_telemetry = emit;
        meta.emit_reason    = reason;
        meta.current_state  = (bit<2>)fsm_state;

        /* --- 8.14  Telemetry header insertion --- */
        if (emit == true) {
            /* Clamp q_pred_far to 19 bits for the hop record */
            bit<19> far_clamped;
            if (q_pred_far > (bit<32>)0x7FFFF) {
                far_clamped = (bit<19>)0x7FFFF;
            } else {
                far_clamped = q_pred_far[18:0];
            }

            bit<16> extra_len = 0;

            if (!hdr.ptt_shim.isValid()) {
                /* --- First-switch instrumentation ---
                 * Create the PTT shim, save the original UDP dport, change UDP dport to INT_PORT, and zero the UDP checksum (IPv4 permits zero UDP checksum). Then insert the first hop record. */
                hdr.ptt_shim.setValid();
                hdr.ptt_shim.magic              = PTT_MAGIC;
                hdr.ptt_shim.version            = PTT_VERSION;
                hdr.ptt_shim.flags              = 0;
                hdr.ptt_shim.hop_count          = 0;
                hdr.ptt_shim.original_udp_dport = hdr.udp.dstPort;
                hdr.ptt_shim.reserved           = 0;

                hdr.udp.dstPort  = PTT_INT_PORT;
                hdr.udp.checksum = 0;

                extra_len = extra_len + PTT_SHIM_BYTES;
            }

            if (hdr.ptt_shim.hop_count < PTT_MAX_HOPS) {
                /* Append local hop record.
                 * push_front(1) shifts existing entries right and creates a new valid header at index 0.  Thus the per-packet hop order is "nearest switch first", which the collector reverses to path order. */
                hdr.hops.push_front(1);
                hdr.hops[0].switch_id     = switch_id;
                hdr.hops[0].egress_port   = eport;
                hdr.hops[0].state         = (bit<2>)fsm_state;
                hdr.hops[0].reason        = reason;
                hdr.hops[0].qdepth        = q;
                hdr.hops[0].q_pred_far    = far_clamped;
                hdr.hops[0].timestamp_low = now[31:0];
                hdr.ptt_shim.hop_count    = hdr.ptt_shim.hop_count + 1;

                extra_len = extra_len + PTT_HOP_BYTES;
            } else {
                /* Hop stack full -- set overflow flag */
                hdr.ptt_shim.flags = hdr.ptt_shim.flags | 0x1;
            }

            /* Update lengths to reflect added telemetry bytes.
             * The ComputeChecksum control will recalc the IPv4 header checksum afterward. */
            hdr.ipv4.totalLen = hdr.ipv4.totalLen + extra_len;
            hdr.udp.len       = hdr.udp.len       + extra_len;

            /* Record that we reported at this time */
            last_report = now;
        }

        /* --- 8.15  Write all per-port registers back --- */
        prev_q_reg.write((bit<32>)eport, prev_q);
        trend_q8_reg.write((bit<32>)eport, trend_q8);
        last_epoch_reg.write((bit<32>)eport, last_epoch);
        state_reg.write((bit<32>)eport, fsm_state);
        recovery_cnt_reg.write((bit<32>)eport, recovery_cnt);
        sample_ctr_reg.write((bit<32>)eport, sample_ctr);
        last_report_reg.write((bit<32>)eport, last_report);
        init_flag_reg.write((bit<32>)eport, init_flag);
        delta_last_q_reg.write((bit<32>)eport, delta_last_q);

        /* --- 8.15b  Write Gate B validation counters back --- */
        eligible_quiet_reg.write((bit<32>)eport, eligible_quiet);
        eligible_watch_reg.write((bit<32>)eport, eligible_watch);
        eligible_burst_reg.write((bit<32>)eport, eligible_burst);
        sampled_quiet_reg.write((bit<32>)eport, sampled_quiet);
        sampled_watch_reg.write((bit<32>)eport, sampled_watch);
        sampled_burst_reg.write((bit<32>)eport, sampled_burst);
        freshness_forced_reg.write((bit<32>)eport, freshness_forced);
    }
}


/* =====================================================================
 * 9.  Checksum Computation
 *     IPv4 header checksum is recomputed after egress may have increased totalLen (telemetry bytes) and ingress decremented TTL.
 *     UDP checksum is intentionally left as 0 (set during first instrumentation).  IPv4 does not require a valid UDP checksum.
 * ===================================================================== */

control PttComputeChecksum(
    inout headers_t  hdr,
    inout metadata_t meta)
{
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/* =====================================================================
 * 10.  Deparser
 *      Emit in wire order.  The hop header stack emits all valid elements starting at index 0 (nearest switch first).
 * ===================================================================== */

control PttDeparser(
    packet_out pkt,
    in         headers_t hdr)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.ptt_shim);
        pkt.emit(hdr.hops);
    }
}


/* =====================================================================
 * 11.  V1Switch Instantiation
 * ===================================================================== */

V1Switch(
    PttParser(),
    PttVerifyChecksum(),
    PttIngress(),
    PttEgress(),
    PttComputeChecksum(),
    PttDeparser()
) main;
