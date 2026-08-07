/*
 * PTT-INT: Predictive Time-to-Threshold Triggered In-band Network Telemetry
 *
 * headers.p4 — Protocol header definitions and compile-time constants.
 *
 * Constants guarded with #ifndef are overridden by p4src/generated_params.p4,
 * which is machine-generated from config/default.yaml.
 */

#ifndef _PTT_INT_HEADERS_P4_
#define _PTT_INT_HEADERS_P4_

#include <core.p4>
#include <v1model.p4>

// ============================================================================
// 1. Compile-time bit-width constants
// ============================================================================

#define SWITCH_ID_WIDTH      12
#define EGRESS_PORT_WIDTH     9
#define STATE_WIDTH           2
#define REASON_WIDTH          3
#define QDEPTH_WIDTH         19
#define QPRED_WIDTH          19
#define TIMESTAMP_LOW_WIDTH  32
#define HOP_RECORD_BITS      96    // 12 + 9 + 2 + 3 + 19 + 19 + 32 = 96

// ============================================================================
// 2. Protocol constants (overridable by generated_params.p4)
// ============================================================================

#ifndef MAX_HOPS
#define MAX_HOPS 8
#endif

#ifndef INT_PORT
#define INT_PORT    32768      // UDP dst port signalling an INT packet
#endif

#ifndef DATA_PORT
#define DATA_PORT   65534      // Default UDP dst port for ordinary traffic
#endif

#ifndef PTT_MAGIC
#define PTT_MAGIC   0x5054     // Experiment-identification magic number
#endif

#ifndef PTT_VERSION
#define PTT_VERSION 1
#endif

// Shim flag bits
#define SHIM_FLAG_OVERFLOW  0x1   // Bit 0 set when hop_count reached MAX_HOPS

// ============================================================================
// 3. FSM state encoding
// ============================================================================

#define STATE_QUIET  0
#define STATE_WATCH  1
#define STATE_BURST  2

// ============================================================================
// 4. Trigger reason encoding
// ============================================================================

#define REASON_PERIODIC_QUIET       0
#define REASON_PERIODIC_WATCH       1
#define REASON_PREDICTIVE_NEAR      2
#define REASON_EMERGENCY_THRESHOLD  3
#define REASON_FRESHNESS            4
#define REASON_BASELINE_TRIGGER     5

// ============================================================================
// 5. Scheme mode identifiers
// ============================================================================

#define SCHEME_FULL          0
#define SCHEME_PERIODIC_4    1
#define SCHEME_PERIODIC_16   2
#define SCHEME_PERIODIC_32   3
#define SCHEME_REACTIVE      4
#define SCHEME_DELTA         5
#define SCHEME_PTT           6

// ============================================================================
// 6. Predictor and FSM parameters
// ============================================================================
// All guarded so generated_params.p4 can override them.

#ifndef Q_CAP
#define Q_CAP      128
#endif

#ifndef Q_EVENT
#define Q_EVENT     96          // 0.75 * Q_CAP
#endif

#ifndef Q_RELEASE
#define Q_RELEASE   64          // 0.50 * Q_CAP
#endif

#ifndef EPOCH_US
#define EPOCH_US    5000        // W: measurement epoch in microseconds
#endif

#ifndef EWMA_ALPHA_SHIFT
#define EWMA_ALPHA_SHIFT  2     // alpha = 1/4 -> >> 2
#endif

#ifndef NEAR_HORIZON
#define NEAR_HORIZON  2         // H_N
#endif

#ifndef FAR_HORIZON
#define FAR_HORIZON   8         // H_F
#endif

#ifndef RECOVERY_EPOCHS
#define RECOVERY_EPOCHS  3      // M: hysteresis recovery count
#endif

#ifndef GAP_RESET_US
#define GAP_RESET_US    20000   // 4 * W
#endif

#ifndef IDLE_RESET_US
#define IDLE_RESET_US  100000   // 20 * W
#endif

#ifndef MAX_SILENCE_US
#define MAX_SILENCE_US 100000   // T_max: freshness safeguard interval
#endif

// Sampling bit masks
#ifndef QUIET_MASK
#define QUIET_MASK   0x1f       // 1/32: (counter & 0x1f) == 0
#endif

#ifndef WATCH_MASK
#define WATCH_MASK   0x03       // 1/4:  (counter & 0x03) == 0
#endif

// Delta-trigger baseline
#ifndef DELTA_THRESHOLD
#define DELTA_THRESHOLD  10     // Delta_Q: report when |q - q_last| >= 10
#endif

// Per-switch identifier (overridden per topology)
#ifndef SWITCH_ID
#define SWITCH_ID  1
#endif

// ============================================================================
// 7. Standard Protocol Headers
// ============================================================================

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
    bit<16> length;
    bit<16> checksum;
}

// ============================================================================
// 8. PTT-INT Custom Headers
// ============================================================================

/*
 * PTT Shim — 8 bytes (64 bits)
 *
 * Inserted between UDP and payload when the first switch instruments
 * a packet.  Downstream switches detect INT packets by checking
 * udp.dstPort == INT_PORT.
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
    bit<16> magic;                // 0x5054
    bit<4>  version;              // PTT_VERSION
    bit<4>  flags;                // overflow flag (bit 0) + reserved
    bit<8>  hop_count;            // number of hop records present
    bit<16> original_udp_dport;   // saved UDP dst port before first insertion
    bit<16> reserved;             // set to 0
}

/*
 * PTT Hop Record — 12 bytes (96 bits)
 *
 * Appended by each switch whose local emit decision is true.
 * The header stack uses push_front(1) so the collector sees hops
 * nearest-switch-first; offline analysis reverses to path order.
 *
 *   +-------------------------------------------+
 *   | switch_id 12 | egress_port 9 | state 2 |  |  + reason 3 |
 *   +-------------------------------------------+
 *   | qdepth 19 | q_pred_far 19 | ts_low 32     |
 *   +-------------------------------------------+
 */
header ptt_hop_t {
    bit<SWITCH_ID_WIDTH>      switch_id;
    bit<EGRESS_PORT_WIDTH>    egress_port;
    bit<STATE_WIDTH>          state;         // STATE_QUIET / WATCH / BURST
    bit<REASON_WIDTH>         reason;        // REASON_* code
    bit<QDEPTH_WIDTH>         qdepth;        // deq_qdepth at emission
    bit<QPRED_WIDTH>          q_pred_far;    // far-horizon prediction
    bit<TIMESTAMP_LOW_WIDTH>  timestamp_low; // egress_global_timestamp[31:0]
}

// ============================================================================
// 9. Header Stack
// ============================================================================
// P4c requires the array size to be an integer literal or a #define'd name
// that expands directly.  Redeclare the name to satisfy some older p4c builds.

#define MAX_HOP_STACK MAX_HOPS

// ============================================================================
// 10. Combined Header Struct
// ============================================================================
// Passed to the parser (parse) and deparser (emit).

struct headers_t {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    udp_t         udp;
    ptt_shim_t    ptt_shim;
    ptt_hop_t[MAX_HOP_STACK] hops;
}

// ============================================================================
// 11. User-defined Local Metadata
// ============================================================================
// Carries per-packet state between the parser, ingress, egress, and deparser.
// All fields are written during parsing or egress processing and read by the
// deparser when deciding what to emit.

struct local_metadata_t {
    // --- set by parser ---
    bool     is_int_packet;          // true if udp.dstPort == INT_PORT
    bit<8>   existing_hop_count;     // parsed from shim (0 if no shim)
    bool     has_overflow;           // true when parsed shim flags have overflow

    // --- set by egress predictor / telemetry decision ---
    bool     emit_telemetry;         // this switch should append a hop record
    bit<3>   emit_reason;            // REASON_* code for this emission
    bit<2>   current_state;          // STATE_QUIET / WATCH / BURST at decision time

    // --- hop-record field values (filled by egress) ---
    bit<QDEPTH_WIDTH>         qdepth_val;
    bit<QPRED_WIDTH>          q_pred_far_val;
    bit<TIMESTAMP_LOW_WIDTH>  timestamp_low_val;

    // --- first-insertion bookkeeping ---
    bit<16>  original_dport;         // saved UDP dst port before first shim insert
}

#endif  // _PTT_INT_HEADERS_P4_
