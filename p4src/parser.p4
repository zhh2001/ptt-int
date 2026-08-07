// PTT-INT: Parser
//
// Parse graph:
//
//   start
//     |
//     v
//   Ethernet  -----------(etherType != 0x0800)----> accept
//     | (IPv4)
//     v
//   IPv4  ----------------(protocol != 17)--------> accept
//     | (UDP)
//     v
//   UDP  -----------------(dstPort != INT_PORT)----> accept
//     | (dstPort == INT_PORT)
//     v
//   parse_ptt: extract shim, validate magic+version
//     |
//     +------(magic/version mismatch)-------------> accept
//     |
//     v
//   parse_hops_begin: clamp count, set metadata
//     |
//     v
//   extract_hop  <---- loop: idx < safe_count
//     |                    |
//     +---(done)----------> accept
//
// PTT Shim (8 bytes): magic(16) version(4) flags(4) hop_count(8)
//                     original_udp_dport(16) reserved(16)
// Hop Record (12 bytes): switch_id(12) egress_port(9) state(2) reason(3)
//                        qdepth(19) q_pred_far(19) timestamp_low(32)
// Max hops: MAX_HOPS (8 by default)

parser PttParser(packet_in packet,
                 out headers_t hdr,
                 inout local_metadata_t meta,
                 inout standard_metadata_t stdmeta)
{
    // Parser-level loop counter (persists across state transitions)
    bit<8> hop_idx;

    // --- Ethernet ---
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;         // IPv4
            default: accept;
        }
    }

    // --- IPv4 ---
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;              // UDP
            default: accept;
        }
    }

    // --- UDP ---
    // Branch on destination port: INT_PORT packets carry PTT telemetry
    // from an upstream switch; all other ports are regular data packets.
    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            INT_PORT: parse_ptt;
            default: accept;
        }
    }

    // --- PTT Shim ---
    // Extract the 8-byte shim and validate magic + version.
    // Packets with an unrecognised magic/version are accepted without
    // parsing hop records (safe fallback for non-PTT UDP traffic on
    // the INT port).
    state parse_ptt {
        meta.is_int_packet = true;
        packet.extract(hdr.ptt_shim);
        transition select(hdr.ptt_shim.magic, hdr.ptt_shim.version) {
            (PTT_MAGIC, PTT_VERSION): parse_hops_begin;
            default: accept;
        }
    }

    // --- Hop stack preamble ---
    // Compute the safe hop count (capped at MAX_HOPS), record metadata,
    // and branch: if the clamped count is zero, short-circuit to accept.
    state parse_hops_begin {
        bit<8> wire_count = hdr.ptt_shim.hop_count;

        // Clamp count to MAX_HOPS for stack bounds safety
        bit<8> safe_count = wire_count;
        if (safe_count > MAX_HOPS) {
            safe_count = MAX_HOPS;
        }

        meta.existing_hop_count = safe_count;

        // has_overflow is asserted when the wire count exceeds MAX_HOPS
        // OR the shim overflow flag was already set by an upstream switch
        meta.has_overflow =
            (wire_count > MAX_HOPS) ||
            ((hdr.ptt_shim.flags & 0x1) != 0);

        hop_idx = 0;
        transition select(safe_count) {
            0: accept;
            default: extract_hop;
        }
    }

    // --- Hop stack loop ---
    // Extract one 12-byte hop record per iteration.  The loop continues
    // while hop_idx < existing_hop_count.  Because existing_hop_count is
    // already clamped to MAX_HOPS, this state is entered at most MAX_HOPS
    // times and the header stack index is always in bounds.
    state extract_hop {
        packet.extract(hdr.hops[hop_idx]);
        hop_idx = hop_idx + 1;
        transition select(hop_idx < meta.existing_hop_count) {
            true: extract_hop;
            default: accept;
        }
    }
}
