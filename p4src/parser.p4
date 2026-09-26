// Reject malformed encapsulations before they can affect predictor state.
parser PttParser(packet_in packet, out headers_t hdr,
                 inout local_metadata_t meta,
                 inout standard_metadata_t stdmeta) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.version == 4 && hdr.ipv4.ihl >= 5, error.InvalidIPv4);
        meta.ip_header_bytes = (bit<32>)hdr.ipv4.ihl << 2;
        verify((bit<32>)hdr.ipv4.totalLen >= meta.ip_header_bytes &&
               stdmeta.packet_length >= 14 + (bit<32>)hdr.ipv4.totalLen, error.InvalidIPv4);
        transition select(hdr.ipv4.ihl) {
            5: classify_ip;
            default: parse_options;
        }
    }
    state parse_options {
        packet.extract(hdr.ipv4_options, (meta.ip_header_bytes - 20) << 3);
        transition classify_ip;
    }
    state classify_ip {
        // Fragments are forwarded without telemetry. Options are preserved.
        transition select(hdr.ipv4.protocol, hdr.ipv4.flags[0:0], hdr.ipv4.fragOffset) {
            (17, 0, 0): parse_udp;
            default: accept;
        }
    }
    state parse_udp {
        verify((bit<32>)hdr.ipv4.totalLen >= meta.ip_header_bytes + 8, error.InvalidUDP);
        packet.extract(hdr.udp);
        verify(hdr.udp.length >= 8 &&
               (bit<32>)hdr.udp.length == (bit<32>)hdr.ipv4.totalLen - meta.ip_header_bytes,
               error.InvalidUDP);
        transition select(hdr.udp.dstPort) {
            INT_PORT: parse_ptt;
            default: accept;
        }
    }
    state parse_ptt {
        verify(hdr.udp.length >= 16, error.InvalidPTT);
        packet.extract(hdr.ptt_shim);
        verify(hdr.ptt_shim.magic == PTT_MAGIC &&
               hdr.ptt_shim.version == PTT_VERSION &&
               hdr.ptt_shim.hop_count <= MAX_HOPS, error.InvalidPTT);
        verify((bit<32>)hdr.udp.length >= 16 + (bit<32>)hdr.ptt_shim.hop_count * 12,
               error.InvalidPTT);
        transition select(hdr.ptt_shim.hop_count) {
            0: accept;
            default: parse_hop_0;
        }
    }
    state parse_hop_0 {
        packet.extract(hdr.hops[0]);
#if MAX_HOPS > 1
        transition select(hdr.ptt_shim.hop_count) {
            1: accept;
            default: parse_hop_1;
        }
#else
        transition accept;
#endif
    }
#if MAX_HOPS > 1
    state parse_hop_1 {
        packet.extract(hdr.hops[1]);
#if MAX_HOPS > 2
        transition select(hdr.ptt_shim.hop_count) {
            2: accept;
            default: parse_hop_2;
        }
#else
        transition accept;
#endif
    }
#endif
#if MAX_HOPS > 2
    state parse_hop_2 {
        packet.extract(hdr.hops[2]);
#if MAX_HOPS > 3
        transition select(hdr.ptt_shim.hop_count) {
            3: accept;
            default: parse_hop_3;
        }
#else
        transition accept;
#endif
    }
#endif
#if MAX_HOPS > 3
    state parse_hop_3 {
        packet.extract(hdr.hops[3]);
#if MAX_HOPS > 4
        transition select(hdr.ptt_shim.hop_count) {
            4: accept;
            default: parse_hop_4;
        }
#else
        transition accept;
#endif
    }
#endif
#if MAX_HOPS > 4
    state parse_hop_4 {
        packet.extract(hdr.hops[4]);
#if MAX_HOPS > 5
        transition select(hdr.ptt_shim.hop_count) {
            5: accept;
            default: parse_hop_5;
        }
#else
        transition accept;
#endif
    }
#endif
#if MAX_HOPS > 5
    state parse_hop_5 {
        packet.extract(hdr.hops[5]);
#if MAX_HOPS > 6
        transition select(hdr.ptt_shim.hop_count) {
            6: accept;
            default: parse_hop_6;
        }
#else
        transition accept;
#endif
    }
#endif
#if MAX_HOPS > 6
    state parse_hop_6 {
        packet.extract(hdr.hops[6]);
#if MAX_HOPS > 7
        transition select(hdr.ptt_shim.hop_count) {
            7: accept;
            default: parse_hop_7;
        }
#else
        transition accept;
#endif
    }
#endif
#if MAX_HOPS > 7
    state parse_hop_7 {
        packet.extract(hdr.hops[7]);
        transition accept;
    }
#endif
}
