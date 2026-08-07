// PTT-INT: Ingress Pipeline
// L3 forwarding and per-packet bookkeeping shared across all scheme modes.
//
// This control runs on every packet in the ingress pipeline. Its sole job is
// routing: map the destination IPv4 address to an egress port, decrement TTL,
// and drop packets that cannot be forwarded. All telemetry logic lives in the
// egress pipeline (egress.p4).

control PttIngress(inout headers_t hdr,
                   inout local_metadata_t meta,
                   inout standard_metadata_t stdmeta)
{
    // =========================================================================
    //  Actions
    // =========================================================================

    // Forward the packet out of the given physical port.
    action forward(bit<9> port) {
        stdmeta.egress_spec = port;
    }

    // Explicitly drop the packet (no route, expired TTL, or non-IP).
    action do_drop() {
        mark_to_drop(stdmeta);
    }

    // =========================================================================
    //  IPv4 Forwarding Table
    // =========================================================================
    // Longest-prefix match on destination address.  Populated at runtime by
    // the Mininet controller (or simple_switch_CLI) per topology.
    //
    // Size 256 is sufficient for any topology in this study (single-bottleneck,
    // incast, leaf-spine up to 6 switches).

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            do_drop;
            NoAction;
        }
        size = 256;
        default_action = do_drop();   // Drop unknown destinations
    }

    // =========================================================================
    //  Apply block
    // =========================================================================

    apply {
        // Only route valid IPv4 packets.  Non-IP traffic (ARP, LLDP, etc.) is
        // passed through transparently so that Mininet host-to-host L2
        // reachability and control-plane discovery work without extra rules.
        if (!hdr.ipv4.isValid()) {
            return;
        }

        // Standard IP TTL handling: decrement and drop on expiry.
        // This prevents infinite loops in multi-hop topologies and is required
        // for correct traceroute / hop-count behaviour during debugging.
        if (hdr.ipv4.ttl <= 1) {
            do_drop();
            return;
        }
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // Look up forwarding table.
        ipv4_lpm.apply();
    }
}
