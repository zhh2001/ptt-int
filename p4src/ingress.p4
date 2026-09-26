// Port forwarding assumes preconfigured link-layer next-hop addresses.
control PttIngress(inout headers_t hdr, inout local_metadata_t meta,
                   inout standard_metadata_t stdmeta) {
    action forward(bit<9> port) { stdmeta.egress_spec = port; }
    action do_drop() { mark_to_drop(stdmeta); }
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { forward; do_drop; }
        size = 256;
        default_action = do_drop();
    }
    apply {
        if (stdmeta.parser_error != error.NoError ||
            stdmeta.checksum_error == 1 || !hdr.ipv4.isValid()) {
            do_drop();
        } else if (hdr.ipv4.ttl <= 1) {
            do_drop();
        } else {
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            ipv4_lpm.apply();
        }
    }
}
