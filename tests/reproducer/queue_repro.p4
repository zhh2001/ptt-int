/* Minimal BMv2 queue-metadata reproducer.
 *
 * One switch, two hosts.  Pure IPv4 forwarding — no PTT, no INT, no FSM.
 * Logs enq_qdepth, deq_qdepth, deq_timedelta, egress_port on every packet.
 *
 * Expected: with set_queue_rate=10 and a fast UDP flood, deq_qdepth should
 * rise above zero as the token-bucket shaper builds a backlog.
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;

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

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

struct metadata { }

parser p(packet_in pkt, out headers hdr, inout metadata m, inout standard_metadata_t sm) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control vrfy(inout headers hdr, inout metadata m) { apply {} }

control ingress(inout headers hdr, inout metadata m, inout standard_metadata_t sm) {

    action forward(bit<9> port) {
        sm.egress_spec = port;
    }

    action do_drop() {
        mark_to_drop(sm);
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { forward; do_drop; }
        size = 64;
        default_action = do_drop();
    }

    apply {
        ipv4_lpm.apply();
    }
}

control egress(inout headers hdr, inout metadata m, inout standard_metadata_t sm) {
    apply {
        log_msg("QREPRO enq={} deq={} delta={} port={} ts={}",
                {sm.enq_qdepth,
                 sm.deq_qdepth,
                 sm.deq_timedelta,
                 sm.egress_port,
                 sm.egress_global_timestamp});
    }
}

control computeChecksum(inout headers hdr, inout metadata m) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen,
             hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset,
             hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control deparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

V1Switch(p(), vrfy(), ingress(), egress(), computeChecksum(), deparser()) main;
