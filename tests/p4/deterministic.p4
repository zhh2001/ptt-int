// Test-only observation adapter. It compiles the production parser, forwarding,
// checksum, telemetry control and deparser without modifying their sources.
// srcAddr carries q; identification ++ dstAddr carries the full 48-bit clock.
#include "headers.p4"
#include "parser.p4"
#include "checksum.p4"
#include "ingress.p4"
#include "telemetry.p4"
#include "deparser.p4"

control TestEgress(inout headers_t hdr, inout local_metadata_t meta,
                   inout standard_metadata_t stdmeta) {
    PttTelemetry() telemetry;
    apply {
        bit<19> q = (bit<19>)hdr.ipv4.srcAddr;
        bit<48> now = hdr.ipv4.identification ++ hdr.ipv4.dstAddr;
        telemetry.apply(hdr, stdmeta.egress_port, q, now);
    }
}
V1Switch(PttParser(), PTTVerifyChecksum(), PttIngress(),
         TestEgress(), PTTComputeChecksum(), PttDeparser()) main;
