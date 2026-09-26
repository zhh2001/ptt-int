// Single production entry point.
#include "headers.p4"
#include "parser.p4"
#include "checksum.p4"
#include "ingress.p4"
#include "telemetry.p4"
#include "egress.p4"
#include "deparser.p4"
V1Switch(PttParser(), PTTVerifyChecksum(), PttIngress(),
         PttEgress(), PTTComputeChecksum(), PttDeparser()) main;
