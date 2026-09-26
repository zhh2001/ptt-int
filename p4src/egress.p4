control PttEgress(inout headers_t hdr, inout local_metadata_t meta,
                  inout standard_metadata_t stdmeta) {
    PttTelemetry() telemetry;
    apply {
        telemetry.apply(hdr, stdmeta.egress_port, stdmeta.deq_qdepth,
                        stdmeta.egress_global_timestamp);
    }
}
