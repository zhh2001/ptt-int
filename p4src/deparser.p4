control PttDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_options);
        packet.emit(hdr.udp);
        packet.emit(hdr.ptt_shim);
        packet.emit(hdr.hops);
    }
}
