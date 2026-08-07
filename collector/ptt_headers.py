#!/usr/bin/env python3
"""PTT-INT packet header definitions for offline pcap parsing.

Uses scapy for packet manipulation.

To avoid scapy BitField serialization issues, non-standard-width fields
are packed into standard ShortField/IntField containers with helper
properties for bit-field extraction.
"""

import struct
from scapy.all import Packet, ByteField, ShortField, IntField, XShortField
from scapy.all import bind_layers, IP, UDP


# PTT Shim: 8 bytes = 4 x 16-bit words
# Layout: magic(16) | version(4) flags(4) hop_count(8) | original_udp_dport(16) | reserved(16)
class PTTShim(Packet):
    """PTT shim header (8 bytes).

    Wire format:
        magic:           16 bits  (offset 0)
        version:         4 bits   (offset 16)
        flags:           4 bits   (offset 20)
        hop_count:       8 bits   (offset 24)
        original_udp_dport: 16 bits (offset 32)
        reserved:        16 bits  (offset 48)
    """
    name = "PTTShim"
    fields_desc = [
        XShortField("magic", 0x5054),        # offset 0: 2 bytes
        ShortField("_vfc", 0x1010),          # offset 2: version(4)<<12 | flags(4)<<8 | hop_count(8)
        ShortField("original_udp_dport", 0), # offset 4: 2 bytes
        ShortField("reserved", 0),           # offset 6: 2 bytes
    ]

    @property
    def version(self):
        return (self._vfc >> 12) & 0xF

    @version.setter
    def version(self, v):
        self._vfc = (self._vfc & 0x0FFF) | ((v & 0xF) << 12)

    @property
    def flags(self):
        return (self._vfc >> 8) & 0xF

    @flags.setter
    def flags(self, v):
        self._vfc = (self._vfc & 0xF0FF) | ((v & 0xF) << 8)

    @property
    def hop_count(self):
        return self._vfc & 0xFF

    @hop_count.setter
    def hop_count(self, v):
        self._vfc = (self._vfc & 0xFF00) | (v & 0xFF)


# PTT Hop Record: 12 bytes = 96 bits
# Layout: switch_id(12) | egress_port(9) | state(2) | reason(3) |
#         qdepth(19) | q_pred_far(19) | timestamp_low(32)
#
# Packed as 3 x 32-bit words:
#   word0[31:20] = switch_id
#   word0[19:11] = egress_port
#   word0[10:9]  = state
#   word0[8:6]   = reason
#   word0[5:0]   = qdepth[18:13] (top 6 bits)
#   word1[31:19] = qdepth[12:0] (lower 13 bits)
#   word1[18:0]  = q_pred_far
#   word2[31:0]  = timestamp_low
#
class PTTHop(Packet):
    """PTT hop record (12 bytes = 96 bits).

    Bit-fields are packed into three 32-bit words for scapy compatibility.
    """
    name = "PTTHop"
    fields_desc = [
        IntField("_word0", 0),  # switch_id(12)|egress_port(9)|state(2)|reason(3)|qdepth_hi(6)
        IntField("_word1", 0),  # qdepth_lo(13)|q_pred_far(19)
        IntField("_word2", 0),  # timestamp_low(32)
    ]

    # --- Bit-field accessors ---

    @property
    def switch_id(self):
        return (self._word0 >> 20) & 0xFFF

    @switch_id.setter
    def switch_id(self, v):
        self._word0 = (self._word0 & 0x000FFFFF) | ((v & 0xFFF) << 20)

    @property
    def egress_port(self):
        return (self._word0 >> 11) & 0x1FF

    @egress_port.setter
    def egress_port(self, v):
        self._word0 = (self._word0 & 0xFFF007FF) | ((v & 0x1FF) << 11)

    @property
    def state(self):
        return (self._word0 >> 9) & 0x3

    @state.setter
    def state(self, v):
        self._word0 = (self._word0 & 0xFFFFF9FF) | ((v & 0x3) << 9)

    @property
    def reason(self):
        return (self._word0 >> 6) & 0x7

    @reason.setter
    def reason(self, v):
        self._word0 = (self._word0 & 0xFFFFFE3F) | ((v & 0x7) << 6)

    @property
    def qdepth(self):
        hi = (self._word0 & 0x3F)  # top 6 bits
        lo = (self._word1 >> 19) & 0x1FFF  # lower 13 bits
        return (hi << 13) | lo

    @qdepth.setter
    def qdepth(self, v):
        hi = (v >> 13) & 0x3F
        lo = v & 0x1FFF
        self._word0 = (self._word0 & 0xFFFFFFC0) | hi
        self._word1 = (self._word1 & 0x0007FFFF) | (lo << 19)

    @property
    def q_pred_far(self):
        return self._word1 & 0x7FFFF

    @q_pred_far.setter
    def q_pred_far(self, v):
        self._word1 = (self._word1 & 0xFFF80000) | (v & 0x7FFFF)

    @property
    def timestamp_low(self):
        return self._word2 & 0xFFFFFFFF

    @timestamp_low.setter
    def timestamp_low(self, v):
        self._word2 = v & 0xFFFFFFFF


# State name mapping
STATE_NAMES = {0: "QUIET", 1: "WATCH", 2: "BURST"}

# Reason code mapping
REASON_NAMES = {
    0: "PERIODIC_QUIET",
    1: "PERIODIC_WATCH",
    2: "PREDICTIVE_NEAR",
    3: "EMERGENCY_THRESHOLD",
    4: "FRESHNESS",
    5: "BASELINE_TRIGGER",
}

# Scheme mode mapping
SCHEME_NAMES = {
    0: "FULL",
    1: "PERIODIC_4",
    2: "PERIODIC_16",
    3: "PERIODIC_32",
    4: "REACTIVE",
    5: "DELTA",
    6: "PTT",
}


def register_ptt_layers(int_port: int = 32768):
    """Register PTT layers with scapy for packet dissection."""
    # When UDP dst port == INT_PORT, the payload is PTTShim
    bind_layers(UDP, PTTShim, dport=int_port)
    # PTTShim is followed by PTTHop records
    bind_layers(PTTShim, PTTHop)
    # PTTHop can be followed by another PTTHop (for multiple hops)
    bind_layers(PTTHop, PTTHop)


def parse_state_name(state: int) -> str:
    return STATE_NAMES.get(state, f"UNKNOWN({state})")


def parse_reason_name(reason: int) -> str:
    return REASON_NAMES.get(reason, f"UNKNOWN({reason})")


def parse_scheme_name(scheme: int) -> str:
    return SCHEME_NAMES.get(scheme, f"UNKNOWN({scheme})")
