"""The 8-byte shim and 12-byte hop record (network byte order)."""
from scapy.fields import BitField, ByteField, IntField, PacketListField, ShortField, XShortField
from scapy.packet import Packet, Raw, bind_layers
from scapy.layers.inet import UDP

MAGIC = 0x5054
VERSION = 1
MAX_HOPS = 8
SHIM_BYTES = 8
HOP_BYTES = 12
STATE_NAMES = {0: "QUIET", 1: "WATCH", 2: "BURST"}
REASON_NAMES = {
    0: "PERIODIC_QUIET", 1: "PERIODIC_WATCH", 2: "PREDICTIVE_NEAR",
    3: "EMERGENCY_THRESHOLD", 4: "FRESHNESS",
}


class PTTHop(Packet):
    name = "PTTHop"
    fields_desc = [
        BitField("switch_id", 0, 12), BitField("egress_port", 0, 9),
        BitField("state", 0, 2), BitField("reason", 0, 3),
        BitField("qdepth", 0, 19), BitField("q_pred_far", 0, 19),
        IntField("timestamp_low", 0),
    ]

    def extract_padding(self, data):
        return b"", data


class PTTShim(Packet):
    name = "PTTShim"
    fields_desc = [
        XShortField("magic", MAGIC), BitField("version", VERSION, 4),
        BitField("flags", 0, 4), ByteField("hop_count", 0),
        ShortField("original_udp_dport", 0), ShortField("reserved", 0),
        PacketListField("hops", [], PTTHop, count_from=lambda p: min(p.hop_count, MAX_HOPS)),
    ]

    def guess_payload_class(self, payload):
        return Raw


def decode_ptt(data: bytes, max_hops: int = MAX_HOPS):
    """Return (shim, hops, application_payload); reject invalid/truncated PTT."""
    if not 1 <= max_hops <= MAX_HOPS:
        raise ValueError("max_hops must be in [1, 8]")
    if len(data) < SHIM_BYTES:
        raise ValueError("truncated PTT shim")
    if int.from_bytes(data[:2], "big") != MAGIC or data[2] >> 4 != VERSION:
        raise ValueError("unsupported PTT magic/version")
    count = data[3]
    if count > max_hops:
        raise ValueError("PTT hop count exceeds configured maximum")
    end = SHIM_BYTES + HOP_BYTES * count
    if len(data) < end:
        raise ValueError("truncated PTT hop stack")
    shim = PTTShim(data[:end])
    return shim, list(shim.hops), data[end:]


def register_ptt_layers(int_port: int = 32768):
    bind_layers(UDP, PTTShim, dport=int_port)
    # The reserved destination port takes precedence over source-port bindings
    # such as DNS. Repeated registration must not create duplicate guesses.
    match = ({"dport": int_port}, PTTShim)
    UDP.payload_guess = [match] + [entry for entry in UDP.payload_guess if entry != match]


def parse_state_name(state):
    return STATE_NAMES.get(state, f"UNKNOWN({state})")


def parse_reason_name(reason):
    return REASON_NAMES.get(reason, f"UNKNOWN({reason})")
