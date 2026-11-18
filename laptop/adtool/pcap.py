"""Incremental pcap file/stream parser (pure stdlib).

Supports:
- classic pcap (LE/BE, usec/nsec, Ethernet / Linux SLL / Linux SLL2 / raw IP)
- IPv4 and IPv6 (incl. 802.1Q VLAN and QinQ double-tagging)
- PCAP-over-IP: byte stream where a new global header means a new session
  (client reconnects mid-stream)

pcapng is detected and reported (tcpdump defaults to classic pcap; tools
like dumpcap/tshark produce pcapng).
"""

from collections import namedtuple
import struct

TCP_PROTO = 6
UDP_PROTO = 17

LINK_ETHERNET = 1
LINK_SLL = 113
LINK_SLL2 = 276
LINK_RAW = 101

Packet = namedtuple(
    "Packet", "ts src_ip dst_ip src_port dst_port proto tcp_flags payload"
)

_MAGIC_LE_USEC = 0xA1B2C3D4
_MAGIC_BE_USEC = 0xD4C3B2A1
_MAGIC_LE_NSEC = 0xA1B23C4D
_MAGIC_BE_NSEC = 0x4D3CB2A1
_MAX_RECORD = 262144


class PcapFormatError(Exception):
    pass


class PcapParser:
    """Incremental parser. feed(data) -> list[Packet]; remaining bytes buffered.

    allow_resync: on garbage bytes (leading junk before a header, oversized
    records) skip one byte at a time instead of raising. Useful for
    PCAP-over-IP where streams may reconnect mid-flight.
    """

    def __init__(self, allow_resync=True):
        self._buf = b""
        self._got_header = False
        self._end = "<"
        self._nsec = False
        self._linktype = LINK_ETHERNET
        self.allow_resync = allow_resync

    def feed(self, data: bytes) -> list:
        self._buf += data
        packets = []
        while True:
            if not self._got_header:
                if len(self._buf) < 24:
                    break
                try:
                    ok = self._parse_header(self._buf[:24])
                except PcapFormatError:
                    if not self.allow_resync:
                        raise  # файл: честная ошибка (например, pcapng)
                    ok = False  # поток: ищем следующий валидный заголовок
                if not ok:
                    if self.allow_resync:
                        self._buf = self._buf[1:]
                        continue
                    raise PcapFormatError("bad pcap magic")
                self._buf = self._buf[24:]
                continue
            if len(self._buf) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig = struct.unpack(
                self._end + "IIII", self._buf[:16]
            )
            if incl_len == 0 or incl_len > _MAX_RECORD:
                if self.allow_resync:
                    self._buf = self._buf[1:]
                    continue
                raise PcapFormatError("implausible record length: %d" % incl_len)
            if len(self._buf) < 16 + incl_len:
                break
            raw = self._buf[16 : 16 + incl_len]
            self._buf = self._buf[16 + incl_len :]
            ts = ts_sec + (ts_frac / 1e9 if self._nsec else ts_frac / 1e6)
            pkt = self._decode_link(ts, raw)
            if pkt is not None:
                packets.append(pkt)
        return packets

    def _parse_header(self, hdr):
        if hdr[:4] == b"\x0a\x0d\x0d\x0a":
            raise PcapFormatError(
                "pcapng не поддерживается — перезапишите tcpdump'ом: "
                "`tcpdump -w file.pcap` (или конвертируйте: editcap -F pcap)"
            )
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (_MAGIC_LE_USEC, _MAGIC_LE_NSEC):
            self._end = "<"
            self._nsec = magic == _MAGIC_LE_NSEC
        elif magic in (_MAGIC_BE_USEC, _MAGIC_BE_NSEC):
            self._end = ">"
            self._nsec = magic == _MAGIC_BE_NSEC
        else:
            return False
        fields = struct.unpack(self._end + "IHHiIII", hdr[:24])
        # fields: magic, major, minor, tz, sigfigs, snaplen, linktype
        self._linktype = fields[6]
        self._got_header = True
        return True

    def _decode_link(self, ts, raw):
        lt = self._linktype
        offset = None
        if lt == LINK_ETHERNET and len(raw) > 14:
            ethertype = struct.unpack(">H", raw[12:14])[0]
            offset = 14
            # 802.1Q (0x8100) и QinQ/802.1ad (0x88A8): пропускаем теги
            while ethertype in (0x8100, 0x88A8) and len(raw) > offset + 4:
                ethertype = struct.unpack(">H", raw[offset + 2 : offset + 4])[0]
                offset += 4
            if ethertype not in (0x0800, 0x86DD):
                return None
        elif lt == LINK_SLL and len(raw) > 16:
            if struct.unpack(">H", raw[14:16])[0] not in (0x0800, 0x86DD):
                return None
            offset = 16
        elif lt == LINK_SLL2 and len(raw) > 20:
            if struct.unpack(">H", raw[0:2])[0] not in (0x0800, 0x86DD):
                return None
            offset = 20
        elif lt == LINK_RAW and len(raw) >= 20:
            offset = 0
        else:
            return None
        return self._decode_ip(ts, raw[offset:])

    def _decode_ip(self, ts, raw):
        if len(raw) < 20:
            return None
        version = raw[0] >> 4
        if version == 4:
            return self._decode_ipv4(ts, raw)
        if version == 6:
            return self._decode_ipv6(ts, raw)
        return None

    def _decode_ipv4(self, ts, raw):
        ihl = (raw[0] & 0x0F) * 4
        if len(raw) < ihl:
            return None
        proto = raw[9]
        src_ip = ".".join(str(b) for b in raw[12:16])
        dst_ip = ".".join(str(b) for b in raw[16:20])
        if proto not in (TCP_PROTO, UDP_PROTO):
            return None
        return self._decode_l4(ts, raw, ihl, proto, src_ip, dst_ip)

    def _decode_ipv6(self, ts, raw):
        if len(raw) < 40:
            return None
        src = raw[8:24]
        dst = raw[24:40]
        proto, offset = raw[6], 40
        # skip extension headers (hop-by-hop, routing, dst options)
        for _ in range(8):
            if proto in (0, 43, 60):
                if len(raw) < offset + 8:
                    return None
                proto = raw[offset]
                ext_len = (raw[offset + 1] + 1) * 8
                offset += ext_len
            else:
                break
        if proto not in (TCP_PROTO, UDP_PROTO):
            return None
        src_ip = ":".join(f"{(src[i] << 8) | src[i + 1]:x}" for i in range(0, 16, 2))
        dst_ip = ":".join(f"{(dst[i] << 8) | dst[i + 1]:x}" for i in range(0, 16, 2))
        return self._decode_l4(ts, raw, offset, proto, src_ip, dst_ip)

    def _decode_l4(self, ts, raw, offset, proto, src_ip, dst_ip):
        l4 = raw[offset:]
        if len(l4) < 8:
            return None
        src_port, dst_port = struct.unpack(">HH", l4[:4])
        payload = b""
        tcp_flags = 0
        if proto == TCP_PROTO:
            data_off = (l4[12] >> 4) * 4
            tcp_flags = l4[13]
            if len(l4) > data_off:
                payload = l4[data_off:]
        else:
            payload = l4[8:]
        return Packet(
            ts=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            tcp_flags=tcp_flags,
            payload=payload,
        )


def read_pcap_file(path):
    """Parse a whole pcap file, return list[Packet]."""
    parser = PcapParser(allow_resync=False)
    packets = []
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            packets.extend(parser.feed(chunk))
    return packets
