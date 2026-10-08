"""A hand-built pcap exercising what SHAR-CRATES's per-protocol records
have to get right - DNS, HTTP/1.1, TLS and Modbus/TCP - for checking its
output against Suricata's on the same packets (see
tests/test_shark_analyzer.py's TestProtocolRecordsAgainstSuricata, whose
expected values are what Suricata 8.0.6 logged for this capture).

Built with struct like tests/pcap_fixtures.py, deterministic, so the
expected values never drift. Keep it deterministic: changing a single byte
here means re-running Suricata over it to refresh those expectations.
"""
import socket
import struct

from tests.pcap_fixtures import _checksum, _tcp_packet, tcp_segments, write_pcap

CLIENT = '10.1.0.10'
DNS_SERVER, HTTP_SERVER, TLS_SERVER, MODBUS_SERVER = '10.1.0.53', '10.1.0.80', '10.1.0.43', '10.1.0.50'


def _udp_packet(src, dst, sport, dport, payload):
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = s + d + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', _checksum(pseudo + udp) or 0xffff) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, s, d)
    ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]
    return b'\x00' * 6 + b'\x11' * 6 + struct.pack('!H', 0x0800) + ip + udp


# ---------------------------------------------------------------- DNS

_TYPES = {'A': 1, 'NS': 2, 'CNAME': 5, 'PTR': 12, 'MX': 15, 'TXT': 16, 'AAAA': 28}


def _name(name):
    return b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'


def _rdata(rtype, value):
    if rtype == 'A':
        return socket.inet_aton(value)
    if rtype == 'AAAA':
        return socket.inet_pton(socket.AF_INET6, value)
    if rtype in ('CNAME', 'NS', 'PTR'):
        return _name(value)
    if rtype == 'MX':
        return struct.pack('!H', 10) + _name(value)
    if rtype == 'TXT':
        raw = value.encode()
        return bytes([len(raw)]) + raw
    raise ValueError(rtype)


def dns_message(txid, qname, qtype, answers=(), response=False, rcode=0):
    """A DNS message: one question, and for a response its answers as
    (name, type, value) with a 300s TTL."""
    flags = 0x0100 | (0x8180 if response else 0) | rcode
    msg = struct.pack('!HHHHHH', txid, flags, 1, len(answers), 0, 0)
    msg += _name(qname) + struct.pack('!HH', _TYPES[qtype], 1)
    for name, rtype, value in answers:
        rd = _rdata(rtype, value)
        msg += _name(name) + struct.pack('!HHIH', _TYPES[rtype], 1, 300, len(rd)) + rd
    return msg


# (client port, txid, name, type, answers or None for no response, rcode)
DNS_TRANSACTIONS = [
    (53001, 0x1001, 'www.example.com', 'A', [('www.example.com', 'A', '93.184.216.34'),
                                             ('www.example.com', 'A', '93.184.216.35')], 0),
    (53002, 0x1002, 'cdn.example.net', 'A', [('cdn.example.net', 'CNAME', 'edge.example.net'),
                                             ('edge.example.net', 'A', '198.51.100.7')], 0),
    (53003, 0x1003, 'ipv6.example.org', 'AAAA', [('ipv6.example.org', 'AAAA', '2001:db8::7')], 0),
    (53004, 0x1004, 'missing.example.com', 'A', [], 3),
    (53005, 0x1005, 'lost.example.com', 'A', None, 0),
    (53006, 0x1006, 'txt.example.com', 'TXT', [('txt.example.com', 'TXT', 'v=spf1 a\tb\\c')], 0),
    (53007, 0x1007, 'mail.example.com', 'A', [('mail.example.com', 'A', '192.0.2.25')], 0),
    (53007, 0x1008, 'example.com', 'MX', [('example.com', 'MX', 'mail.example.com')], 0),
]


def dns_packets():
    pkts = []
    for port, txid, name, qtype, answers, rcode in DNS_TRANSACTIONS:
        pkts.append(_udp_packet(CLIENT, DNS_SERVER, port, 53, dns_message(txid, name, qtype)))
        if answers is not None:
            pkts.append(_udp_packet(DNS_SERVER, CLIENT, 53, port,
                                    dns_message(txid, name, qtype, answers, response=True, rcode=rcode)))
    return pkts


# ---------------------------------------------------------------- HTTP

def _http_response(status, reason, body, content_type='text/html'):
    return (f'HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n'
            f'Content-Length: {len(body)}\r\n\r\n').encode() + body


HTTP_POST_BODY = b'name=report.pdf&size=1024'


def http_packets():
    """Three requests on one keep-alive connection: a 200, a 404, and a
    POST whose body arrives in a second segment."""
    ua = 'Mozilla/5.0 (X11; Linux x86_64) SO-CRATES-test'
    post_head = (f'POST /upload HTTP/1.1\r\nHost: files.example.com\r\nUser-Agent: {ua}\r\n'
                 f'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(HTTP_POST_BODY)}\r\n\r\n').encode()
    return tcp_segments(CLIENT, HTTP_SERVER, 41000, 80, [
        (True, f'GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: {ua}\r\n\r\n'.encode()),
        (False, _http_response(200, 'OK', b'<h1>Hello</h1>')),
        (True, f'GET /missing HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: {ua}\r\nReferer: http://www.example.com/index.html\r\n\r\n'.encode()),
        (False, _http_response(404, 'Not Found', b'nope')),
        (True, post_head),
        (True, HTTP_POST_BODY),
        (False, _http_response(201, 'Created', b'{"ok":true}', 'application/json')),
    ])


# ---------------------------------------------------------------- TLS

TLS_SNI = 'secure.example.com'


def _ext(ext_type, data):
    return struct.pack('!HH', ext_type, len(data)) + data


def client_hello():
    sni = TLS_SNI.encode()
    exts = (
        _ext(0x0000, struct.pack('!HBH', len(sni) + 3, 0, len(sni)) + sni)                  # server_name
        + _ext(0x000a, struct.pack('!H', 4) + struct.pack('!HH', 0x001d, 0x0017))          # supported_groups
        + _ext(0x000b, b'\x01\x00')                                                         # ec_point_formats
        + _ext(0x000d, struct.pack('!H', 4) + struct.pack('!HH', 0x0403, 0x0804))          # signature_algorithms
        + _ext(0x0010, struct.pack('!H', 12) + b'\x02h2' + b'\x08http/1.1')                # ALPN
        + _ext(0x002b, b'\x04' + struct.pack('!HH', 0x0304, 0x0303))                       # supported_versions
        + _ext(0x0033, struct.pack('!HHH', 36, 0x001d, 32) + bytes(range(32)))             # key_share
    )
    suites = struct.pack('!HHHH', 0x1301, 0x1302, 0xc02f, 0xc030)
    body = (struct.pack('!H', 0x0303) + bytes(32) + b'\x20' + bytes(range(32, 64))
            + struct.pack('!H', len(suites)) + suites + b'\x01\x00' + struct.pack('!H', len(exts)) + exts)
    hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs


def server_hello():
    exts = _ext(0x002b, struct.pack('!H', 0x0304)) + _ext(0x0033, struct.pack('!HH', 0x001d, 32) + bytes(32))
    body = (struct.pack('!H', 0x0303) + bytes(range(100, 132)) + b'\x20' + bytes(range(32, 64))
            + struct.pack('!H', 0x1301) + b'\x00' + struct.pack('!H', len(exts)) + exts)
    hs = b'\x02' + struct.pack('!I', len(body))[1:] + body
    record = b'\x16\x03\x03' + struct.pack('!H', len(hs)) + hs
    ccs = b'\x14\x03\x03\x00\x01\x01'
    appdata = b'\x17\x03\x03\x00\x20' + bytes(32)
    return record + ccs + appdata


def tls_packets():
    return tcp_segments(CLIENT, TLS_SERVER, 41001, 443, [
        (True, client_hello()),
        (False, server_hello()),
        (True, b'\x14\x03\x03\x00\x01\x01' + b'\x17\x03\x03\x00\x20' + bytes(32)),
    ])


# ---------------------------------------------------------------- Modbus/TCP

def _mbap(txid, unit, pdu):
    return struct.pack('!HHHB', txid, 0, len(pdu) + 1, unit) + pdu


# (txid, unit, request PDU, response PDU)
MODBUS_TRANSACTIONS = [
    (1, 1, struct.pack('!BHH', 3, 100, 2), struct.pack('!BBHH', 3, 4, 1, 2)),   # read holding registers 100-101
    (2, 1, struct.pack('!BHH', 6, 200, 7), struct.pack('!BHH', 6, 200, 7)),     # write single register 200 = 7
    (3, 1, struct.pack('!BHH', 1, 0, 8), struct.pack('!BB', 0x81, 2)),          # read coils -> illegal data address
]


def modbus_packets():
    segments = []
    for txid, unit, req, resp in MODBUS_TRANSACTIONS:
        segments += [(True, _mbap(txid, unit, req)), (False, _mbap(txid, unit, resp))]
    return tcp_segments(CLIENT, MODBUS_SERVER, 41002, 502, segments)


def write_protocol_pcap(path):
    write_pcap(path, dns_packets() + http_packets() + tls_packets() + modbus_packets())
