"""A hand-built pcap exercising what tshark's per-protocol records
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
FTP_SERVER = '10.1.0.21'


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


# ---------------------------------------------------------------- FTP

class _Tcp:
    """One TCP connection built a step at a time, so two connections'
    packets can be interleaved (an FTP data connection between its
    command's 150 and 226 replies)."""

    def __init__(self, client, server, cport, sport):
        self.c, self.s, self.cp, self.sp = client, server, cport, sport
        self.cs, self.ss = 1000, 5000

    def open(self):
        pkts = [_tcp_packet(self.c, self.s, self.cp, self.sp, self.cs, 0, 0x02)]
        self.cs += 1
        pkts.append(_tcp_packet(self.s, self.c, self.sp, self.cp, self.ss, self.cs, 0x12))
        self.ss += 1
        pkts.append(_tcp_packet(self.c, self.s, self.cp, self.sp, self.cs, self.ss, 0x10))
        return pkts

    def send(self, from_client, payload):
        if from_client:
            pkt = _tcp_packet(self.c, self.s, self.cp, self.sp, self.cs, self.ss, 0x18, payload)
            self.cs += len(payload)
        else:
            pkt = _tcp_packet(self.s, self.c, self.sp, self.cp, self.ss, self.cs, 0x18, payload)
            self.ss += len(payload)
        return [pkt]

    def close(self):
        return [_tcp_packet(self.c, self.s, self.cp, self.sp, self.cs, self.ss, 0x11),
                _tcp_packet(self.s, self.c, self.sp, self.cp, self.ss, self.cs + 1, 0x11)]


FTP_GREETING = b'220-Welcome to the test FTP server\r\n220-Second greeting line\r\n220 Ready.\r\n'


def ftp_packets():
    """A control connection with a three-line greeting, login, an OPTS
    command the server rejects, a passive RETR and an active PORT + STOR,
    each data connection running between its command's 150 and 226."""
    ctl = _Tcp(CLIENT, FTP_SERVER, 41003, 21)
    pkts = ctl.open() + ctl.send(False, FTP_GREETING)
    for command, reply in ((b'USER alice', b'331 Password required'), (b'PASS s3cret', b'230 Logged in.'),
                           (b'OPTS utf8 on', b'504 Unknown command'),
                           (b'PASV', b'227 Entering Passive Mode (10,1,0,21,195,81)'),
                           (b'RETR report.pdf', b'150 Opening data connection')):
        pkts += ctl.send(True, command + b'\r\n') + ctl.send(False, reply + b'\r\n')
    passive = _Tcp(CLIENT, FTP_SERVER, 41004, 50001)
    pkts += passive.open() + passive.send(False, b'%PDF-1.4 test report\n') + passive.close()
    pkts += ctl.send(False, b'226 Transfer complete\r\n')
    for command, reply in ((b'PORT 10,1,0,10,160,5', b'200 PORT command successful'),
                           (b'STOR upload.txt', b'150 Ok to send data')):
        pkts += ctl.send(True, command + b'\r\n') + ctl.send(False, reply + b'\r\n')
    active = _Tcp(FTP_SERVER, CLIENT, 20, 40965)   # PORT ...,160,5 = 160 * 256 + 5
    pkts += active.open() + active.send(False, b'uploaded contents\n') + active.close()
    pkts += ctl.send(False, b'226 Transfer complete\r\n')
    pkts += ctl.send(True, b'QUIT\r\n') + ctl.send(False, b'221 Goodbye.\r\n') + ctl.close()
    return pkts


def write_protocol_pcap(path):
    write_pcap(path, dns_packets() + http_packets() + tls_packets() + modbus_packets() + ftp_packets())


# ---------------------------------------------------------------- the second capture
#
# write_extra_pcap: protocols tshark records that Suricata doesn't
# (NBNS, LLMNR, SSDP, S7comm), and the cases real captures turned up that
# the first capture lacked - checked against Suricata's output where
# Suricata parses them too (tests/data/extra_fixture.eve.json).

def _udp_dns(src, dst, sport, dport, payload):
    return _udp_packet(src, dst, sport, dport, payload)


def _icmp_unreachable(src, dst, about):
    """An ICMP port unreachable from src to dst, carrying the IP header and
    first 8 bytes of the packet `about` (a whole Ethernet frame)."""
    inner = about[14:14 + 20 + 8]
    icmp = struct.pack('!BBHI', 3, 3, 0, 0) + inner
    icmp = icmp[:2] + struct.pack('!H', _checksum(icmp)) + icmp[4:]
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0, s, d)
    ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]
    return b'\x00' * 6 + b'\x11' * 6 + struct.pack('!H', 0x0800) + ip + icmp


def _nbns_name(name, suffix):
    raw = name.upper().ljust(15)[:15].encode() + bytes([suffix])
    encoded = b''.join(bytes([0x41 + (c >> 4), 0x41 + (c & 0xf)]) for c in raw)
    return b'\x20' + encoded + b'\x00'


def _nbns(txid, flags, name, suffix, answer_addr=None, additional_addr=None, ttl=300000):
    rr = lambda addr: b'\xc0\x0c' + struct.pack('!HHIH', 0x20, 1, ttl, 6) + b'\x00\x00' + socket.inet_aton(addr)
    an = rr(answer_addr) if answer_addr else b''
    ar = rr(additional_addr) if additional_addr else b''
    is_response = flags & 0x8000
    question = b'' if is_response else _nbns_name(name, suffix) + struct.pack('!HH', 0x20, 1)
    head = struct.pack('!HHHHHH', txid, flags, 0 if is_response else 1, 1 if an else 0, 0, 1 if ar else 0)
    if is_response:
        an = _nbns_name(name, suffix) + an[2:]
    return head + question + an + ar


def _tpkt_s7(s7):
    cotp = b'\x02\xf0\x80'
    return struct.pack('!BBH', 3, 0, 4 + len(cotp) + len(s7)) + cotp + s7


def _s7_job(pduref, params, data=b''):
    return _tpkt_s7(struct.pack('!BBHHHH', 0x32, 1, 0, pduref, len(params), len(data)) + params + data)


def _s7_ack(pduref, params, data=b'', errcls=0, errcod=0):
    return _tpkt_s7(struct.pack('!BBHHHHBB', 0x32, 3, 0, pduref, len(params), len(data), errcls, errcod) + params + data)


S7_PLC = '10.1.0.102'
SSDP_DEVICE = '10.1.0.60'
LLMNR_RESPONDER = '10.1.0.70'


def extra_packets():
    pkts = []
    # DNS: a query sent twice before its one answer; a query answered three times
    q = dns_message(0x3001, 'slow.example.com', 'A')
    a = dns_message(0x3001, 'slow.example.com', 'A', [('slow.example.com', 'A', '192.0.2.80')], response=True)
    pkts += [_udp_packet(CLIENT, DNS_SERVER, 53010, 53, q), _udp_packet(CLIENT, DNS_SERVER, 53010, 53, q),
             _udp_packet(DNS_SERVER, CLIENT, 53, 53010, a)]
    q = dns_message(0x3002, 'echo.example.com', 'A')
    a = dns_message(0x3002, 'echo.example.com', 'A', [('echo.example.com', 'A', '192.0.2.81')], response=True)
    response = _udp_packet(DNS_SERVER, CLIENT, 53, 53011, a)
    # ... and the client, having closed the port, answers the third with an ICMP port unreachable
    pkts += [_udp_packet(CLIENT, DNS_SERVER, 53011, 53, q), response, response, response,
             _icmp_unreachable(CLIENT, DNS_SERVER, response)]
    # mDNS: a query, its multicast answer, and an empty probe
    pkts += [_udp_packet(CLIENT, '224.0.0.251', 5353, 5353, dns_message(0, '_ipp._tcp.local', 'PTR')),
             _udp_packet(SSDP_DEVICE, '224.0.0.251', 5353, 5353,
                         dns_message(0, '_ipp._tcp.local', 'PTR', [('_ipp._tcp.local', 'PTR', 'printer._ipp._tcp.local')],
                                     response=True)),
             _udp_packet(CLIENT, '224.0.0.251', 5353, 5353, b'\x00' * 12)]
    # LLMNR: who has wpad?
    pkts += [_udp_packet(CLIENT, '224.0.0.252', 53020, 5355, dns_message(0x4001, 'wpad', 'A')),
             _udp_packet(LLMNR_RESPONDER, CLIENT, 5355, 53020,
                         dns_message(0x4001, 'wpad', 'A', [('wpad', 'A', LLMNR_RESPONDER)], response=True))]
    # NBNS: a registration broadcast three times, then a query and its answer
    reg = _nbns(0x5001, 0x2910, 'DESKTOP-TEST01', 0x20, additional_addr=CLIENT)
    pkts += [_udp_packet(CLIENT, '10.1.0.255', 137, 137, reg)] * 3
    pkts += [_udp_packet(CLIENT, '10.1.0.255', 137, 137, _nbns(0x5002, 0x0110, 'FILESERVER', 0x20)),
             _udp_packet('10.1.0.30', CLIENT, 137, 137, _nbns(0x5002, 0x8500, 'FILESERVER', 0x20, answer_addr='10.1.0.30'))]
    # SSDP: an M-SEARCH, a device's answer, and a NOTIFY
    pkts += [_udp_packet(CLIENT, '239.255.255.250', 53030, 1900,
                         b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\n'
                         b'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n'),
             _udp_packet(SSDP_DEVICE, CLIENT, 1900, 53030,
                         b'HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://10.1.0.60:49152/gateway.xml\r\n'
                         b'SERVER: Linux/5.4 UPnP/1.0 TestGateway/1.0\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n'
                         b'USN: uuid:0b1d-test::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n'),
             _udp_packet(SSDP_DEVICE, '239.255.255.250', 1900, 1900,
                         b'NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n'
                         b'LOCATION: http://10.1.0.60:49152/gateway.xml\r\nUSN: uuid:0b1d-test::upnp:rootdevice\r\n\r\n')]
    # HTTP: Host with a port, and a Content-Type with parameters
    pkts += tcp_segments(CLIENT, HTTP_SERVER, 41010, 8080, [
        (True, b'GET /status HTTP/1.1\r\nHost: www.example.com:8080\r\nUser-Agent: test\r\n\r\n'),
        (False, b'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\n\r\nok'),
    ])
    # FTP: a failed login the server answers, then hangs up on
    pkts += tcp_segments(CLIENT, FTP_SERVER, 41011, 21, [
        (False, b'220 Ready.\r\n'), (True, b'USER bob\r\n'), (False, b'331 Password required\r\n'),
        # The client's ACK of the 530, as a real client sends one, before the 221
        (True, b'PASS wrong\r\n'), (False, b'530 Login incorrect.\r\n'), (True, b''), (False, b'221 Goodbye.\r\n'),
    ])
    # S7comm (ISO-on-TCP, port 102): setup, a read of DB1 byte 10, a write
    # the PLC refuses, and a CPU-functions userdata request
    read_item = b'\x12\x0a\x10\x02\x00\x01\x00\x01\x84' + (10 << 3).to_bytes(3, 'big')
    pkts += tcp_segments(CLIENT, S7_PLC, 41012, 102, [
        (True, _s7_job(1, b'\xf0\x00\x00\x01\x00\x01\x01\xe0')),
        (False, _s7_ack(1, b'\xf0\x00\x00\x01\x00\x01\x01\xe0')),
        (True, _s7_job(2, b'\x04\x01' + read_item)),
        (False, _s7_ack(2, b'\x04\x01', b'\xff\x04\x00\x08\x2a')),
        (True, _s7_job(3, b'\x05\x01' + read_item, b'\x00\x04\x00\x08\x07')),
        (False, _s7_ack(3, b'\x05\x01', b'\x0a', errcls=0x85, errcod=0x00)),
        (True, _tpkt_s7(struct.pack('!BBHHHH', 0x32, 7, 0, 4, 8, 8) + b'\x00\x01\x12\x04\x11\x44\x01\x00'
                        + b'\xff\x09\x00\x04\x00\x11\x00\x00')),
    ])
    # DNS caught mid-conversation (the 4SICS GeekLounge capture opens this
    # way): the answer to a query sent before recording began, then the
    # client's next query and its answer. Suricata takes the server for the
    # client, doesn't recognize the flow as DNS, and logs no DNS for it.
    old = dns_message(0x6001, 'time.example.com', 'A', rcode=5, response=True)
    new_q = dns_message(0x6002, 'time.example.com', 'A')
    new_a = dns_message(0x6002, 'time.example.com', 'A', rcode=5, response=True)
    pkts += [_udp_packet(DNS_SERVER, CLIENT, 53, 949, old), _udp_packet(CLIENT, DNS_SERVER, 949, 53, new_q),
             _udp_packet(DNS_SERVER, CLIENT, 53, 949, new_a)]
    return pkts


def write_extra_pcap(path):
    write_pcap(path, extra_packets())
