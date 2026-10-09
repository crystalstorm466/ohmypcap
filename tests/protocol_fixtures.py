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
# write_extra_pcap: protocols SHAR-CRATES records that Suricata doesn't
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


# ---------------------------------------------------------------- SMB
#
# An SMB2 (3.02) session over TCP 445, each message framed in NetBIOS
# session headers: negotiate, an NTLM login (wrapped in SPNEGO, as Windows
# sends it), the IPC$ pipe share and a file share, a file opened and read
# twice (one transfer), a failed open, the share's root opened, an IOCTL,
# a compound open + close in one packet, and a DCERPC bind over a named
# pipe. Plus, on its own connection, an SMB1 negotiate answered in SMB2.

SMB_SERVER = '10.1.0.45'
SMB_SESSION = 0x0000400000000011
_FILETIME_EPOCH = 11644473600


def _filetime(unix):
    return (unix + _FILETIME_EPOCH) * 10_000_000


def _nbss(payload):
    return b'\x00' + len(payload).to_bytes(3, 'big') + payload


def _smb2_header(cmd, msg_id, response=False, status=0, tree=0, session=0, next_command=0, related=False):
    flags = (0x1 if response else 0) | (0x4 if related else 0)
    return (b'\xfeSMB' + struct.pack('<HHIHHIIQIIQ', 64, 1, status, cmd, 1, flags, next_command, msg_id, 0xfeff, tree,
                                      session) + b'\x00' * 16)


def _smb2(cmd, msg_id, body, **kwargs):
    return _smb2_header(cmd, msg_id, **kwargs) + body


def _utf16(text):
    return text.encode('utf-16-le')


def _der(tag, content):
    n = len(content)
    length = bytes([n]) if n < 0x80 else (b'\x81' + bytes([n]) if n < 0x100 else b'\x82' + n.to_bytes(2, 'big'))
    return bytes([tag]) + length + content


def _ntlm_authenticate(domain, user, host):
    """An NTLMSSP AUTHENTICATE message (NTLMv1-sized responses), with its version."""
    fields = [b'\x00' * 24, b'\x11' * 24, _utf16(domain), _utf16(user), _utf16(host), b'\x22' * 16]
    offset = 88      # the fixed part, the version and the MIC
    header, payload = b'', b''
    for data in fields:
        header += struct.pack('<HHI', len(data), len(data), offset + len(payload))
        payload += data
    flags = 0x00000001 | 0x00000200 | 0x02000000 | 0x00080000   # Unicode, NTLM, version, extended security
    version = struct.pack('<BBH', 10, 0, 19041) + b'\x00\x00\x00' + bytes([15])
    return b'NTLMSSP\x00' + struct.pack('<I', 3) + header + struct.pack('<I', flags) + version + b'\x00' * 16 + payload


def _spnego_response_token(token):
    # negTokenResp { responseToken [2] OCTET STRING }
    return _der(0xa1, _der(0x30, _der(0xa2, _der(0x04, token))))


def _smb2_create_request(name, directory=False, delete_on_close=False):
    options = (0x1 if directory else 0x40) | (0x1000 if delete_on_close else 0)
    raw = _utf16(name) or b'\x00'
    return struct.pack('<HBBIQQIIIIIHHII', 57, 0, 0, 2, 0, 0, 0x00120089, 0, 7, 1, options, 120, len(_utf16(name)), 0, 0) + raw


def _smb2_create_response(fid, created, size):
    t = _filetime(created)
    return (struct.pack('<HBBIQQQQQQII', 89, 0, 0, 1, t, t + 10_000_000, t + 20_000_000, t + 30_000_000, 4096, size, 0x20, 0)
            + fid + struct.pack('<II', 0, 0))


def _smb2_error(status_cmd):
    return struct.pack('<HBBI', 9, 0, 0, 0) + b'\x00'


def _smb2_read_request(fid, length, offset):
    return struct.pack('<HBBIQ', 49, 0x50, 0, length, offset) + fid + struct.pack('<IIIHH', 1, 0, 0, 0, 0) + b'\x00'


def _smb2_read_response(data):
    return struct.pack('<HBBIII', 17, 80, 0, len(data), 0, 0) + data


def _smb2_write_request(fid, data):
    return struct.pack('<HHIQ', 49, 112, len(data), 0) + fid + struct.pack('<IIHHI', 0, 0, 0, 0, 0) + data


def _smb2_write_response(count):
    return struct.pack('<HHIIHH', 17, 0, count, 0, 0, 0)


def _smb2_close_request(fid):
    return struct.pack('<HHI', 24, 0, 0) + fid


def _smb2_close_response():
    return struct.pack('<HHIQQQQQQI', 60, 0, 0, 0, 0, 0, 0, 0, 0, 0)


_NDR = bytes.fromhex('045d888aeb1cc9119fe808002b104860') + struct.pack('<HH', 2, 0)
_SRVSVC = bytes.fromhex('c84f324b7016d30112785a47bf6ee188') + struct.pack('<HH', 3, 0)


def _dcerpc_bind(call_id):
    body = struct.pack('<HHIB3x', 4280, 4280, 0, 1) + struct.pack('<HBx', 0, 1) + _SRVSVC + _NDR
    return struct.pack('<BBBB4sHHI', 5, 0, 11, 0x03, b'\x10\x00\x00\x00', 16 + len(body), 0, call_id) + body


def _dcerpc_bind_ack(call_id):
    port = b'\\PIPE\\srvsvc\x00'
    secondary = struct.pack('<H', len(port)) + port
    secondary += b'\x00' * (-(len(secondary) + 24) % 4)
    body = struct.pack('<HHI', 4280, 4280, 0x1234) + secondary + struct.pack('<B3x', 1) + struct.pack('<HH', 0, 0) + _NDR
    return struct.pack('<BBBB4sHHI', 5, 0, 12, 0x03, b'\x10\x00\x00\x00', 16 + len(body), 0, call_id) + body


def smb_packets():
    sid = SMB_SESSION
    file_fid = bytes.fromhex('15000000000000002100000000000000')
    root_fid = bytes.fromhex('16000000000000002200000000000000')
    temp_fid = bytes.fromhex('17000000000000002300000000000000')
    pipe_fid = bytes.fromhex('18000000000000002400000000000000')
    server_guid = bytes.fromhex('7a8e7c564a72104830929a2706fe1853')
    client_guid = bytes.fromhex('ada9c5712669eb119040120079a2c241')
    negotiate = struct.pack('<HHHHI', 36, 4, 1, 0, 0x7f) + client_guid + struct.pack('<Q', 0) + \
        struct.pack('<4H', 0x0202, 0x0210, 0x0300, 0x0302)
    # the server offers NTLMSSP in a SPNEGO negTokenInit, as Windows does -
    # tshark reads the session setup's token by the mechanism offered here
    offer = _der(0x60, _der(0x06, bytes.fromhex('2b0601050502')) + _der(0xa0, _der(0x30, _der(0xa0, _der(0x30, _der(
        0x06, bytes.fromhex('2b06010401823702020a')))))))
    negotiated = struct.pack('<HHHH', 65, 1, 0x0302, 0) + server_guid + struct.pack('<IIIIQQHHI', 0x7, 8388608, 8388608,
                                                                                     8388608, 0, 0, 128, len(offer), 0) + offer
    blob = _spnego_response_token(_ntlm_authenticate('EXAMPLE', 'alice', 'WORKSTATION7'))
    session_setup = struct.pack('<HBBIIHHQ', 25, 0, 1, 1, 0, 88, len(blob), 0) + blob
    ipc, share = _utf16('\\\\FILESRV\\IPC$'), _utf16('\\\\FILESRV\\Finance')
    tree = lambda path: struct.pack('<HHHH', 9, 0, 72, len(path)) + path
    tree_ok = lambda share_type: struct.pack('<HBBIII', 16, share_type, 0, 0, 0, 0x1f01ff)
    ioctl = struct.pack('<HHI', 57, 0, 0x001401fc) + b'\xff' * 16 + struct.pack('<IIIIIIII', 0, 0, 0, 0, 0, 65536, 1, 0)
    ioctl_ok = struct.pack('<HHI', 49, 0, 0x001401fc) + b'\xff' * 16 + struct.pack('<IIIIII', 0, 0, 0, 0, 0, 0)
    created = 1700000000
    # A compound request: CREATE then CLOSE of the file it creates (related)
    create_part = _smb2(5, 10, _smb2_create_request('temp.txt', delete_on_close=True), tree=2, session=sid)
    create_part += b'\x00' * (-len(create_part) % 8)
    compound = create_part[:20] + struct.pack('<I', len(create_part)) + create_part[24:] + \
        _smb2(6, 11, _smb2_close_request(b'\xff' * 16), tree=2, session=sid, related=True)
    created_part = _smb2(5, 10, _smb2_create_response(temp_fid, created, 0), response=True, tree=2, session=sid)
    created_part += b'\x00' * (-len(created_part) % 8)
    compound_ok = created_part[:20] + struct.pack('<I', len(created_part)) + created_part[24:] + \
        _smb2(6, 11, _smb2_close_response(), response=True, tree=2, session=sid, related=True)
    data = b'quarterly numbers\n' * 8
    bind, bind_ack = _dcerpc_bind(2), _dcerpc_bind_ack(2)
    messages = [
        (True, _smb2(0, 0, negotiate)), (False, _smb2(0, 0, negotiated, response=True)),
        (True, _smb2(1, 1, session_setup)),
        (False, _smb2(1, 1, struct.pack('<HHHH', 9, 0, 0, 0), response=True, session=sid)),
        (True, _smb2(3, 2, tree(ipc), session=sid)), (False, _smb2(3, 2, tree_ok(2), response=True, tree=1, session=sid)),
        (True, _smb2(11, 3, ioctl, tree=1, session=sid)), (False, _smb2(11, 3, ioctl_ok, response=True, tree=1, session=sid)),
        (True, _smb2(3, 4, tree(share), session=sid)), (False, _smb2(3, 4, tree_ok(1), response=True, tree=2, session=sid)),
        (True, _smb2(5, 5, _smb2_create_request('Reports\\Q3.xlsx'), tree=2, session=sid)),
        (False, _smb2(5, 5, _smb2_create_response(file_fid, created, len(data) * 2), response=True, tree=2, session=sid)),
        (True, _smb2(8, 6, _smb2_read_request(file_fid, len(data), 0), tree=2, session=sid)),
        (False, _smb2(8, 6, _smb2_read_response(data), response=True, tree=2, session=sid)),
        (True, _smb2(8, 7, _smb2_read_request(file_fid, len(data), len(data)), tree=2, session=sid)),
        (False, _smb2(8, 7, _smb2_read_response(data), response=True, tree=2, session=sid)),
        (True, _smb2(6, 8, _smb2_close_request(file_fid), tree=2, session=sid)),
        (False, _smb2(6, 8, _smb2_close_response(), response=True, tree=2, session=sid)),
        (True, _smb2(5, 9, _smb2_create_request('Missing.docx'), tree=2, session=sid)),
        (False, _smb2(5, 9, _smb2_error(5), response=True, status=0xc0000034, tree=2, session=sid)),
        (True, compound), (False, compound_ok),
        (True, _smb2(5, 12, _smb2_create_request('', directory=True), tree=2, session=sid)),
        (False, _smb2(5, 12, _smb2_create_response(root_fid, created, 0), response=True, tree=2, session=sid)),
        (True, _smb2(5, 13, _smb2_create_request('srvsvc'), tree=1, session=sid)),
        (False, _smb2(5, 13, _smb2_create_response(pipe_fid, 0, 0), response=True, tree=1, session=sid)),
        (True, _smb2(9, 14, _smb2_write_request(pipe_fid, bind), tree=1, session=sid)),
        (False, _smb2(9, 14, _smb2_write_response(len(bind)), response=True, tree=1, session=sid)),
        (True, _smb2(8, 15, _smb2_read_request(pipe_fid, 1024, 0), tree=1, session=sid)),
        (False, _smb2(8, 15, _smb2_read_response(bind_ack), response=True, tree=1, session=sid)),
        (True, _smb2(4, 16, b'\x04\x00\x00\x00', tree=2, session=sid)),
        (False, _smb2(4, 16, b'\x04\x00\x00\x00', response=True, tree=2, session=sid)),
        (True, _smb2(2, 17, b'\x04\x00\x00\x00', session=sid)), (False, _smb2(2, 17, b'\x04\x00\x00\x00', response=True, session=sid)),
    ]
    pkts = tcp_segments(CLIENT, SMB_SERVER, 49700, 445, [(c, _nbss(m)) for c, m in messages])
    # SMB1 negotiate (offering SMB2), answered by an SMB2 negotiate response with the wildcard dialect
    dialects = b''.join(b'\x02' + d + b'\x00' for d in (b'NT LM 0.12', b'SMB 2.002', b'SMB 2.???'))
    smb1 = (b'\xffSMB' + struct.pack('<BIBHH8sHHHHH', 0x72, 0, 0x18, 0xc853, 0, b'\x00' * 8, 0, 0xffff, 0xfeff, 0, 0)
            + b'\x00' + struct.pack('<H', len(dialects)) + dialects)
    wildcard = struct.pack('<HHHH', 65, 1, 0x02ff, 0) + server_guid + struct.pack('<IIIIQQHHI', 0x7, 8388608, 8388608,
                                                                                   8388608, 0, 0, 128, 0, 0)
    pkts += tcp_segments(CLIENT, SMB_SERVER, 49701, 445, [(True, _nbss(smb1)), (False, _nbss(_smb2(0, 0, wildcard, response=True)))])
    return pkts


def write_smb_pcap(path):
    write_pcap(path, smb_packets())
