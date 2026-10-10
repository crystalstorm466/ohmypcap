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


# ---------------------------------------------------------------- Telnet
#
# Three sessions to TELNET_SERVER:23 - a login (option negotiation, a
# banner, a name typed a key at a time and echoed back, a password with a
# backspace in it, commands, an arrow key), a failed login at a MOXA-style
# "Account:" prompt, and a scanner's HTTP request to the Telnet port,
# which Suricata takes for HTTP.

TELNET_SERVER = '10.1.0.23'


def _keystrokes(text, echo=True):
    """Each character typed as its own segment, echoed back unless a
    password."""
    out = []
    for ch in text:
        out.append((True, ch.encode()))
        if echo and ch not in '\r\x7f':
            out.append((False, ch.encode()))
    return out


def telnet_packets():
    iac_do_ttype, iac_will_ttype = b'\xff\xfd\x18', b'\xff\xfb\x18'
    login = ([(False, iac_do_ttype), (True, iac_will_ttype),
              (False, b'\r\nUbuntu 22.04.3 LTS\r\nrouter1 login: ')]
             + _keystrokes('admin\r') + [(False, b'\r\nPassword: ')]
             + _keystrokes('s3crx\x7fet\r', echo=False)
             + [(False, b'\r\nLast login: Mon Oct  9 10:00:00 2026\r\nadmin@router1:~$ ')]
             + _keystrokes('ls -la\r') + [(False, b'\r\ntotal 0\r\nadmin@router1:~$ ')]
             + [(True, b'\x1b[A'), (False, b'ls -la'), (True, b'\x7f' * 6), (True, b'\r'), (False, b'\r\nadmin@router1:~$ ')]
             + _keystrokes('exit\r') + [(False, b'\r\nlogout\r\n')])
    failed = ([(False, iac_do_ttype), (True, iac_will_ttype),
               (False, b'\r\nMOXA EtherDevice Switch EDS-508A\r\nAccount: ')]
              + _keystrokes('admin\r') + [(False, b'\r\nPassword: ')] + _keystrokes('admin\r', echo=False)
              + [(False, b'\r\nLogin incorrect\r\n')])
    probe = [(True, b'GET / HTTP/1.0\r\n\r\n'), (False, iac_do_ttype + b'\r\nrouter2 login: ')]
    return (tcp_segments(CLIENT, TELNET_SERVER, 41023, 23, login)
            + tcp_segments(CLIENT, TELNET_SERVER, 41024, 23, failed)
            + tcp_segments(CLIENT, TELNET_SERVER, 41025, 23, probe))


def write_telnet_pcap(path):
    write_pcap(path, telnet_packets())


# ---------------------------------------------------------------- IEC 60870-5-104
#
# A controlling station (CLIENT) and a substation (IEC104_RTU:2404, common
# address 7): STARTDT, a station interrogation answered by two float
# points and terminated, a single command (on) confirmed and terminated,
# a float set point refused (negative confirmation), a packet carrying
# two messages, two interrogations sent back to back, and a confirmation
# whose request isn't in the capture.

IEC104_RTU = '10.1.0.104'
_IEC104_STATION = 7


def _apci_i(asdu, tx, rx):
    return bytes([0x68, 4 + len(asdu)]) + struct.pack('<HH', tx << 1, rx << 1) + asdu


def _apci_u(control):
    return bytes([0x68, 4, control, 0, 0, 0])


def _asdu(typeid, cause, objects, negative=False, sq=False):
    """objects: (ioa, element bytes) - each with its address unless sq."""
    vsq = len(objects) | (0x80 if sq else 0)
    cot = cause | (0x40 if negative else 0)
    body = b''
    for i, (ioa, element) in enumerate(objects):
        if not sq or i == 0:
            body += ioa.to_bytes(3, 'little')
        body += element
    return bytes([typeid, vsq, cot, 0]) + struct.pack('<H', _IEC104_STATION) + body


def iec104_packets():
    float_point = lambda value: struct.pack('<f', value) + b'\x00'          # value, quality
    interrogation = lambda cause: _asdu(100, cause, [(0, b'\x14')])         # QOI 20: station
    segments = [
        (True, _apci_u(0x07)), (False, _apci_u(0x0b)),                         # STARTDT act / con
        (True, _apci_i(interrogation(6), 0, 0)),
        (False, _apci_i(interrogation(7), 0, 1)),
        (False, _apci_i(_asdu(13, 20, [(1001, float_point(230.5)), (1002, float_point(49.98))]), 1, 1)),
        (False, _apci_i(interrogation(10), 2, 1)),
        (True, _apci_i(_asdu(45, 6, [(2001, b'\x01')]), 1, 3)),                 # single command: on
        (False, _apci_i(_asdu(45, 7, [(2001, b'\x01')]), 3, 2)),
        (False, _apci_i(_asdu(45, 10, [(2001, b'\x01')]), 4, 2)),
        (True, _apci_i(_asdu(50, 6, [(3001, struct.pack('<f', 3.25) + b'\x00')]), 2, 5)),   # set point
        (False, _apci_i(_asdu(50, 7, [(3001, struct.pack('<f', 3.25) + b'\x00')], negative=True), 5, 3)),
        # one packet, two messages: a float and a single point, spontaneous
        (False, _apci_i(_asdu(13, 3, [(1001, float_point(231.0))]), 6, 3)
                + _apci_i(_asdu(1, 3, [(1003, b'\x01')]), 7, 3)),
        # two interrogations before either is answered; replies in order
        (True, _apci_i(interrogation(6), 3, 8)), (True, _apci_i(interrogation(6), 4, 8)),
        (False, _apci_i(interrogation(7), 8, 5)), (False, _apci_i(interrogation(10), 9, 5)),
        (False, _apci_i(interrogation(7), 10, 5)), (False, _apci_i(interrogation(10), 11, 5)),
        # a clock sync confirmation whose activation the capture missed
        (False, _apci_i(_asdu(103, 7, [(0, b'\x00' * 7)]), 12, 5)),
    ]
    return tcp_segments(CLIENT, IEC104_RTU, 42404, 2404, segments)


def write_iec104_pcap(path):
    write_pcap(path, iec104_packets())


# ---------------------------------------------------------------- BACnet/IP
#
# A workstation (CLIENT:47808) and a controller (BACNET_DEVICE:47808,
# device 1047, vendor 42): Who-Is broadcasts (one with a range), the
# device's I-Am twice, a present-value read answered with 72.5 and then
# refused (unknown-property), a write of a binary output to active, a
# write and a read both sent as invoke id 4 before either reply - the
# replies in the other order, as a real client and router did - a
# reinitialize with a wrong password (password-failure), a communication
# control disabling the device for 5 minutes with its password, and a
# change-of-value notification of an analog input.

BACNET_DEVICE = '10.1.0.47'
_BACNET_BROADCAST = '10.1.255.255'
_BACNET_PORT = 47808
_ANALOG_INPUT, _ANALOG_VALUE, _BINARY_OUTPUT, _DEVICE = 0, 2, 4, 8
_PRESENT_VALUE, _STATUS_FLAGS = 85, 111


def _bacnet_ip(src, dst, apdu, expecting_reply=False, broadcast=False):
    npdu = bytes([0x01, 0x04 if expecting_reply else 0x00]) + apdu
    bvlc = bytes([0x81, 0x0b if broadcast else 0x0a]) + struct.pack('!H', 4 + len(npdu))
    return _udp_packet(src, dst, _BACNET_PORT, _BACNET_PORT, bvlc + npdu)


def _bacnet_object(obj_type, instance):
    return struct.pack('!I', (obj_type << 22) | instance)


def _ctx(number, value):
    """A context tag with a short value."""
    if len(value) <= 4:
        return bytes([(number << 4) | 0x08 | len(value)]) + value
    return bytes([(number << 4) | 0x08 | 5, len(value)]) + value


def _bacnet_string(text):
    return b'\x00' + text.encode()      # character set 0: UTF-8


def _bacnet_real(value):
    return b'\x44' + struct.pack('!f', value)


def _confirmed(invoke, service, body):
    return bytes([0x00, 0x05, invoke, service]) + body


def _read_property(invoke, obj_type, instance, prop=_PRESENT_VALUE):
    return _confirmed(invoke, 12, _ctx(0, _bacnet_object(obj_type, instance)) + _ctx(1, bytes([prop])))


def _read_property_ack(invoke, obj_type, instance, value, prop=_PRESENT_VALUE):
    return bytes([0x30, invoke, 12]) + _ctx(0, _bacnet_object(obj_type, instance)) + _ctx(1, bytes([prop])) \
        + b'\x3e' + value + b'\x3f'


def _write_property(invoke, obj_type, instance, value):
    return _confirmed(invoke, 15, _ctx(0, _bacnet_object(obj_type, instance)) + _ctx(1, bytes([_PRESENT_VALUE]))
                      + b'\x3e' + value + b'\x3f' + _ctx(4, b'\x08'))


def _bacnet_error(invoke, service, error_class, error_code):
    return bytes([0x50, invoke, service, 0x91, error_class, 0x91, error_code])


def bacnet_packets():
    device = _bacnet_object(_DEVICE, 1047)
    i_am = b'\x10\x00' + b'\xc4' + device + b'\x22\x05\xc4' + b'\x91\x00' + b'\x21\x2a'
    to_device = lambda apdu: _bacnet_ip(CLIENT, BACNET_DEVICE, apdu, expecting_reply=apdu[0] == 0x00)
    from_device = lambda apdu: _bacnet_ip(BACNET_DEVICE, CLIENT, apdu)
    cov = (b'\x10\x02' + _ctx(0, b'\x01') + _ctx(1, device) + _ctx(2, _bacnet_object(_ANALOG_INPUT, 2)) + _ctx(3, b'\x00')
           + b'\x4e' + _ctx(0, bytes([_PRESENT_VALUE])) + b'\x2e' + _bacnet_real(21.5) + b'\x2f'
           + _ctx(0, bytes([_STATUS_FLAGS])) + b'\x2e' + b'\x82\x04\x00' + b'\x2f' + b'\x4f')
    return [
        _bacnet_ip(CLIENT, _BACNET_BROADCAST, b'\x10\x08', broadcast=True),
        _bacnet_ip(CLIENT, _BACNET_BROADCAST, b'\x10\x08' + _ctx(0, b'\x64') + _ctx(1, b'\xc8'), broadcast=True),
        _bacnet_ip(BACNET_DEVICE, _BACNET_BROADCAST, i_am, broadcast=True),
        to_device(_read_property(1, _ANALOG_VALUE, 1)),
        from_device(_read_property_ack(1, _ANALOG_VALUE, 1, _bacnet_real(72.5))),
        to_device(_read_property(2, _ANALOG_VALUE, 1)),
        from_device(_bacnet_error(2, 12, 2, 32)),                                # property: unknown-property
        to_device(_write_property(3, _BINARY_OUTPUT, 3, b'\x91\x01')),          # active
        from_device(bytes([0x20, 3, 15])),
        to_device(_write_property(4, _ANALOG_VALUE, 2, _bacnet_real(50.0))),
        to_device(_read_property(4, _ANALOG_VALUE, 2)),
        from_device(_read_property_ack(4, _ANALOG_VALUE, 2, _bacnet_real(49.0))),
        from_device(bytes([0x20, 4, 15])),
        to_device(_confirmed(5, 20, _ctx(0, b'\x01') + _ctx(1, _bacnet_string('filister')))),   # warmstart
        from_device(_bacnet_error(5, 20, 5, 26)),                               # services: password-failure
        to_device(_confirmed(6, 17, _ctx(0, b'\x05') + _ctx(1, b'\x01') + _ctx(2, _bacnet_string('secret')))),
        from_device(bytes([0x20, 6, 17])),
        _bacnet_ip(BACNET_DEVICE, _BACNET_BROADCAST, i_am, broadcast=True),
        from_device(cov),
    ]


def write_bacnet_pcap(path):
    write_pcap(path, bacnet_packets())


# ---------------------------------------------------------------- OPC UA
#
# A client (CLIENT:48400) and a server (OPCUA_SERVER:4840) over one
# connection, security policy None: hello, open secure channel (mode None),
# create a session as "Fixture Client", activate it as user1 with the
# password sent in the clear, a write of 42 to ns=1;s=the.answer (Good), a
# method call refused for its one operation (BadNodeIdUnknown), a read, a
# publish answered with a ServiceFault (BadNoSubscription), and close.

OPCUA_SERVER = '10.1.0.48'
_OPCUA_ENDPOINT = 'opc.tcp://10.1.0.48:4840/fixture'


def _ua_string(text):
    if text is None:
        return struct.pack('<i', -1)
    data = text.encode() if isinstance(text, str) else text
    return struct.pack('<i', len(data)) + data


def _ua_node(ns, ident):
    if isinstance(ident, str):
        return struct.pack('<BH', 0x03, ns) + _ua_string(ident)
    if ns == 0 and ident < 256:
        return struct.pack('<BB', 0x00, ident)
    return struct.pack('<BBH', 0x01, ns, ident)


_UA_NULL_EXTOBJ = b'\x00\x00\x00'


def _ua_request_header(handle):
    return _ua_node(0, 0) + struct.pack('<qII', 0, handle, 0) + _ua_string(None) + struct.pack('<I', 0) + _UA_NULL_EXTOBJ


def _ua_response_header(handle, result=0):
    return struct.pack('<qII', 0, handle, result) + b'\x00' + struct.pack('<i', -1) + _UA_NULL_EXTOBJ


def _ua_message(kind, header, body):
    return kind + b'F' + struct.pack('<I', 8 + len(header) + len(body)) + header + body


def _ua_msg(service, request_id, body):
    header = struct.pack('<IIII', 7, 1, request_id + 1, request_id)
    return _ua_message(b'MSG', header, struct.pack('<BBH', 0x01, 0, service) + body)


def opcua_packets():
    hello = _ua_message(b'HEL', b'', struct.pack('<IIIII', 0, 65536, 65536, 0, 0) + _ua_string(_OPCUA_ENDPOINT))
    ack = _ua_message(b'ACK', b'', struct.pack('<IIIII', 0, 65536, 65536, 0, 0))
    opn_header = struct.pack('<I', 0) + _ua_string('http://opcfoundation.org/UA/SecurityPolicy#None') \
        + _ua_string(None) + _ua_string(None) + struct.pack('<II', 1, 1)
    open_request = _ua_message(b'OPN', opn_header, struct.pack('<BBH', 0x01, 0, 446) + _ua_request_header(1)
                               + struct.pack('<III', 0, 0, 1) + _ua_string(b'') + struct.pack('<I', 3600000))
    open_response = _ua_message(b'OPN', opn_header, struct.pack('<BBH', 0x01, 0, 449) + _ua_response_header(1)
                                + struct.pack('<IIIqI', 0, 7, 1, 0, 3600000) + _ua_string(b''))
    client = (_ua_string('urn:fixture:client') + _ua_string('urn:fixture') + b'\x02' + _ua_string('Fixture Client')
              + struct.pack('<I', 1) + _ua_string(None) + _ua_string(None) + struct.pack('<i', 0))
    create = _ua_msg(461, 2, _ua_request_header(2) + client + _ua_string(None) + _ua_string(_OPCUA_ENDPOINT)
                     + _ua_string('Fixture Session') + _ua_string(None) + _ua_string(None) + struct.pack('<dI', 60000.0, 0))
    create_response = _ua_msg(464, 2, _ua_response_header(2) + _ua_node(1, 1001) + _ua_node(1, 1002)
                              + struct.pack('<d', 60000.0) + _ua_string(None) + _ua_string(None)
                              + struct.pack('<ii', 0, 0) + _ua_string(None) + _ua_string(None) + struct.pack('<I', 0))
    token = _ua_string('username-policy') + _ua_string('user1') + _ua_string(b's3cret') + _ua_string(None)
    activate = _ua_msg(467, 3, _ua_request_header(3) + _ua_string(None) + _ua_string(None) + struct.pack('<ii', 0, 0)
                       + _ua_node(0, 324) + b'\x01' + struct.pack('<i', len(token)) + token
                       + _ua_string(None) + _ua_string(None))
    activate_response = _ua_msg(470, 3, _ua_response_header(3) + _ua_string(None) + struct.pack('<ii', 0, 0))
    write = _ua_msg(673, 4, _ua_request_header(4) + struct.pack('<i', 1) + _ua_node(1, 'the.answer')
                    + struct.pack('<I', 13) + _ua_string(None) + b'\x01' + b'\x06' + struct.pack('<i', 42))
    write_response = _ua_msg(676, 4, _ua_response_header(4) + struct.pack('<iI', 1, 0) + struct.pack('<i', 0))
    call = _ua_msg(712, 5, _ua_request_header(5) + struct.pack('<i', 1) + _ua_node(0, 85) + _ua_node(1, 62541)
                   + struct.pack('<i', 1) + b'\x0c' + _ua_string('Hello'))
    call_response = _ua_msg(715, 5, _ua_response_header(5) + struct.pack('<i', 1) + struct.pack('<I', 0x80340000)
                            + struct.pack('<iii', -1, -1, -1) + struct.pack('<i', -1))
    read = _ua_msg(631, 6, _ua_request_header(6) + struct.pack('<dI', 0.0, 0) + struct.pack('<i', 1)
                   + _ua_node(1, 'the.answer') + struct.pack('<I', 13) + _ua_string(None) + struct.pack('<H', 0)
                   + _ua_string(None))
    read_response = _ua_msg(634, 6, _ua_response_header(6) + struct.pack('<i', 1) + b'\x01' + b'\x06'
                            + struct.pack('<i', 42) + struct.pack('<i', 0))
    publish = _ua_msg(826, 7, _ua_request_header(7) + struct.pack('<i', 0))
    fault = _ua_msg(397, 7, _ua_response_header(7, 0x80790000))
    close = _ua_msg(473, 8, _ua_request_header(8) + b'\x01')
    close_response = _ua_msg(476, 8, _ua_response_header(8))
    segments = [(True, hello), (False, ack), (True, open_request), (False, open_response), (True, create),
                (False, create_response), (True, activate), (False, activate_response), (True, write),
                (False, write_response), (True, call), (False, call_response), (True, read), (False, read_response),
                (True, publish), (False, fault), (True, close), (False, close_response)]
    return tcp_segments(CLIENT, OPCUA_SERVER, 48400, 4840, segments)


def write_opcua_pcap(path):
    write_pcap(path, opcua_packets())


# ---------------------------------------------------------------- GOOSE
#
# One relay (GOOSE_PUBLISHER) publishing control block LD0/LLN0$GO$gcb1:
# state 1 sent three times (heartbeat), state 2 with its trip value turned
# true, then stNum jumping to 10 and falling back to 1 - what a forged
# publisher looks like next to the real one.

GOOSE_PUBLISHER = '00:30:a7:00:00:01'
_GOOSE_DEST = bytes.fromhex('010ccd010001')


def _ber(tag, value):
    return bytes([tag, len(value)]) + value


def _goose(stnum, sqnum, trip):
    data = _ber(0x83, b'\x01' if trip else b'\x00') + _ber(0x84, b'\x06\x40') + _ber(0x85, b'\x07')
    pdu = (_ber(0x80, b'IED1LD0/LLN0$GO$gcb1') + _ber(0x81, b'\x07\xd0') + _ber(0x82, b'IED1LD0/LLN0$Trips')
           + _ber(0x83, b'Trips') + _ber(0x84, b'\x65\x53\xf1\x00\x00\x00\x00\x0a')
           + _ber(0x85, bytes([stnum])) + _ber(0x86, bytes([sqnum])) + _ber(0x87, b'\x00')
           + _ber(0x88, b'\x01') + _ber(0x89, b'\x00') + _ber(0x8a, b'\x03') + _ber(0xab, data))
    apdu = _ber(0x61, pdu)
    header = struct.pack('!HHHH', 0x0001, 8 + len(apdu), 0, 0)
    return _GOOSE_DEST + bytes.fromhex(GOOSE_PUBLISHER.replace(':', '')) + struct.pack('!H', 0x88b8) + header + apdu


def goose_packets():
    return [_goose(1, 0, False), _goose(1, 1, False), _goose(1, 2, False), _goose(2, 0, True),
            _goose(10, 0, True), _goose(1, 0, False)]


def write_goose_pcap(path):
    write_pcap(path, goose_packets())


# ---------------------------------------------------------------- Windows Browser
#
# NetBIOS datagrams to UDP 138 in workgroup/domain FIXTUREDOM: a workstation
# (BROWSER_WORKSTATION, WS1) announcing itself twice, a domain controller
# (BROWSER_DC, DC1) as local master browser, WS1 calling an election, and
# WS1 asking for announcements.

BROWSER_WORKSTATION, BROWSER_DC = '10.1.0.31', '10.1.0.32'
_BROWSER_BROADCAST = '10.1.255.255'


def _browser_datagram(src, source_name, payload, dgram_id):
    name = b'\\MAILSLOT\\BROWSE\x00'
    data_offset = 32 + 1 + 34 + 2 + len(name)
    words = struct.pack('<HHHHBBHIHHHHHBB', 0, len(payload), 0, 0, 0, 0, 0, 0, 0, 0, 0, len(payload), data_offset,
                        3, 0) + struct.pack('<HHH', 1, 1, 2)
    smb = b'\xffSMB\x25' + b'\x00' * 27 + bytes([len(words) // 2]) + words \
        + struct.pack('<H', len(name) + len(payload)) + name + payload
    body = _nbns_name(source_name, 0x00) + _nbns_name('FIXTUREDOM', 0x1d) + smb
    header = struct.pack('!BBH4sHHH', 0x11, 0x02, dgram_id, socket.inet_aton(src), 138, len(body), 0)
    return _udp_packet(src, _BROWSER_BROADCAST, 138, 138, header + body)


def _announcement(command, name, server_type, comment):
    return (bytes([command, 1]) + struct.pack('<I', 720000) + name.encode().ljust(16, b'\x00')
            + bytes([10, 0]) + struct.pack('<I', server_type) + bytes([15, 1]) + struct.pack('<H', 0xaa55)
            + comment.encode() + b'\x00')


def browser_packets():
    workstation = _announcement(0x01, 'WS1', 0x1003, 'Accounting PC')            # workstation, server, NT workstation
    master = _announcement(0x0f, 'DC1', 0x4802b, '')                            # ... domain controller, master browser
    election = bytes([0x08, 1]) + struct.pack('<III', 0x20010f03, 60000, 0) + b'WS1\x00'
    request = bytes([0x02, 0]) + b'WS1\x00'
    return [_browser_datagram(BROWSER_WORKSTATION, 'WS1', workstation, 1),
            _browser_datagram(BROWSER_WORKSTATION, 'WS1', workstation, 2),
            _browser_datagram(BROWSER_DC, 'DC1', master, 3),
            _browser_datagram(BROWSER_WORKSTATION, 'WS1', election, 4),
            _browser_datagram(BROWSER_WORKSTATION, 'WS1', request, 5)]


def write_browser_pcap(path):
    write_pcap(path, browser_packets())


# ---------------------------------------------------------------- LLDP and CDP
#
# A switch (NEIGHBOR_SWITCH) announcing its port Gi1/0/1 by LLDP twice and
# by CDP once, and a PLC (NEIGHBOR_PLC) announcing itself by LLDP - with
# a locally assigned chassis ID (its station name) and LLDP-MED inventory
# - then shutting its port down (time to live 0).

NEIGHBOR_SWITCH, NEIGHBOR_PLC = '00:1b:21:00:00:01', '00:1b:21:00:00:02'


def _mac(text):
    return bytes.fromhex(text.replace(':', ''))


def _lldp_tlv(kind, value):
    return struct.pack('!H', kind << 9 | len(value)) + value


def _lldp(src, tlvs):
    return _mac('01:80:c2:00:00:0e') + _mac(src) + struct.pack('!H', 0x88cc) + b''.join(tlvs) + _lldp_tlv(0, b'')


def _lldp_switch():
    return _lldp(NEIGHBOR_SWITCH, [
        _lldp_tlv(1, b'\x04' + _mac(NEIGHBOR_SWITCH)), _lldp_tlv(2, b'\x05Gi1/0/1'), _lldp_tlv(3, b'\x00\x78'),
        _lldp_tlv(4, b'Uplink to plant floor'), _lldp_tlv(5, b'sw1.example'),
        _lldp_tlv(6, b'Fixture Switch OS 1.0\nBuilt 2026-01-01'),
        _lldp_tlv(7, struct.pack('!HH', 0x14, 0x14)),                                 # bridge, router
        _lldp_tlv(8, b'\x05\x01' + socket.inet_aton('10.1.0.1') + b'\x02\x00\x00\x00\x01\x00'),
        _lldp_tlv(127, b'\x00\x80\xc2\x01' + struct.pack('!H', 10))])                 # port VLAN 10


def _lldp_plc(ttl):
    med = [_lldp_tlv(127, b'\x00\x12\xbb' + bytes([subtype]) + text) for subtype, text in
           ((5, b'HW 3'), (6, b'FW 2.1'), (8, b'SN-0042'), (9, b'Fixture Automation'), (10, b'PLC-100'))]
    return _lldp(NEIGHBOR_PLC, [
        _lldp_tlv(1, b'\x07plc-1   line 2'), _lldp_tlv(2, b'\x07port-001'), _lldp_tlv(3, struct.pack('!H', ttl)),
        _lldp_tlv(7, struct.pack('!HH', 0x80, 0x80))] + med)                          # station only


def _cdp_tlv(kind, value):
    return struct.pack('!HH', kind, 4 + len(value)) + value


def _cdp_switch():
    address = struct.pack('!I', 1) + b'\x01\x01\xcc' + struct.pack('!H', 4) + socket.inet_aton('10.1.0.1')
    tlvs = (_cdp_tlv(1, b'sw1') + _cdp_tlv(5, b'Fixture IOS 15.2') + _cdp_tlv(6, b'cisco WS-C2960-24TT')
            + _cdp_tlv(2, address) + _cdp_tlv(3, b'GigabitEthernet1/0/1') + _cdp_tlv(4, struct.pack('!I', 0x28))
            + _cdp_tlv(9, b'PLANT') + _cdp_tlv(0x0a, struct.pack('!H', 10)) + _cdp_tlv(0x0b, b'\x01'))
    header = bytes([2, 180]) + b'\x00\x00' + tlvs
    cdp = header[:2] + struct.pack('!H', _checksum(header)) + header[4:]
    llc = b'\xaa\xaa\x03\x00\x00\x0c\x20\x00' + cdp
    return _mac('01:00:0c:cc:cc:cc') + _mac(NEIGHBOR_SWITCH) + struct.pack('!H', len(llc)) + llc


def neighbor_packets():
    return [_lldp_switch(), _lldp_plc(20), _cdp_switch(), _lldp_switch(), _lldp_plc(0)]


def write_neighbor_pcap(path):
    write_pcap(path, neighbor_packets())
