#!/usr/bin/env python3
"""SHAR-CRATES per-protocol records: turning tshark's packet-by-packet
fields into one record per request/response transaction, in the same
layout Suricata's eve.json uses for that protocol - so the UI's existing
columns for dns/http/tls/modbus read SHAR-CRATES records unchanged, and
the two views can be compared field by field.

Each protocol is a class listing the tshark fields it needs (appended to
shark_analyzer's single tshark run) with feed(), called for every packet
that has any of them, and finish(), which returns its records once the
capture has been read. Requests are paired with their responses as the
packets stream past - by tshark's own back-reference from a response to
its request's frame where it has one, otherwise by the flow and the
protocol's transaction ID - so tshark never needs its slower two-pass
mode. A request that never got a response is still a record.

Records come back as (flow, when, event_type, body); shark_analyzer adds
the addresses, ports and Community ID from the flow, oriented client to
server like its flow records.
"""


def _first(values, default=''):
    return values[0] if values else default


def _int(value, default=None):
    """tshark's decimal or 0x-prefixed hex integer, or default."""
    try:
        return int(value, 16) if str(value).lower().startswith('0x') else int(value)
    except (TypeError, ValueError):
        return default


def ipv6_exploded(address):
    from shark_analyzer import ipv6_exploded as explode   # shark_analyzer imports this module
    return explode(address)


class Packet:
    """What a protocol needs to know about the packet it's fed: its frame
    number, time, flow (shark_analyzer._Flow) and ports."""
    __slots__ = ('frame', 'when', 'flow', 'sport', 'dport')

    def __init__(self, frame, when, flow, sport, dport):
        self.frame, self.when, self.flow, self.sport, self.dport = frame, when, flow, sport, dport


# ---------------------------------------------------------------- DNS

_DNS_TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
              33: 'SRV', 35: 'NAPTR', 39: 'DNAME', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY',
              52: 'TLSA', 64: 'SVCB', 65: 'HTTPS', 99: 'SPF', 252: 'AXFR', 255: 'ANY', 257: 'CAA'}
_DNS_RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED',
               6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE'}
# Answer type -> the tshark field holding its data. Each list holds every
# record of that type in the message, answers first, so answers take
# values from the front.
_DNS_RDATA = {'A': 'dns.a', 'AAAA': 'dns.aaaa', 'CNAME': 'dns.cname', 'NS': 'dns.ns',
              'PTR': 'dns.ptr.domain_name', 'MX': 'dns.mx.mail_exchange', 'TXT': 'dns.txt'}


def _dns_type(value):
    number = _int(value)
    return _DNS_TYPES.get(number, f'TYPE{number}') if number is not None else ''


class DNS:
    event_type = 'dns'
    fields = ('dns.id', 'dns.flags.response', 'dns.qry.name', 'dns.qry.type', 'dns.flags.rcode',
              'dns.count.answers', 'dns.resp.name', 'dns.resp.type', 'dns.resp.ttl',
              'dns.response_to') + tuple(_DNS_RDATA.values())

    def __init__(self):
        self.records = []        # (flow, when, body), in request order
        self.pending = {}        # request frame number -> its body

    def feed(self, pkt, v):
        txid = _int(_first(v['dns.id']))
        if txid is None:
            return
        queries = [{'rrname': name, 'rrtype': _dns_type(qtype)}
                   for name, qtype in zip(v['dns.qry.name'], v['dns.qry.type'])]
        if _first(v['dns.flags.response']) not in ('True', '1'):
            body = {'version': 3, 'type': 'request', 'id': txid, 'queries': queries}
            self.pending[pkt.frame] = body
            self.records.append((pkt.flow, pkt.when, body))
            return
        rdata = {rtype: list(v[field]) for rtype, field in _DNS_RDATA.items()}
        count = _int(_first(v['dns.count.answers']), 0)
        answers = []
        for name, rtype, ttl in list(zip(v['dns.resp.name'], v['dns.resp.type'], v['dns.resp.ttl']))[:count]:
            rtype = _dns_type(rtype)
            answer = {'rrname': name, 'rrtype': rtype, 'ttl': _int(ttl, 0)}
            if rdata.get(rtype):
                answer['rdata'] = rdata[rtype].pop(0)
                if rtype == 'AAAA':
                    answer['rdata'] = ipv6_exploded(answer['rdata'])
            answers.append(answer)
        body = self.pending.pop(_int(_first(v['dns.response_to'])), None)
        if body is None:   # a response whose request isn't in the capture
            body = {'version': 3, 'id': txid, 'queries': queries}
            self.records.append((pkt.flow, pkt.when, body))
        body['type'] = 'response'
        body['rcode'] = _DNS_RCODES.get(_int(_first(v['dns.flags.rcode']), 0), _first(v['dns.flags.rcode']))
        if answers:
            body['answers'] = answers

    def finish(self):
        return [(flow, when, self.event_type, body) for flow, when, body in self.records]


# ---------------------------------------------------------------- HTTP

class HTTP:
    event_type = 'http'
    fields = ('http.request.method', 'http.request.uri', 'http.request.version', 'http.host',
              'http.user_agent', 'http.referer', 'http.response.code', 'http.content_type',
              'http.content_length', 'http.request_in')

    def __init__(self):
        self.records = []
        self.pending = {}        # request frame number -> bodies of the requests it carried

    def feed(self, pkt, v):
        def at(field, i):
            values = v[field]
            return values[i] if i < len(values) else ''
        for i, method in enumerate(v['http.request.method']):
            # Like Suricata, a header the request didn't send is left out.
            body = {name: at(field, i) for name, field in (
                ('hostname', 'http.host'), ('url', 'http.request.uri'), ('http_user_agent', 'http.user_agent'),
                ('http_refer', 'http.referer'), ('protocol', 'http.request.version')) if at(field, i)}
            body['http_method'] = method
            self.pending.setdefault(pkt.frame, []).append(body)
            self.records.append((pkt.flow, pkt.when, body))
        for i, code in enumerate(v['http.response.code']):
            waiting = self.pending.get(_int(at('http.request_in', i)))
            if waiting:
                body = waiting.pop(0)
            else:   # a response whose request isn't in the capture
                body = {}
                self.records.append((pkt.flow, pkt.when, body))
            body['status'] = _int(code, code)
            # Request and response both carry a Content-Type; a response
            # packet's is the response's, which is the one Suricata logs.
            # Suricata logs the media type alone ('text/plain; charset=utf-8' ->
            # 'text/plain').
            if not v['http.request.method'] and at('http.content_type', i):
                body['http_content_type'] = at('http.content_type', i).split(';')[0].strip()
            length = _int(at('http.content_length', i))
            if length is not None:
                body['length'] = length

    def finish(self):
        return [(flow, when, self.event_type, body) for flow, when, body in self.records]


# ---------------------------------------------------------------- TLS

_TLS_VERSIONS = {0x0300: 'SSLv3', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'}


def _tls_version(value):
    number = _int(value)
    return _TLS_VERSIONS.get(number, value) if number is not None else ''


class TLS:
    """One record per TLS session (flow): the ClientHello's SNI, JA3, JA4
    and ALPNs, and the ServerHello's negotiated version and JA3S."""
    event_type = 'tls'
    fields = ('tls.handshake.type', 'tls.handshake.extensions_server_name', 'tls.handshake.version',
              'tls.handshake.extensions.supported_version', 'tls.handshake.ja3', 'tls.handshake.ja3_full',
              'tls.handshake.ja3s', 'tls.handshake.ja3s_full', 'tls.handshake.ja4',
              'tls.handshake.extensions_alpn_str')

    def __init__(self):
        self.sessions = {}       # flow key -> (flow, when, body)

    def _session(self, pkt):
        if pkt.flow.key not in self.sessions:
            self.sessions[pkt.flow.key] = (pkt.flow, pkt.when, {})
        return self.sessions[pkt.flow.key][2]

    def feed(self, pkt, v):
        types = v['tls.handshake.type']
        if '1' in types:   # ClientHello
            body = self._session(pkt)
            if v['tls.handshake.extensions_server_name']:
                body['sni'] = v['tls.handshake.extensions_server_name'][0]
            if v['tls.handshake.ja3']:
                body['ja3'] = {'hash': v['tls.handshake.ja3'][0], 'string': _first(v['tls.handshake.ja3_full'])}
            if v['tls.handshake.ja4']:
                body['ja4'] = v['tls.handshake.ja4'][0]
            if v['tls.handshake.extensions_alpn_str']:
                body['client_alpns'] = list(v['tls.handshake.extensions_alpn_str'])
        if '2' in types:   # ServerHello: TLS 1.3 names its version in supported_versions
            body = self._session(pkt)
            version = _first(v['tls.handshake.extensions.supported_version']) or _first(v['tls.handshake.version'])
            if version:
                body['version'] = _tls_version(version)
            if v['tls.handshake.ja3s']:
                body['ja3s'] = {'hash': v['tls.handshake.ja3s'][0], 'string': _first(v['tls.handshake.ja3s_full'])}

    def finish(self):
        return [(flow, when, self.event_type, body) for flow, when, body in self.sessions.values() if body]


# ---------------------------------------------------------------- Modbus/TCP

# Function code -> (Suricata's name, access type). Suricata's category is
# PUBLIC_ASSIGNED for these.
_MODBUS_FUNCTIONS = {
    1: ('RdCoils', 'READ | COILS'), 2: ('RdDiscreteInputs', 'READ | DISCRETES'),
    3: ('RdHoldRegs', 'READ | HOLDING'), 4: ('RdInputRegs', 'READ | INPUT'),
    5: ('WrSingleCoil', 'WRITE | COILS | SINGLE | WRITE_SINGLE'),
    6: ('WrSingleReg', 'WRITE | HOLDING | SINGLE | WRITE_SINGLE'),
    7: ('RdExcStatus', ''), 8: ('Diagnostic', ''), 11: ('GetCommEventCtr', ''), 12: ('GetCommEventLog', ''),
    15: ('WrMultCoils', 'WRITE | COILS | MULTIPLE | WRITE_MULTIPLE'),
    16: ('WrMultRegs', 'WRITE | HOLDING | MULTIPLE | WRITE_MULTIPLE'),
    17: ('ReportServerID', ''), 20: ('RdFileRec', ''), 21: ('WrFileRec', ''), 22: ('MaskWrReg', ''),
    23: ('RdWrMultRegs', ''), 24: ('RdFIFOQueue', ''), 43: ('MEI', ''),
}
_MODBUS_EXCEPTIONS = {1: 'IllegalFunction', 2: 'IllegalDataAddr', 3: 'IllegalDataValue', 4: 'ServerDeviceFail',
                      5: 'Ack', 6: 'ServerDeviceBusy', 7: 'NegAck', 8: 'MemParityErr',
                      10: 'GatewayPathUnavailable', 11: 'GatewayTargetFailToResp'}
MODBUS_PORT = 502


def _modbus_category(code):
    if code in _MODBUS_FUNCTIONS:
        return 'PUBLIC_ASSIGNED'
    if 65 <= code <= 72 or 100 <= code <= 110:
        return 'USER_DEFINED'
    return 'RESERVED'


class Modbus:
    event_type = 'modbus'
    fields = ('mbtcp.trans_id', 'mbtcp.prot_id', 'mbtcp.unit_id', 'modbus.func_code', 'modbus.request_frame',
              'modbus.exception_code', 'modbus.reference_num', 'modbus.word_cnt', 'modbus.bit_cnt',
              'modbus.regval_uint16')

    def __init__(self):
        self.records = []
        self.pending = {}        # (flow key, transaction id) -> body awaiting its response

    def feed(self, pkt, v):
        txid = _int(_first(v['mbtcp.trans_id']))
        code = _int(_first(v['modbus.func_code']))
        if txid is None or code is None:
            return
        name, access = _MODBUS_FUNCTIONS.get(code, (f'Function{code}', ''))
        side = {'transaction_id': txid, 'protocol_id': _int(_first(v['mbtcp.prot_id']), 0),
                'unit_id': _int(_first(v['mbtcp.unit_id']), 0), 'function_raw': code,
                'function_code': name, 'category': _modbus_category(code)}
        if access:
            side['access_type'] = access
        address = _int(_first(v['modbus.reference_num']))
        quantity = _int(_first(v['modbus.word_cnt'])) or _int(_first(v['modbus.bit_cnt']))
        values = [_int(r, r) for r in v['modbus.regval_uint16']]
        exception = _int(_first(v['modbus.exception_code']))
        # Requests go to the Modbus port; tshark marks every response but
        # an exception with the frame of its request.
        is_request = pkt.dport == MODBUS_PORT and not v['modbus.request_frame'] and exception is None
        key = (pkt.flow.key, txid)
        if is_request:
            if code in (1, 2, 3, 4):
                side['read'] = {'address': address, 'quantity': quantity}
            elif code in (5, 6):
                side['write'] = {'address': address, 'data': values[0] if values else None}
            elif code in (15, 16):
                side['write'] = {'address': address, 'quantity': quantity}
            body = {'id': txid, 'request': side}
            self.pending[key] = body
            self.records.append((pkt.flow, pkt.when, body))
            return
        if exception is not None:
            side['function_raw'] = code | 0x80
            side['exception'] = {'raw': exception, 'code': _MODBUS_EXCEPTIONS.get(exception, f'Exception{exception}')}
        elif code in (3, 4, 23) and values:
            side['read'] = {'values': values}
        elif code in (5, 6, 15, 16):
            side['write'] = {'address': address, 'data': values[0] if values else quantity}
        body = self.pending.pop(key, None)
        if body is None:   # a response whose request isn't in the capture
            body = {'id': txid}
            self.records.append((pkt.flow, pkt.when, body))
        body['response'] = side

    def finish(self):
        return [(flow, when, self.event_type, body) for flow, when, body in self.records]


# Every protocol SHAR-CRATES builds records for, in the order their fields
# follow the base fields in tshark's output.
PROTOCOLS = (DNS, HTTP, TLS, Modbus)
