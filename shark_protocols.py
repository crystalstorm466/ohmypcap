#!/usr/bin/env python3
"""SHAR-CRATES per-protocol records: turning tshark's packet-by-packet
fields into one record per request/response transaction, in the same
layout Suricata's eve.json uses for that protocol - so the UI's existing
columns for dns/http/tls/modbus/ftp read SHAR-CRATES records unchanged, and
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

import re


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
    number, time, flow (shark_analyzer._Flow), addresses and ports, and
    application protocol (shark_analyzer.app_protocol - 'dns', 'mdns'...)."""
    __slots__ = ('frame', 'when', 'flow', 'sport', 'dport', 'app', 'src', 'dst')

    def __init__(self, frame, when, flow, sport, dport, app='', src='', dst=''):
        self.frame, self.when, self.flow, self.sport, self.dport = frame, when, flow, sport, dport
        self.app, self.src, self.dst = app, src, dst


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
    """DNS and the two protocols tshark decodes with its DNS dissector:
    mDNS and LLMNR (same message format, dns.* fields). DNS and LLMNR get
    a record per query, its response merged in; mDNS - multicast, where
    any number of hosts may answer - a record per message, as Suricata
    logs it (its 'mdns' type, with lowercase record types)."""
    event_type = 'dns'
    app_protos = ('dns', 'mdns', 'llmnr')      # flow app_proto values whose transactions these records are
    fields = ('dns.id', 'dns.flags.response', 'dns.flags.opcode', 'dns.qry.name', 'dns.qry.type', 'dns.flags.rcode',
              'dns.count.answers', 'dns.resp.name', 'dns.resp.type', 'dns.resp.ttl',
              'dns.response_to') + tuple(_DNS_RDATA.values())

    def __init__(self):
        self.records = []        # (flow, when, event_type, body), in request order
        self.by_frame = {}       # request frame number -> its body
        self.unanswered = {}     # (asker's address, port, id, first query) -> body, until its response
        self.answered = {}       # the same keys, once answered -> body

    def feed(self, pkt, v):
        txid = _int(_first(v['dns.id']))
        if txid is None:
            return
        kind = pkt.app if pkt.app in ('mdns', 'llmnr') else 'dns'
        lower = kind == 'mdns'
        queries = [{'rrname': name, 'rrtype': _dns_type(qtype).lower() if lower else _dns_type(qtype)}
                   for name, qtype in zip(v['dns.qry.name'], v['dns.qry.type'])]
        is_response = _first(v['dns.flags.response']) in ('True', '1')
        if kind == 'mdns':
            body = {'type': 'response' if is_response else 'request', 'id': txid,
                    'opcode': _int(_first(v['dns.flags.opcode']), 0),
                    'rcode': _int(_first(v['dns.flags.rcode']), 0), 'queries': queries}
            # Suricata's mDNS answers name their data by its record type:
            # {'rrname': ..., 'ptr': ...} - no rrtype or ttl keys.
            answers = [{'rrname': a['rrname'], a['rrtype']: a.get('rdata', '')}
                       for a in self._answers(v, lower=True)]
            if answers:
                body['answers'] = answers
            if queries or answers:   # an empty message (a scanner's probe) says nothing
                self.records.append((pkt.flow, pkt.when, 'mdns', body))
            return
        if not is_response:
            # A retransmission - the same question, same ID, sent again while
            # still unanswered - is the same transaction. (The same ID and
            # question after an answer is a new one.)
            key = self._key(pkt.src, pkt.sport, txid, queries)
            body = self.unanswered.get(key)
            if body is None:
                body = self.unanswered[key] = {'version': 3, 'type': 'request', 'id': txid, 'queries': queries}
                self.records.append((pkt.flow, pkt.when, kind, body))
            else:
                body['transmissions'] = body.get('transmissions', 1) + 1
            self.by_frame[pkt.frame] = body
            return
        answers = self._answers(v)
        # The response goes back to whoever asked. tshark links a response
        # to its query only within one conversation, and only the first
        # response - so a multicast LLMNR query's unicast answer, or a
        # repeat of an answered query's response, arrives unlinked.
        key = self._key(pkt.dst, pkt.dport, txid, queries)
        body = self.by_frame.get(_int(_first(v['dns.response_to']))) or self.unanswered.get(key) \
            or self.answered.get(key)
        if body is not None and body['type'] == 'response':
            # The answer again: counted, not a new record. More than one
            # response to a query can mean an attacker racing the real server.
            body['responses'] = body.get('responses', 1) + 1
            return
        if body is None:   # a response whose request isn't in the capture
            body = {'version': 3, 'id': txid, 'queries': queries}
            self.records.append((pkt.flow, pkt.when, kind, body))
        else:
            self.unanswered = {k: b for k, b in self.unanswered.items() if b is not body}
        self.answered[key] = body
        body['type'] = 'response'
        body['rcode'] = _DNS_RCODES.get(_int(_first(v['dns.flags.rcode']), 0), _first(v['dns.flags.rcode']))
        if answers:
            body['answers'] = answers

    @staticmethod
    def _key(asker, asker_port, txid, queries):
        return (asker, asker_port, txid, (queries[0]['rrname'], queries[0]['rrtype']) if queries else None)

    @staticmethod
    def _answers(v, lower=False):
        rdata = {rtype: list(v[field]) for rtype, field in _DNS_RDATA.items()}
        count = _int(_first(v['dns.count.answers']), 0)
        answers = []
        for name, rtype, ttl in list(zip(v['dns.resp.name'], v['dns.resp.type'], v['dns.resp.ttl']))[:count]:
            rtype = _dns_type(rtype)
            answer = {'rrname': name, 'rrtype': rtype.lower() if lower else rtype, 'ttl': _int(ttl, 0)}
            if rdata.get(rtype):
                answer['rdata'] = rdata[rtype].pop(0)
                if rtype == 'AAAA':
                    answer['rdata'] = ipv6_exploded(answer['rdata'])
            answers.append(answer)
        return answers

    def finish(self):
        return self.records


# ---------------------------------------------------------------- HTTP

def _host_without_port(host):
    """'example.com:8080' -> 'example.com', '[2001:db8::1]:80' -> '2001:db8::1'."""
    if host.startswith('['):
        return host[1:host.index(']')] if ']' in host else host
    name, sep, port = host.rpartition(':')
    return name if sep and port.isdigit() and ':' not in name else host


class HTTP:
    event_type = 'http'
    app_protos = ('http',)      # flow app_proto values whose transactions these records are
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
            if 'hostname' in body:   # Suricata logs the Host header's name without its port
                body['hostname'] = _host_without_port(body['hostname'])
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

# Suricata's names for them (TLS 1.0 is 'TLSv1')
_TLS_VERSIONS = {0x0002: 'SSLv2', 0x0300: 'SSLv3', 0x0301: 'TLSv1', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2',
                 0x0304: 'TLS 1.3'}


def _tls_version(value):
    number = _int(value)
    return _TLS_VERSIONS.get(number, value) if number is not None else ''


class TLS:
    """One record per TLS session (flow): the ClientHello's SNI, JA3, JA4
    and ALPNs, and the ServerHello's negotiated version and JA3S. QUIC
    carries the same TLS handshake (tshark decodes it from QUIC's Initial
    packets), so a QUIC connection gets the same record as Suricata's
    'quic' type, with the QUIC version."""
    event_type = 'tls'
    app_protos = ('tls', 'quic')
    fields = ('quic.version', 'tls.handshake.type', 'tls.handshake.extensions_server_name', 'tls.handshake.version',
              'tls.handshake.extensions.supported_version', 'tls.handshake.ja3', 'tls.handshake.ja3_full',
              'tls.handshake.ja3s', 'tls.handshake.ja3s_full', 'tls.handshake.ja4',
              'tls.handshake.extensions_alpn_str')

    def __init__(self):
        self.sessions = {}       # flow key -> (flow, when, body)

    def _session(self, pkt):
        if pkt.flow.key not in self.sessions:
            kind = 'quic' if pkt.app == 'quic' else 'tls'
            self.sessions[pkt.flow.key] = (pkt.flow, pkt.when, kind, {})
        return self.sessions[pkt.flow.key][3]

    def feed(self, pkt, v):
        if pkt.app == 'quic' and v['quic.version']:
            # Suricata's form: '1' for QUIC v1, any other version in hex
            version = _int(v['quic.version'][0])
            self._session(pkt).setdefault('version', '1' if version == 1 else
                                          f'{version:08x}' if version is not None else v['quic.version'][0])
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
            if version and pkt.app != 'quic':   # a QUIC record's version is QUIC's
                body['version'] = _tls_version(version)
            if v['tls.handshake.ja3s']:
                body['ja3s'] = {'hash': v['tls.handshake.ja3s'][0], 'string': _first(v['tls.handshake.ja3s_full'])}

    def finish(self):
        return [(flow, when, kind, body) for flow, when, kind, body in self.sessions.values() if body]


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
    23: ('RdWrMultRegs', 'READ | WRITE | HOLDING | MULTIPLE | WRITE_MULTIPLE'), 24: ('RdFIFOQueue', ''), 43: ('MEI', ''),
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
    app_protos = ('modbus',)      # flow app_proto values whose transactions these records are
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
        side['access_type'] = access or 'NONE'   # as Suricata says for a function with no data access
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


# ---------------------------------------------------------------- FTP

class FTP:
    """Suricata's two FTP record types: 'ftp', one per command on a
    control connection with every reply it got (a STOR's 150 and its 226),
    plus one for the server's greeting before any command; and 'ftp_data',
    one per data connection, with the command that opened it and its file."""
    event_type = 'ftp'
    app_protos = ('ftp', 'ftp-data')
    fields = ('ftp.request.command', 'ftp.request.arg', 'ftp.response.code', 'ftp.response.arg',
              'ftp.passive.port', 'ftp.active.port', 'ftp.epsv.port', 'ftp.eprt.port', 'ftp-data.command')

    def __init__(self):
        self.records = []        # (flow, when, event_type, body)
        self.current = {}        # control flow key -> the record its replies belong to
        self.data_flows = set()  # data flow keys with an ftp_data record already

    def feed(self, pkt, v):
        key = pkt.flow.key
        if v['ftp-data.command']:
            if key not in self.data_flows:
                self.data_flows.add(key)
                command, _, filename = v['ftp-data.command'][0].partition(' ')
                body = {'command': command}
                if filename:
                    body['filename'] = filename
                self.records.append((pkt.flow, pkt.when, 'ftp_data', body))
            return
        for i, command in enumerate(v['ftp.request.command']):
            body = {'command': command}
            arg = v['ftp.request.arg'][i] if i < len(v['ftp.request.arg']) else ''
            if arg:
                body['command_data'] = arg
            if v['ftp.active.port'] or v['ftp.eprt.port']:
                body['dynamic_port'] = _int(_first(v['ftp.active.port']) or _first(v['ftp.eprt.port']))
                body['mode'] = 'active'
            self.current[key] = body
            self.records.append((pkt.flow, pkt.when, 'ftp', body))
        for i, code in enumerate(v['ftp.response.code']):
            body = self.current.get(key)
            # A command's replies end with its first final (non-1xx) one; a
            # reply after that - the greeting, a 221 as the server hangs up,
            # a reply to a command before the capture - is its own record.
            if body is None or body.get('_done'):
                body = self.current[key] = {}
                self.records.append((pkt.flow, pkt.when, 'ftp', body))
            if not code.startswith('1'):
                body['_done'] = True
            body.setdefault('completion_code', []).append(code)
            body.setdefault('reply', []).append(v['ftp.response.arg'][i] if i < len(v['ftp.response.arg']) else '')
            body['reply_received'] = 'yes'
            if v['ftp.passive.port'] or v['ftp.epsv.port']:
                body['dynamic_port'] = _int(_first(v['ftp.passive.port']) or _first(v['ftp.epsv.port']))
                body['mode'] = 'passive'

    def finish(self):
        for _, _, event_type, body in self.records:
            if event_type == 'ftp':
                body.pop('_done', None)
                body.setdefault('reply_received', 'no')
        return self.records


# ---------------------------------------------------------------- NBNS

_NBNS_OPCODES = {0: 'query', 5: 'registration', 6: 'release', 7: 'wack', 8: 'refresh',
                 15: 'multi-homed registration'}
_NBNS_RCODES = {0: 'NOERROR', 1: 'FMT_ERR', 2: 'SRV_ERR', 3: 'NAM_ERR', 4: 'IMP_ERR', 5: 'RFS_ERR',
                6: 'ACT_ERR', 7: 'CFT_ERR'}
# tshark writes a NetBIOS name as NAME<suffix>, and once as NAME<suffix> (service)
_NBNS_NAME = re.compile(r'^(.*)<([0-9A-Fa-f]{2})>(?: \((.*)\))?$')


class NBNS:
    """NetBIOS name service (Windows name resolution - Suricata doesn't
    parse it): a record per transaction - a query and its answer, or a
    name registration, refresh or release, usually broadcast and
    unanswered - with its retransmissions (same transaction ID) folded in.
    The name is split into name, its 16th-byte suffix and the service that
    suffix means (<20> is the Server service)."""
    event_type = 'nbns'
    app_protos = ('nbns',)
    fields = ('nbns.id', 'nbns.flags.response', 'nbns.flags.opcode', 'nbns.flags.rcode', 'nbns.name',
              'nbns.addr', 'nbns.ttl')

    def __init__(self):
        self.records = []
        self.open = {}           # (asker's address, transaction id) -> body

    def feed(self, pkt, v):
        txid = _int(_first(v['nbns.id']))
        if txid is None:
            return
        # A broadcast query's answer comes back directly to the asker, on
        # another flow - so a transaction is keyed by who asked.
        is_response = _first(v['nbns.flags.response']) in ('True', '1')
        key = (pkt.dst if is_response else pkt.src, txid)
        body = self.open.get(key)
        if body is None:
            opcode = _int(_first(v['nbns.flags.opcode']), 0)
            body = self.open[key] = {'type': 'request', 'id': txid,
                                     'opcode': _NBNS_OPCODES.get(opcode, f'opcode {opcode}')}
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        for raw in v['nbns.name']:
            m = _NBNS_NAME.match(raw)
            if m:
                body.setdefault('name', m.group(1).rstrip())
                body.setdefault('suffix', m.group(2).upper())
                if m.group(3):
                    body.setdefault('service', m.group(3))
            else:
                body.setdefault('name', raw)
        if v['nbns.addr']:
            body['address'] = v['nbns.addr'][0]
        if v['nbns.ttl']:
            body['ttl'] = _int(v['nbns.ttl'][0], 0)
        if is_response:
            body['type'] = 'response'
            rcode = _int(_first(v['nbns.flags.rcode']), 0)
            body['rcode'] = _NBNS_RCODES.get(rcode, str(rcode))
        else:
            body['transmissions'] = body.get('transmissions', 0) + 1

    def finish(self):
        return self.records


# ---------------------------------------------------------------- SSDP

class SSDP:
    """SSDP (UPnP discovery - Suricata doesn't parse it): a record per
    message - an M-SEARCH looking for devices or services, a NOTIFY
    announcing one, or a search response - with its search target or
    notification type, the device's description URL (LOCATION) and server
    string, and its unique service name. tshark decodes SSDP with its HTTP
    dissector: a header is an http.request.line / http.response.line, or -
    in a NOTIFY - http.location or an http.unknown_header."""
    event_type = 'ssdp'
    app_protos = ('ssdp',)
    fields = ('http.request.method', 'http.response.code', 'http.request.line', 'http.response.line',
              'http.unknown_header', 'http.location')
    _HEADERS = {'ST': 'search_target', 'NT': 'notification_type', 'NTS': 'notification_sub_type',
                'USN': 'usn', 'MAN': 'man', 'MX': 'mx', 'LOCATION': 'location', 'SERVER': 'server',
                'USER-AGENT': 'user_agent'}

    def __init__(self):
        self.records = []

    def feed(self, pkt, v):
        if v['http.request.method']:
            body = {'type': 'request', 'method': v['http.request.method'][0]}
        elif v['http.response.code']:
            body = {'type': 'response', 'status': _int(v['http.response.code'][0], v['http.response.code'][0])}
        else:
            return
        if v['http.location']:
            body['location'] = v['http.location'][0]
        for line in v['http.request.line'] + v['http.response.line'] + v['http.unknown_header']:
            name, sep, value = line.partition(':')
            key = self._HEADERS.get(name.strip().upper())
            if sep and key and key not in body:
                # an unknown header keeps its line ending as the text \r\n
                body[key] = value.strip().removesuffix('\\r\\n').strip()
        self.records.append((pkt.flow, pkt.when, self.event_type, body))

    def finish(self):
        return self.records


# ---------------------------------------------------------------- S7comm

_S7_ROSCTR = {1: 'job', 2: 'ack', 3: 'ack_data', 7: 'userdata'}
_S7_FUNCTIONS = {0x00: 'CPU services', 0x04: 'Read Var', 0x05: 'Write Var', 0x1a: 'Request download',
                 0x1b: 'Download block', 0x1c: 'Download ended', 0x1d: 'Start upload', 0x1e: 'Upload',
                 0x1f: 'End upload', 0x28: 'PLC Control', 0x29: 'PLC Stop', 0xf0: 'Setup communication'}
_S7_AREAS = {0x03: 'System info', 0x05: 'System flags', 0x06: 'Analog inputs', 0x07: 'Analog outputs',
             0x1c: 'Counter', 0x1d: 'Timer', 0x1e: 'IEC counter', 0x1f: 'IEC timer', 0x80: 'Direct peripheral',
             0x81: 'Inputs', 0x82: 'Outputs', 0x83: 'Flags', 0x84: 'Data blocks', 0x85: 'Instance DB',
             0x86: 'Local data'}
# S7-1200/1500 symbolic addressing (syntax ID 0xb2) names its area differently
_S7_SYMBOLIC_AREAS = {0x50: 'Inputs', 0x51: 'Outputs', 0x52: 'Flags', 0x53: 'Counter', 0x54: 'Timer'}
_S7_SYMBOLIC_DB_AREA = 0x8a0e
_S7_USERDATA_GROUPS = {0x0: 'Mode transition', 0x1: 'Programmer commands', 0x2: 'Cyclic data', 0x3: 'Block functions',
                       0x4: 'CPU functions', 0x5: 'Security', 0x6: 'PBC BSEND/BRECV', 0x7: 'Time functions',
                       0xf: 'NC programming'}
_S7_ERROR_CLASSES = {0x00: 'No error', 0x81: 'Application relationship', 0x82: 'Object definition',
                     0x83: 'No resources available', 0x84: 'Error on service processing',
                     0x85: 'Error on supplies', 0x87: 'Access error'}


class S7comm:
    """Siemens S7 (S7comm, PLC programming and data access over ISO-on-TCP -
    Suricata doesn't parse it): a record per job - Read Var, Write Var,
    Setup communication, PLC Stop, block uploads and downloads - paired
    with its acknowledgement by PDU reference, plus a record per userdata
    message (CPU functions, block functions...). A packet can carry several
    S7 PDUs; each is its own record. The variables a read or write names
    are kept when the packet carries only that one PDU: area, data block
    and byte.bit address for classic (S7-300/400) addressing; area and data
    block for S7-1200/1500 symbolic addressing."""
    event_type = 's7comm'
    app_protos = ('s7comm',)
    fields = ('s7comm.header.rosctr', 's7comm.header.pduref', 's7comm.param.func', 's7comm.header.errcls',
              's7comm.header.errcod', 's7comm.param.itemcount', 's7comm.param.item.area', 's7comm.param.item.db',
              's7comm.param.item.address.byte', 's7comm.param.item.address.bit',
              's7comm.tiap.item.area1', 's7comm.tiap.item.area2', 's7comm.tiap.item.dbnumber',
              's7comm.param.userdata.funcgroup', 's7comm.param.userdata.subfunc')

    def __init__(self):
        self.records = []
        self.jobs = {}           # (flow key, PDU reference) -> job body awaiting its ack

    def feed(self, pkt, v):
        rosctrs = v['s7comm.header.rosctr']
        single = len(rosctrs) == 1
        for i, rosctr in enumerate(rosctrs):
            def at(field):
                values = v[field]
                return values[i] if i < len(values) else ''
            kind = _S7_ROSCTR.get(_int(rosctr), f'rosctr {rosctr}')
            pduref = _int(at('s7comm.header.pduref'))
            func = _int(at('s7comm.param.func'))
            if kind == 'userdata':
                group = _int(at('s7comm.param.userdata.funcgroup'))
                body = {'type': kind, 'pdu_ref': pduref,
                        'function_group': _S7_USERDATA_GROUPS.get(group, f'group {group}'),
                        'subfunction': _int(at('s7comm.param.userdata.subfunc'))}
                self.records.append((pkt.flow, pkt.when, self.event_type, body))
                continue
            side = {}
            if func is not None:
                side['function_raw'] = func
                side['function'] = _S7_FUNCTIONS.get(func, f'function 0x{func:02x}')
            if single and _int(_first(v['s7comm.param.itemcount'])) is not None:
                side['item_count'] = _int(_first(v['s7comm.param.itemcount']))
            if single and (v['s7comm.param.item.area'] or v['s7comm.tiap.item.area1']):
                side['items'] = ([self._item(v, n) for n in range(len(v['s7comm.param.item.area']))]
                                 + [self._symbolic_item(v, n) for n in range(len(v['s7comm.tiap.item.area1']))])
            if kind == 'job':
                body = {'type': 'job', 'pdu_ref': pduref, **side}
                self.jobs[(pkt.flow.key, pduref)] = body
                self.records.append((pkt.flow, pkt.when, self.event_type, body))
                continue
            errcls = _int(at('s7comm.header.errcls'))
            if errcls:
                side['error_class'] = _S7_ERROR_CLASSES.get(errcls, f'0x{errcls:02x}')
                side['error_code'] = _int(at('s7comm.header.errcod'), 0)
            body = self.jobs.pop((pkt.flow.key, pduref), None)
            if body is None:   # an ack whose job isn't in the capture
                body = {'type': 'job', 'pdu_ref': pduref}
                self.records.append((pkt.flow, pkt.when, self.event_type, body))
            body['response'] = side

    @staticmethod
    def _item(v, n):
        def at(field):
            values = v[field]
            return values[n] if n < len(values) else ''
        area = _int(at('s7comm.param.item.area'))
        item = {'area': _S7_AREAS.get(area, f'area 0x{area:02x}' if area is not None else '')}
        db = _int(at('s7comm.param.item.db'))
        if db:
            item['db'] = db
        byte, bit = _int(at('s7comm.param.item.address.byte')), _int(at('s7comm.param.item.address.bit'))
        if byte is not None:
            item['address'] = f'{byte}.{bit or 0}'
        return item

    @staticmethod
    def _symbolic_item(v, n):
        def at(field):
            values = v[field]
            return values[n] if n < len(values) else ''
        if _int(at('s7comm.tiap.item.area1')) == _S7_SYMBOLIC_DB_AREA:
            item = {'area': 'Data blocks'}
            if _int(at('s7comm.tiap.item.dbnumber')):
                item['db'] = _int(at('s7comm.tiap.item.dbnumber'))
            return item
        area = _int(at('s7comm.tiap.item.area2'))
        return {'area': _S7_SYMBOLIC_AREAS.get(area, f'area 0x{area:04x}' if area is not None else '')}

    def finish(self):
        return self.records


# ---------------------------------------------------------------- structured protocols
#
# Protocols whose messages nest - several SMB2 commands in one packet, a
# Kerberos ticket inside an SMB session setup - can't be read from flat
# per-packet fields: a field present in only some of a packet's commands
# can't be told apart. These are read instead from a second tshark pass
# that writes each packet as a JSON tree (shark_analyzer's structured
# pass), run only over the flows that carry them. Each class lists the
# tshark dissectors it needs (tshark_protocols), the layers to keep
# (layers) and the packets to keep (display_filter); feed_json() gets each
# packet's layers.


def _flatten(tree, out=None):
    """A JSON subtree's fields: name -> every value under it, in order."""
    out = {} if out is None else out
    if isinstance(tree, dict):
        for name, value in tree.items():
            if isinstance(value, (dict, list)):
                if isinstance(value, list) and value and not isinstance(value[0], (dict, list)):
                    out.setdefault(name, []).extend(value)
                else:
                    _flatten(value, out)
            else:
                out.setdefault(name, []).append(value)
    elif isinstance(tree, list):
        for item in tree:
            _flatten(item, out)
    return out


def _pdus(layer):
    """A layer's messages - one, or a list of them (--no-duplicate-keys
    turns a packet's repeated layer into a list)."""
    if layer is None:
        return []
    return layer if isinstance(layer, list) else [layer]


def _suricata_guid(text, smb1=False):
    """A GUID the way Suricata writes one: tshark's 8-4-4-4-12 text is
    the standard mixed-endian layout, but Suricata reads the last eight
    bytes as two little-endian 16-bit words and a 32-bit one - and, for
    SMB1, the first eight as they come on the wire."""
    hexdigits = text.replace('-', '')
    if len(hexdigits) != 32:
        return text
    try:
        raw = bytes.fromhex(hexdigits)
    except ValueError:
        return text
    b = raw[:4][::-1] + raw[4:6][::-1] + raw[6:8][::-1] + raw[8:]   # back to the wire bytes
    le = lambda chunk: int.from_bytes(chunk, 'little')
    head = f'{b[0:4].hex()}-{b[4:6].hex()}-{b[6:8].hex()}' if smb1 else f'{le(b[0:4]):08x}-{le(b[4:6]):04x}-{le(b[6:8]):04x}'
    return f'{head}-{le(b[8:10]):04x}-{le(b[10:12]):04x}{le(b[12:16]):08x}'


_MONTHS = {m: i for i, m in enumerate(('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug',
                                       'Sep', 'Oct', 'Nov', 'Dec'), 1)}


def _epoch(text):
    """tshark's absolute time ('Feb  4, 2021 13:59:17.430926700 UTC' - the
    structured pass runs with TZ=UTC) as whole seconds since 1970."""
    import calendar
    try:
        month, day, year, clock = text.replace(',', '').split()[:4]
        hours, minutes, seconds = clock.split(':')
        return calendar.timegm((int(year), _MONTHS[month], int(day), int(hours), int(minutes),
                                int(float(seconds)), 0, 0, 0))
    except (ValueError, KeyError):
        return None


def _smb_status(value):
    from shark_names import NT_STATUS
    code = _int(value)
    if code is None:
        return None, None
    return NT_STATUS.get(code, f'0x{code:x}'), f'0x{code:x}'


# Suricata's names for SMB2 commands (rust/src/smb/smb2.rs)
_SMB2_COMMANDS = ('NEGOTIATE_PROTOCOL', 'SESSION_SETUP', 'SESSION_LOGOFF', 'TREE_CONNECT', 'TREE_DISCONNECT',
                  'CREATE', 'CLOSE', 'FLUSH', 'READ', 'WRITE', 'LOCK', 'IOCTL', 'CANCEL', 'KEEPALIVE', 'FIND',
                  'CHANGE_NOTIFY', 'GET_INFO', 'SET_INFO', 'OPLOCK_BREAK')
# ... and SMB1's (rust/src/smb/smb1.rs)
_SMB1_COMMANDS = {
    0x00: 'CREATE_DIRECTORY', 0x01: 'DELETE_DIRECTORY', 0x02: 'OPEN', 0x03: 'CREATE', 0x04: 'CLOSE',
    0x05: 'FLUSH', 0x06: 'DELETE', 0x07: 'RENAME', 0x08: 'QUERY_INFORMATION', 0x09: 'SET_INFORMATION',
    0x0a: 'READ', 0x0b: 'WRITE', 0x0c: 'LOCK_BYTE_RANGE', 0x0d: 'UNLOCK_BYTE_RANGE', 0x0e: 'CREATE_TEMPORARY',
    0x0f: 'CREATE_NEW', 0x10: 'CHECK_DIRECTORY', 0x11: 'PROCESS_EXIT', 0x12: 'SEEK', 0x13: 'LOCK_AND_READ',
    0x14: 'WRITE_AND_UNLOCK', 0x1a: 'READ_RAW', 0x1b: 'READ_MPX', 0x1c: 'READ_MPX_SECONDARY',
    0x1d: 'WRITE_RAW', 0x1e: 'WRITE_MPX', 0x1f: 'WRITE_MPX_SECONDARY', 0x20: 'WRITE_COMPLETE',
    0x21: 'QUERY_SERVER', 0x22: 'SET_INFORMATION2', 0x23: 'QUERY_INFORMATION2', 0x24: 'LOCKING_ANDX',
    0x25: 'TRANS', 0x26: 'TRANS_SECONDARY', 0x27: 'IOCTL', 0x28: 'IOCTL_SECONDARY', 0x29: 'COPY',
    0x2a: 'MOVE', 0x2b: 'ECHO', 0x2c: 'WRITE_AND_CLOSE', 0x2d: 'OPEN_ANDX', 0x2e: 'READ_ANDX',
    0x2f: 'WRITE_ANDX', 0x30: 'NEW_FILE_SIZE', 0x31: 'CLOSE_AND_TREE_DISC', 0x32: 'TRANS2',
    0x33: 'TRANS2_SECONDARY', 0x34: 'FIND_CLOSE2', 0x35: 'FIND_NOTIFY_CLOSE', 0x70: 'TREE_CONNECT',
    0x71: 'TREE_DISCONNECT', 0x72: 'NEGOTIATE_PROTOCOL', 0x73: 'SESSION_SETUP_ANDX', 0x74: 'LOGOFF_ANDX',
    0x75: 'TREE_CONNECT_ANDX', 0x7e: 'SECURITY_PACKAGE_ANDX', 0x80: 'QUERY_INFORMATION_DISK',
    0x81: 'SEARCH', 0x82: 'FIND', 0x83: 'FIND_UNIQUE', 0x84: 'FIND_CLOSE', 0xa0: 'NT_TRANS',
    0xa1: 'NT_TRANS_SECONDARY', 0xa2: 'NT_CREATE_ANDX', 0xa4: 'NT_CANCEL', 0xa5: 'NT_RENAME',
    0xc0: 'OPEN_PRINT_FILE', 0xc1: 'WRITE_PRINT_FILE', 0xc2: 'CLOSE_PRINT_FILE', 0xc3: 'GET_PRINT_QUEUE',
}
_SMB_DISPOSITIONS = ('FILE_SUPERSEDE', 'FILE_OPEN', 'FILE_CREATE', 'FILE_OPEN_IF', 'FILE_OVERWRITE',
                     'FILE_OVERWRITE_IF')
_SMB_SHARE_TYPES = {1: 'FILE', 2: 'PIPE', 3: 'PRINT'}
_STATUS_PENDING = 0x103


def _smb2_dialect(value):
    """0x0311 -> '3.11', SMB2's wildcard 0x02ff -> '2.??', as Suricata writes them."""
    code = _int(value)
    if code is None:
        return None
    if code == 0x02ff:
        return '2.??'
    return f'{code >> 8}.{code & 0xff:02x}'


class _SmbFlow:
    """What SMB keeps per connection: the dialect negotiated, each open
    file's name by its file ID, each tree's share, and requests waiting
    for their response."""
    __slots__ = ('dialect', 'files', 'trees', 'waiting', 'transfers')

    def __init__(self):
        self.dialect = None
        self.transfers = set()   # (command, file ID) already recorded
        self.files = {}      # file ID -> filename
        self.trees = {}      # tree ID -> (share path, share type)
        self.waiting = {}    # ('smb2', message ID) or ('smb1', mid, pid) -> body


class SMB:
    """SMB2 and SMB1 commands, one record per request with its response,
    in Suricata's smb layout (its DCERPC-over-SMB detail aside, which
    comes with DCERPC's own records). The negotiated dialect, a file's name
    on a READ or WRITE, and a tree's share are carried over from earlier
    commands on the connection, as Suricata does."""
    app_protos = ('smb',)
    tshark_protocols = ('nbss', 'netbios', 'smb', 'smb2', 'gss-api', 'spnego', 'spnego-krb5', 'kerberos', 'ber', 'ntlmssp',
                        'dcerpc')
    layers = ('smb', 'smb2', 'dcerpc')
    display_filter = 'smb || smb2'

    def __init__(self):
        self.records = []
        self.flows = {}

    def feed_json(self, pkt, layers):
        state = self.flows.get(pkt.flow.key)
        if state is None:
            state = self.flows[pkt.flow.key] = _SmbFlow()
        # DCERPC over a named pipe is a layer of its own, beside SMB's
        dcerpc = _flatten(layers.get('dcerpc')) if layers.get('dcerpc') else {}
        for pdu in _pdus(layers.get('smb')):
            self._smb1(pkt, state, _flatten(pdu))
        for pdu in _pdus(layers.get('smb2')):
            self._smb2(pkt, state, _flatten(pdu), dcerpc)

    def _new(self, pkt, state, body):
        self.records.append((pkt.flow, pkt.when, 'smb', body))
        return body

    @staticmethod
    def _status(body, value):
        status, code = _smb_status(value)
        if status is not None:
            body['status'], body['status_code'] = status, code

    # SMB2
    def _smb2(self, pkt, state, f, dcerpc):
        cmd = _int(_first(f.get('smb2.cmd', [])))
        if cmd is None:
            return
        response = _first(f.get('smb2.flags.response', [])) in ('1', 'True')
        msg_id = _int(_first(f.get('smb2.msg_id', [])))
        key = ('smb2', msg_id)
        value = lambda name: _first(f.get(name, []))
        if not response:
            body = {'dialect': state.dialect or 'unknown',
                    'command': 'SMB2_COMMAND_' + (_SMB2_COMMANDS[cmd] if cmd < len(_SMB2_COMMANDS) else f'UNKNOWN_{cmd:02X}'),
                    'session_id': _int(value('smb2.sesid'), 0), 'tree_id': _int(value('smb2.tid'), 0)}
            if cmd == 0:
                body['client_dialects'] = [_smb2_dialect(d) for d in f.get('smb2.dialect', [])]
                if value('smb2.client_guid'):
                    body['client_guid'] = _suricata_guid(value('smb2.client_guid'))
            elif cmd == 1:
                self._auth(body, f)
            elif cmd == 3:
                body['_path'] = value('smb2.tree')
            elif cmd == 5:
                name = value('smb2.filename') or '<share_root>'
                directory = value('smb.nt.create_options.directory') in ('1', 'True') and name != '<share_root>'
                body['directory' if directory else 'filename'] = name
                disposition = _int(value('smb2.create.disposition'))
                if disposition is not None and disposition < len(_SMB_DISPOSITIONS):
                    body['disposition'] = _SMB_DISPOSITIONS[disposition]
                body['access'] = 'delete on close' if value('smb.nt.create_options.delete_on_close') in ('1', 'True') \
                    else 'normal'
                # 0 and '' until a successful response says otherwise, as Suricata writes them
                body.update(created=0, accessed=0, modified=0, changed=0, size=0, fuid='')
                body['_name'] = name
            elif cmd in (8, 9):
                # Suricata records a READ or WRITE as a file transfer - one
                # record for all of a file's reads (or writes) - or, on a
                # named pipe, a WRITE as the DCERPC call it carries (whose
                # answer comes back in a READ)
                fid = value('smb2.fid')
                tree = state.trees.get(body['tree_id'])
                if tree and tree[1] == 'PIPE':
                    # one record per DCERPC call: a WRITE that starts one
                    if cmd == 8 or not dcerpc.get('dcerpc.pkt_type') or \
                            _first(dcerpc.get('dcerpc.cn_flags.first_frag', [])) not in ('1', 'True'):
                        return
                elif fid not in state.files or not tree or (cmd, fid) in state.transfers:
                    return     # a file whose opening wasn't seen, or already recorded
                else:
                    state.transfers.add((cmd, fid))
                    body.update(filename=state.files[fid], share=tree[0], fuid=_suricata_guid(fid))
            elif cmd in (16, 17):
                return         # no record for GET_INFO or SET_INFO
            elif cmd == 11:
                from shark_names import FSCTL
                function = _int(value('smb2.ioctl.function'))
                if function is not None:
                    body['function'] = FSCTL.get(function, f'0x{function:x}')
            body = self._new(pkt, state, body)
            if cmd != 12:      # a CANCEL is never answered
                state.waiting[key] = body
            return
        body = state.waiting.get(key)
        status = _int(value('smb2.nt_status'))
        if status == _STATUS_PENDING and value('smb2.flags.async') in ('1', 'True'):
            return             # an interim response: the final one follows
        if body is None:
            if cmd == 0 and ('smb1', 0, None) in state.waiting:
                body = state.waiting.pop(('smb1', 0, None))   # SMB1 negotiate answered in SMB2
                body['session_id'] = _int(value('smb2.sesid'), 0)
                body['tree_id'] = _int(value('smb2.tid'), 0)
            else:
                return
        else:
            del state.waiting[key]
        self._status(body, value('smb2.nt_status'))
        if cmd == 0:
            dialect = _smb2_dialect(value('smb2.dialect'))
            if dialect:
                state.dialect = body['dialect'] = dialect
            if value('smb2.server_guid'):
                body['server_guid'] = _suricata_guid(value('smb2.server_guid'))
            for size in ('max_read_size', 'max_write_size'):
                if value(f'smb2.{size}'):
                    body[size] = _int(value(f'smb2.{size}'))
        elif cmd == 1:
            body['session_id'] = _int(value('smb2.sesid'), body['session_id'])
        elif cmd == 3:
            body['tree_id'] = _int(value('smb2.tid'), body['tree_id'])
            share_type = _SMB_SHARE_TYPES.get(_int(value('smb2.share_type')))
            path = body.pop('_path', '')
            if share_type:
                body['named_pipe' if share_type == 'PIPE' else 'share'] = path
                body['share_type'] = share_type
                state.trees[body['tree_id']] = (path, share_type)
        elif cmd == 5:
            name = body.pop('_name', '')
            fid = value('smb2.fid')
            if fid and status == 0:
                state.files[fid] = name
                body['fuid'] = _suricata_guid(fid)
            for key_name, field in (('created', 'smb2.create.time'), ('accessed', 'smb2.last_access.time'),
                                    ('modified', 'smb2.last_write.time'), ('changed', 'smb2.last_change.time')):
                when = _epoch(value(field)) if value(field) else None
                if when is not None:
                    body[key_name] = when
            if value('smb2.eof'):
                body['size'] = _int(value('smb2.eof'))
        body.pop('_path', None)
        body.pop('_name', None)

    @staticmethod
    def _auth(body, f):
        """Who a session setup authenticates: the Kerberos ticket's realm
        and service, or NTLM's domain, user and host."""
        value = lambda name: _first(f.get(name, []))
        if value('kerberos.realm') and f.get('kerberos.SNameString'):
            body['kerberos'] = {'realm': value('kerberos.realm'), 'snames': f['kerberos.SNameString']}
        if value('ntlmssp.auth.username') or value('ntlmssp.auth.hostname'):
            # tshark writes an empty name (an anonymous login's) as NULL
            name = lambda field: '' if value(field) == 'NULL' else value(field)
            ntlm = {'domain': name('ntlmssp.auth.domain'), 'user': name('ntlmssp.auth.username'),
                    'host': name('ntlmssp.auth.hostname')}
            if value('ntlmssp.version.major'):
                ntlm['version'] = (f"{value('ntlmssp.version.major')}.{value('ntlmssp.version.minor')} "
                                   f"build {value('ntlmssp.version.build_number')} "
                                   f"rev {value('ntlmssp.version.ntlm_current_revision')}")
            body['ntlmssp'] = ntlm

    # SMB1
    def _smb1(self, pkt, state, f):
        cmd = _int(_first(f.get('smb.cmd', [])))
        if cmd is None:
            return
        value = lambda name: _first(f.get(name, []))
        if cmd in (0x2e, 0x2f, 0x25, 0x32):
            return     # READ_ANDX, WRITE_ANDX, TRANS, TRANS2: no record of their own in Suricata
        response = value('smb.flags.response') in ('1', 'True')
        key = ('smb1', _int(value('smb.mid'), 0), None if cmd == 0x72 else _int(value('smb.pid'), 0))
        if not response:
            body = {'dialect': state.dialect or ('NT LM 0.12' if cmd != 0x72 else 'unknown'),
                    'command': 'SMB1_COMMAND_' + _SMB1_COMMANDS.get(cmd, f'UNKNOWN_{cmd:02X}'),
                    'session_id': _int(value('smb.uid'), 0), 'tree_id': _int(value('smb.tid'), 0)}
            if cmd == 0x72:
                body['client_dialects'] = f.get('smb.dialect.name', [])
            elif cmd == 0x73:
                body['request'] = {'native_os': value('smb.native_os'), 'native_lm': value('smb.native_lanman')}
                self._auth(body, f)
            elif cmd == 0x75:
                # Suricata's SMB1 share path starts one backslash in
                path = value('smb.path')
                body['_path'] = path[1:] if path.startswith('\\\\') else path
                body['service'] = {'request': value('smb.service')}
            state.waiting[key] = self._new(pkt, state, body)
            return
        body = state.waiting.pop(key, None)
        if body is None:
            return
        self._status(body, value('smb.nt_status'))
        if cmd == 0x72:
            index = _int(value('smb.dialect.index'))
            if index is not None and index < len(body.get('client_dialects', [])):
                state.dialect = body['dialect'] = body['client_dialects'][index]
            if value('smb.server_guid'):
                body['server_guid'] = _suricata_guid(value('smb.server_guid'), smb1=True)
        elif cmd == 0x73:
            body['session_id'] = _int(value('smb.uid'), body['session_id'])
            body['response'] = {'native_os': value('smb.native_os'), 'native_lm': value('smb.native_lanman')}
        elif cmd == 0x75:
            body['tree_id'] = _int(value('smb.tid'), body['tree_id'])
            service = value('smb.service')
            body['service']['response'] = service
            path = body.pop('_path', '')
            body['named_pipe' if service == 'IPC' else 'share'] = path
            state.trees[body['tree_id']] = (path, 'PIPE' if service == 'IPC' else 'FILE')
        body.pop('_path', None)

    def finish(self):
        for _, _, _, body in self.records:
            body.pop('_path', None)
            body.pop('_name', None)
        return self.records


# Every protocol SHAR-CRATES builds records for from tshark's fields, in
# the order their fields follow the base fields in tshark's output.
PROTOCOLS = (DNS, HTTP, TLS, Modbus, FTP, NBNS, SSDP, S7comm)
# ... and from the structured pass.
STRUCTURED_PROTOCOLS = (SMB,)
# Flow application protocols with transaction records here - every other
# one gets a connection tab (db.CONNECTION_TYPE_PREFIX) instead.
RECORDED_APP_PROTOS = frozenset(p for proto in PROTOCOLS + STRUCTURED_PROTOCOLS for p in proto.app_protos)
