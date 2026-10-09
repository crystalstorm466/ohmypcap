#!/usr/bin/env python3
"""Records for protocols Suricata doesn't parse: tshark's packet-by-packet
fields turned into one record per request/response transaction, to join
Suricata's records in the analysis (shark_analyzer.merge). Suricata stays
the source of truth for everything it parses, so nothing here duplicates
one of its protocols.

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


# ---------------------------------------------------------------- LLMNR

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


class LLMNR:
    """LLMNR - Windows' link-local name resolution, which tshark decodes
    with its DNS dissector (same message format, dns.* fields): a record
    per query, its response merged in, in the layout of Suricata's DNS
    records. (DNS and mDNS themselves are Suricata's.)"""
    event_type = 'llmnr'
    app_protos = ('llmnr',)      # flow app_proto values whose transactions these records are
    fields = ('dns.id', 'dns.flags.response', 'dns.qry.name', 'dns.qry.type', 'dns.flags.rcode',
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
        kind = 'llmnr'
        queries = [{'rrname': name, 'rrtype': _dns_type(qtype)} for name, qtype in zip(v['dns.qry.name'], v['dns.qry.type'])]
        is_response = _first(v['dns.flags.response']) in ('True', '1')
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
        # response - so a multicast query's unicast answer, or a repeat of
        # an answered query's response, arrives unlinked.
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
    def _answers(v):
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
        return answers

    def finish(self):
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


# ---------------------------------------------------------------- Telnet
#
# Suricata recognizes Telnet but logs nothing about it. One record per
# session: the server's banner, the name and password typed at its login
# prompts, whether it said the login failed, and the lines typed after -
# rebuilt from the keystrokes (a client sends each as it's typed; the
# server echoes them, and its echo is ignored here).

_TELNET_ESCAPES = re.compile(r'\x1b\[[0-9;?]*[A-Za-z~]|\x1b[()][A-Za-z0-9]|\x1b.?')
_TELNET_USER_PROMPT = re.compile(r'(login|user ?name|user|account)\s*:\s*$', re.I)
_TELNET_PASSWORD_PROMPT = re.compile(r'pass(word|code)?\s*:\s*$', re.I)
_TELNET_FAILED = re.compile(r'login incorrect|access denied|authentication fail|invalid (password|login|user)|'
                            r'login fail|incorrect password|bad password', re.I)
_TELNET_MAX_SERVER_TEXT = 4096     # of the session's start, enough for its banner and login
_TELNET_MAX_COMMANDS = 100
_TELNET_MAX_LINE = 200


class _TelnetSession:
    __slots__ = ('first', 'flow', 'server_text', 'tail', 'state', 'line', 'body', 'commands')

    def __init__(self, flow, when):
        self.flow, self.first = flow, when
        self.server_text = ''      # the start of everything the server sent
        self.tail = ''             # the end of it, for spotting the latest prompt
        self.state = None          # what the next line typed is: 'user', 'password', or a command
        self.line = ''
        self.body = {}
        self.commands = []


class Telnet:
    """Telnet sessions - see the comment above."""
    event_type = 'telnet'
    app_protos = ('telnet',)
    fields = ('telnet.data',)

    def __init__(self):
        self.sessions = {}        # flow key -> _TelnetSession

    def feed(self, pkt, v):
        text = ''.join(v['telnet.data'])
        if not text:
            return
        session = self.sessions.get(pkt.flow.key)
        if session is None:
            session = self.sessions[pkt.flow.key] = _TelnetSession(pkt.flow, pkt.when)
        # The server is whoever's on the Telnet port (the flow's client may
        # not be settled yet when its first data arrives)
        if pkt.sport == 23 or (pkt.dport != 23 and pkt.sport == pkt.flow.sport):
            self._from_server(session, text)
        else:
            self._from_client(session, text)

    @staticmethod
    def _from_server(session, text):
        clean = _TELNET_ESCAPES.sub('', text)
        if len(session.server_text) < _TELNET_MAX_SERVER_TEXT:
            session.server_text += clean
        session.tail = (session.tail + clean)[-200:]
        last = session.tail.rstrip(' \t')
        if _TELNET_PASSWORD_PROMPT.search(last):
            session.state = 'password'
        elif _TELNET_USER_PROMPT.search(last):
            session.state = 'user'
        if _TELNET_FAILED.search(clean):
            session.body['login'] = 'failed'

    @staticmethod
    def _from_client(session, text):
        for ch in _TELNET_ESCAPES.sub('', text):
            if ch in '\r\n':
                line, session.line = session.line, ''
                if session.state == 'user':
                    session.body.setdefault('username', line)
                    session.state = None
                elif session.state == 'password':
                    session.body.setdefault('password', line)
                    session.state = None
                elif line.strip() and len(session.commands) < _TELNET_MAX_COMMANDS:
                    session.commands.append(line[:_TELNET_MAX_LINE])
                session.tail = ''
            elif ch in '\x08\x7f':
                session.line = session.line[:-1]
            elif ch >= ' ' and len(session.line) < 4 * _TELNET_MAX_LINE:
                session.line += ch

    def finish(self):
        records = []
        for session in self.sessions.values():
            body = dict(session.body)
            # The banner: the first line of the server's text that reads as
            # text (option negotiation leaves stray bytes ahead of it)
            for line in session.server_text.replace('\r', '\n').split('\n'):
                line = ''.join(ch for ch in line if ch >= ' ' and ch != '\ufffd').strip()
                if sum(ch.isalnum() for ch in line) >= 3:
                    body['banner'] = line[:_TELNET_MAX_LINE]
                    break
            if session.commands:
                body['commands'] = session.commands
            if body:
                records.append((session.flow, session.first, 'telnet', body))
        return records


# ---------------------------------------------------------------- IEC 60870-5-104
#
# Telecontrol between a power grid's control centre and its substations.
# Two record types: 'iec104', one per control action - a command, set
# point, interrogation, clock sync, read, reset, parameter or file
# transfer - with its confirmation and termination paired in; and
# 'iec104_point', one per monitored point per connection (its updates
# counted, the last value kept), so a busy link's hundreds of thousands
# of measurements don't each become a record. A packet often carries
# several messages (ASDUs): each has one type, cause and station, and
# numix objects, by which the flat object and value fields split up.

_IEC104_TYPES = {
    1: 'M_SP_NA_1', 2: 'M_SP_TA_1', 3: 'M_DP_NA_1', 4: 'M_DP_TA_1', 5: 'M_ST_NA_1', 6: 'M_ST_TA_1', 7: 'M_BO_NA_1',
    8: 'M_BO_TA_1', 9: 'M_ME_NA_1', 10: 'M_ME_TA_1', 11: 'M_ME_NB_1', 12: 'M_ME_TB_1', 13: 'M_ME_NC_1', 14: 'M_ME_TC_1',
    15: 'M_IT_NA_1', 16: 'M_IT_TA_1', 17: 'M_EP_TA_1', 18: 'M_EP_TB_1', 19: 'M_EP_TC_1', 20: 'M_PS_NA_1', 21: 'M_ME_ND_1',
    30: 'M_SP_TB_1', 31: 'M_DP_TB_1', 32: 'M_ST_TB_1', 33: 'M_BO_TB_1', 34: 'M_ME_TD_1', 35: 'M_ME_TE_1', 36: 'M_ME_TF_1',
    37: 'M_IT_TB_1', 38: 'M_EP_TD_1', 39: 'M_EP_TE_1', 40: 'M_EP_TF_1', 45: 'C_SC_NA_1', 46: 'C_DC_NA_1', 47: 'C_RC_NA_1',
    48: 'C_SE_NA_1', 49: 'C_SE_NB_1', 50: 'C_SE_NC_1', 51: 'C_BO_NA_1', 58: 'C_SC_TA_1', 59: 'C_DC_TA_1', 60: 'C_RC_TA_1',
    61: 'C_SE_TA_1', 62: 'C_SE_TB_1', 63: 'C_SE_TC_1', 64: 'C_BO_TA_1', 70: 'M_EI_NA_1', 100: 'C_IC_NA_1', 101: 'C_CI_NA_1',
    102: 'C_RD_NA_1', 103: 'C_CS_NA_1', 104: 'C_TS_NA_1', 105: 'C_RP_NA_1', 106: 'C_CD_NA_1', 107: 'C_TS_TA_1',
    110: 'P_ME_NA_1', 111: 'P_ME_NB_1', 112: 'P_ME_NC_1', 113: 'P_AC_NA_1', 120: 'F_FR_NA_1', 121: 'F_SR_NA_1',
    122: 'F_SC_NA_1', 123: 'F_LS_NA_1', 124: 'F_AF_NA_1', 125: 'F_SG_NA_1', 126: 'F_DR_TA_1', 127: 'F_SC_NB_1'}
_IEC104_ACTIONS = {
    45: 'Single command', 46: 'Double command', 47: 'Regulating step command', 48: 'Set point (normalized)',
    49: 'Set point (scaled)', 50: 'Set point (float)', 51: 'Bitstring command', 58: 'Single command', 59: 'Double command',
    60: 'Regulating step command', 61: 'Set point (normalized)', 62: 'Set point (scaled)', 63: 'Set point (float)',
    64: 'Bitstring command', 70: 'End of initialization', 100: 'Interrogation', 101: 'Counter interrogation', 102: 'Read',
    103: 'Clock synchronization', 104: 'Test', 105: 'Reset process', 106: 'Delay acquisition', 107: 'Test',
    110: 'Parameter (normalized)', 111: 'Parameter (scaled)', 112: 'Parameter (float)', 113: 'Parameter activation',
    120: 'File ready', 121: 'Section ready', 122: 'Call directory/file/section', 123: 'Last section/segment',
    124: 'Acknowledge file/section', 125: 'File segment', 126: 'Directory', 127: 'Query log'}
_IEC104_CAUSES = {
    1: 'per/cyc', 2: 'back', 3: 'spont', 4: 'init', 5: 'req', 6: 'act', 7: 'actcon', 8: 'deact', 9: 'deactcon',
    10: 'actterm', 11: 'retrem', 12: 'retloc', 13: 'file', 14: 'auth', 15: 'seskey', 16: 'usrkey', 20: 'inrogen',
    37: 'reqcogen', 44: 'unknown type', 45: 'unknown cause', 46: 'unknown station', 47: 'unknown address'}
for _n in range(1, 17):
    _IEC104_CAUSES[20 + _n] = f'inro{_n}'
for _n in range(1, 5):
    _IEC104_CAUSES[37 + _n] = f'reqco{_n}'
# Each object's value: the field it's in, and how to read it, by type
_IEC104_VALUE_FIELDS = {'siq': 'iec60870_asdu.siq.spi', 'diq': 'iec60870_asdu.diq.dpi', 'vti': 'iec60870_asdu.vti.v',
                        'bits': 'iec60870_asdu.bitstring', 'norm': 'iec60870_asdu.normval', 'scal': 'iec60870_asdu.scalval',
                        'float': 'iec60870_asdu.float', 'bcr': 'iec60870_asdu.bcr.count', 'sco': 'iec60870_asdu.sco.on',
                        'dco': 'iec60870_asdu.dco.on', 'rco': 'iec60870_asdu.rco.up', 'qoi': 'iec60870_asdu.qoi',
                        'qcc': 'iec60870_asdu.qcc', 'qrp': 'iec60870_asdu.qrp'}
_IEC104_VALUE_KIND = {}
for _kind, _types in (('siq', (1, 2, 30)), ('diq', (3, 4, 31)), ('vti', (5, 6, 32)), ('bits', (7, 8, 33, 51, 64)),
                      ('norm', (9, 10, 34, 21, 48, 61)), ('scal', (11, 12, 35, 49, 62)), ('float', (13, 14, 36, 50, 63)),
                      ('bcr', (15, 16, 37)), ('sco', (45, 58)), ('dco', (46, 59)), ('rco', (47, 60)), ('qoi', (100,)),
                      ('qcc', (101,)), ('qrp', (105,))):
    for _t in _types:
        _IEC104_VALUE_KIND[_t] = _kind
_IEC104_DOUBLE_POINT = {0: 'indeterminate', 1: 'off', 2: 'on', 3: 'indeterminate'}
_IEC104_INTERROGATIONS = {20: 'station'}
for _n in range(1, 17):
    _IEC104_INTERROGATIONS[20 + _n] = f'group {_n}'


_IEC104_COMMAND_STATES = {'sco': {0: 'off', 1: 'on'}, 'dco': {1: 'off', 2: 'on'}, 'rco': {1: 'lower', 2: 'higher'}}


def _iec104_value(kind, text):
    if kind == 'siq':
        return 1 if text in ('1', 'True') else 0
    if kind in _IEC104_COMMAND_STATES:
        number = 1 if text == 'True' else 0 if text == 'False' else _int(text)
        return _IEC104_COMMAND_STATES[kind].get(number, text)
    if kind == 'diq':
        return _IEC104_DOUBLE_POINT.get(_int(text), text)
    if kind == 'qoi':
        return _IEC104_INTERROGATIONS.get(_int(text), text)
    if kind in ('norm', 'float'):
        try:
            return float(text)
        except ValueError:
            return text
    number = _int(text)
    return number if number is not None else text


def _iso_utc(when):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(when, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f+0000')


class _IEC104Point:
    __slots__ = ('flow', 'first', 'body')

    def __init__(self, flow, first, body):
        self.flow, self.first, self.body = flow, first, body


class IEC104:
    """IEC 60870-5-104 - see the comment above."""
    event_type = 'iec104'
    app_protos = ('iec60870_104',)
    fields = ('iec60870_asdu.typeid', 'iec60870_asdu.causetx', 'iec60870_asdu.nega', 'iec60870_asdu.test',
              'iec60870_asdu.addr', 'iec60870_asdu.numix', 'iec60870_asdu.ioa') + tuple(_IEC104_VALUE_FIELDS.values())

    # Causes that open a control action: activation, deactivation, and a
    # read's request
    _OPENS = (6, 8)

    def __init__(self):
        self.records = []
        # (flow key, type, station, first object) -> the actions waiting on
        # their replies, oldest first: a station can be sent another
        # interrogation before the last is answered, and replies in order
        self.open = {}
        self.points = {}       # (flow key, station, object, type) -> _IEC104Point

    def feed(self, pkt, v):
        values = {kind: list(v[field]) for kind, field in _IEC104_VALUE_FIELDS.items()}
        objects = list(v['iec60870_asdu.ioa'])
        for tid, cot, addr, count, negative, test in zip(
                v['iec60870_asdu.typeid'], v['iec60870_asdu.causetx'], v['iec60870_asdu.addr'], v['iec60870_asdu.numix'],
                v['iec60870_asdu.nega'] or [''] * len(v['iec60870_asdu.typeid']),
                v['iec60870_asdu.test'] or [''] * len(v['iec60870_asdu.typeid'])):
            tid, cot, addr, count = _int(tid), _int(cot, 0), _int(addr, 0), _int(count, 0)
            if tid is None:
                continue
            ioas = [_int(x, 0) for x in objects[:count]]
            del objects[:count]
            kind = _IEC104_VALUE_KIND.get(tid)
            vals = []
            if kind:
                vals = [_iec104_value(kind, x) for x in values[kind][:count]]
                del values[kind][:count]
            if tid >= 45:
                self._control(pkt, tid, cot, addr, ioas, vals, negative in ('1', 'True'), test in ('1', 'True'))
            else:
                self._points(pkt, tid, cot, addr, ioas, vals)

    def _control(self, pkt, tid, cot, addr, ioas, vals, negative, test):
        key = (pkt.flow.key, tid, addr, ioas[0] if ioas else None)
        cause = _IEC104_CAUSES.get(cot, str(cot))
        waiting = self.open.get(key, [])
        if cot in (7, 9) or 44 <= cot <= 47:
            body = next((b for b in waiting if 'response' not in b), None)
        elif cot == 10:
            body = next((b for b in waiting if 'terminated' not in b), None)
        else:
            body = None
        if cot in self._OPENS or (tid == 102 and cot == 5) or body is None:
            body = {'type_id': tid, 'type': _IEC104_TYPES.get(tid, str(tid)), 'action': _IEC104_ACTIONS.get(tid, ''),
                    'cause': cause, 'station': addr}
            if ioas:
                body['ioa'] = ioas[0]
            if vals:
                body['value'] = vals[0]
            if test:
                body['test'] = True
            opens = cot in self._OPENS or (tid == 102 and cot == 5)
            # A reply whose request the capture doesn't have (it started
            # after, or lost the packet) is still a record
            if opens:
                body['result'] = 'no confirmation'
            elif cot in (7, 9):
                body['result'] = 'negative (request not seen)' if negative else 'confirmed (request not seen)'
            elif cot == 10:
                body['result'] = 'terminated (request not seen)'
            else:
                body['result'] = cause
            self.records.append((pkt.flow, pkt.when, 'iec104', body))
            if opens:
                self.open.setdefault(key, []).append(body)
            return
        # its confirmation, termination, or an "unknown ..." refusal
        if cot in (7, 9):
            body['response'] = {'cause': cause, 'negative': negative}
            body['result'] = 'negative' if negative else 'confirmed'
        elif cot == 10:
            body['terminated'] = True
            if body['result'] == 'confirmed':
                body['result'] = 'confirmed, terminated'
            waiting.remove(body)
        elif 44 <= cot <= 47:
            body['response'] = {'cause': cause, 'negative': True}
            body['result'] = cause
            waiting.remove(body)
        # A command that needs no termination is done once confirmed; keep
        # the queue to what can still be answered
        if len(waiting) > 64:
            del waiting[:-64]

    def _points(self, pkt, tid, cot, addr, ioas, vals):
        cause = _IEC104_CAUSES.get(cot, str(cot))
        for i, ioa in enumerate(ioas):
            key = (pkt.flow.key, addr, ioa, tid)
            point = self.points.get(key)
            if point is None:
                body = {'station': addr, 'ioa': ioa, 'type_id': tid, 'type': _IEC104_TYPES.get(tid, str(tid)),
                        'updates': 0, 'causes': {}}
                point = self.points[key] = _IEC104Point(pkt.flow, pkt.when, body)
            body = point.body
            body['updates'] += 1
            body['causes'][cause] = body['causes'].get(cause, 0) + 1
            body['last_update'] = pkt.when
            if i < len(vals):
                body['last_value'] = vals[i]

    def finish(self):
        records = list(self.records)
        for point in self.points.values():
            body = point.body
            body['last_update'] = _iso_utc(body['last_update'])
            records.append((point.flow, point.first, 'iec104_point', body))
        return records


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


# Every protocol with records here, from tshark's fields, in the order their
# fields follow the base fields in tshark's output.
PROTOCOLS = (LLMNR, NBNS, SSDP, S7comm, Telnet, IEC104)
# ... and from the structured pass (shark_analyzer._structured_pass): none
# yet - it's for a protocol whose messages nest, which flat fields can't
# keep apart (several commands per packet, a token inside a command).
STRUCTURED_PROTOCOLS = ()
# Flow application protocols with transaction records here - every other
# one gets a connection tab (db.CONNECTION_TYPE_PREFIX) instead.
RECORDED_APP_PROTOS = frozenset(p for proto in PROTOCOLS + STRUCTURED_PROTOCOLS for p in proto.app_protos)
