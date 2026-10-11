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
import struct


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


# ---------------------------------------------------------------- DHCPv6
#
# Suricata parses DHCP for IPv4 only. A DHCPv6 client multicasts its
# message (Solicit, Request, Renew, Information-request...) to ff02::1:2
# and the server answers it directly (Advertise, Reply) - on another
# flow, so a transaction is keyed by the client's address and its
# transaction ID, like NBNS's. One record per transaction, its
# retransmissions counted: the client's DUID and the MAC address in it,
# the hostname it gave (the Client FQDN option - Windows always sends
# one), its vendor class, and from the reply the addresses and prefixes
# assigned, the server's DUID, DNS servers, search domains and status.
# Through a relay, the record is the relay's, with the link it serves.

_DHCPV6_MESSAGES = {1: 'Solicit', 2: 'Advertise', 3: 'Request', 4: 'Confirm', 5: 'Renew', 6: 'Rebind', 7: 'Reply',
                    8: 'Release', 9: 'Decline', 10: 'Reconfigure', 11: 'Information-request', 12: 'Relay-forw',
                    13: 'Relay-reply'}
_DHCPV6_FROM_SERVER = {2, 7, 10, 13}
_DHCPV6_STATUS = {0: 'Success', 1: 'UnspecFail', 2: 'NoAddrsAvail', 3: 'NoBinding', 4: 'NotOnLink', 5: 'UseMulticast',
                  6: 'NoPrefixAvail'}
_DHCPV6_MAX_LIST = 20


def _duid_mac(duid):
    """The Ethernet address in a link-layer DUID (types 1 and 3), or ''."""
    try:
        raw = bytes.fromhex(duid.replace(':', ''))
    except ValueError:
        return ''
    kind, hwtype = struct.unpack('!HH', raw[:4]) if len(raw) >= 4 else (0, 0)
    address = raw[8:] if kind == 1 else raw[4:] if kind == 3 else b''
    return ':'.join(f'{b:02x}' for b in address) if hwtype == 1 and len(address) == 6 else ''


class DHCPv6:
    """DHCPv6 - see the comment above."""
    event_type = 'dhcpv6'
    app_protos = ('dhcpv6',)
    fields = ('dhcpv6.msgtype', 'dhcpv6.xid', 'dhcpv6.linkaddr', 'dhcpv6.option.type', 'dhcpv6.duid.bytes',
              'dhcpv6.client_domain', 'dhcpv6.vendorclass.data', 'dhcpv6.iaaddr.ip', 'dhcpv6.iaprefix.pref_addr',
              'dhcpv6.iaprefix.pref_len',
              'dhcpv6.status_code', 'dhcpv6.status_msg', 'dhcpv6.dns_server', 'dhcpv6.search_list_entry')

    def __init__(self):
        self.records = []
        self.open = {}           # (client's or relay's address, transaction id) -> body

    def feed(self, pkt, v):
        kinds = [_int(t) for t in v['dhcpv6.msgtype']]
        txid = _int(_first(v['dhcpv6.xid']))
        if not kinds or txid is None:
            return
        outer, message = kinds[0], kinds[-1]      # a relay's message carries the client's
        from_server = outer in _DHCPV6_FROM_SERVER
        key = (pkt.dst if from_server else pkt.src, txid)
        body = self.open.get(key)
        if body is None:
            body = self.open[key] = {'transaction_id': f'0x{txid:06x}'}
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        name = _DHCPV6_MESSAGES.get(message, f'type {message}')
        if from_server:
            body['reply'] = name
        else:
            body.setdefault('message', name)
            body['transmissions'] = body.get('transmissions', 0) + 1
        if outer in (12, 13):
            body['relayed'] = True
            if v['dhcpv6.linkaddr'] and v['dhcpv6.linkaddr'][0] != '::':
                body['link_address'] = ipv6_exploded(v['dhcpv6.linkaddr'][0])
        # Each Client ID (1) and Server ID (2) option holds one DUID, in order
        owners = [t for t in (_int(x) for x in v['dhcpv6.option.type']) if t in (1, 2)]
        for owner, duid in zip(owners, v['dhcpv6.duid.bytes']):
            duid = duid.replace(':', '')
            if owner == 1:
                body['client_duid'] = duid
                if _duid_mac(duid):
                    body['client_mac'] = _duid_mac(duid)
            else:
                body['server_duid'] = duid
        if v['dhcpv6.client_domain']:
            body['hostname'] = v['dhcpv6.client_domain'][0].rstrip('.')
        if v['dhcpv6.vendorclass.data']:
            body['vendor_class'] = v['dhcpv6.vendorclass.data'][0]
        addresses = [ipv6_exploded(a) for a in dict.fromkeys(v['dhcpv6.iaaddr.ip'])][:_DHCPV6_MAX_LIST]
        prefixes = list(dict.fromkeys(f'{ipv6_exploded(a)}/{n}' for a, n in
                                      zip(v['dhcpv6.iaprefix.pref_addr'], v['dhcpv6.iaprefix.pref_len'])))
        if from_server:
            for field, values in (('assigned_addresses', addresses), ('prefixes', prefixes),
                                 ('dns_servers', [ipv6_exploded(a) for a in dict.fromkeys(v['dhcpv6.dns_server'])]),
                                 ('domain_search', list(dict.fromkeys(e.rstrip('.') for e in
                                                                      v['dhcpv6.search_list_entry'])))):
                if values:
                    body[field] = values[:_DHCPV6_MAX_LIST]
            code = _int(_first(v['dhcpv6.status_code']))
            if code is not None:
                body['status'] = _DHCPV6_STATUS.get(code, str(code))
                if v['dhcpv6.status_msg']:
                    body['status_message'] = v['dhcpv6.status_msg'][0]
        elif addresses:
            body['requested_addresses'] = addresses

    def finish(self):
        return self.records


# ---------------------------------------------------------------- Syslog
#
# Suricata has no syslog parser. One record per message (UDP 514 - tshark
# doesn't decode syslog over TCP): its facility and severity, from the
# <PRI> that starts it, and the rest in either of the two formats - RFC
# 3164's "Mmm dd hh:mm:ss host program[pid]: text" (most devices, many
# leaving out the timestamp or host) or RFC 5424's "1 timestamp host app
# procid msgid [structured data] text". It's parsed here from the
# message's bytes: tshark reads "sshd[812]: Failed..." as program sshd and
# message "812]: Failed...".

_SYSLOG_FACILITIES = ('kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv',
                      'ftp', 'ntp', 'audit', 'alert', 'clock') + tuple(f'local{n}' for n in range(8))
_SYSLOG_SEVERITIES = ('emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug')
_SYSLOG_MAX_MESSAGE = 2048
_SYSLOG_PRI = re.compile(r'<(\d{1,3})>')
_SYSLOG_5424 = re.compile(r'1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]"\\]|\\.|"(?:[^"\\]|\\.)*")*\])+) ?(.*)', re.S)
_SYSLOG_SD_ELEMENT = re.compile(r'\[([^\s\]=]+)((?:\s+[^\s=\]]+="(?:[^"\\]|\\.)*")*)\s*\]')
_SYSLOG_SD_PARAM = re.compile(r'([^\s=\]]+)="((?:[^"\\]|\\.)*)"')
_SYSLOG_3164_TIME = re.compile(r'([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d(?:\.\d+)?(?: \d{4})?) ')
_SYSLOG_TAG = r'([A-Za-z0-9_./-]+)(?:\[(\d+)\])?: ?'
_SYSLOG_HOST_TAG = re.compile(r'([\w.:-]+) ' + _SYSLOG_TAG + r'(.*)', re.S)
_SYSLOG_TAG_ONLY = re.compile(_SYSLOG_TAG + r'(.*)', re.S)


def _syslog_nil(value):
    return '' if value == '-' else value


class Syslog:
    """Syslog - see the comment above."""
    event_type = 'syslog'
    app_protos = ('syslog',)
    fields = ('@syslog',)

    def __init__(self):
        self.records = []

    def feed(self, pkt, v):
        try:
            text = bytes.fromhex(_first(v['@syslog']).replace(':', '')).decode('utf-8', 'replace')
        except ValueError:
            return
        text = text.rstrip('\r\n\x00')
        if not text:
            return
        body = {}
        pri = _SYSLOG_PRI.match(text)
        if pri and int(pri.group(1)) < 192:
            value = int(pri.group(1))
            body['facility'] = _SYSLOG_FACILITIES[value >> 3]
            body['severity'] = _SYSLOG_SEVERITIES[value & 7]
            text = text[pri.end():]
            m = _SYSLOG_5424.match(text)
            if m:
                body['format'] = 'RFC 5424'
                for key, value in zip(('timestamp', 'hostname', 'program', 'pid', 'msgid'), m.groups()[:5]):
                    if _syslog_nil(value):
                        body[key] = value
                if m.group(6) != '-':
                    body['structured_data'] = {
                        element.group(1): {k: re.sub(r'\\(["\\\]])', r'\1', val)
                                           for k, val in _SYSLOG_SD_PARAM.findall(element.group(2))}
                        for element in _SYSLOG_SD_ELEMENT.finditer(m.group(6))}
                text = m.group(7).lstrip('\ufeff')
            else:
                body['format'] = 'RFC 3164'
                stamp = _SYSLOG_3164_TIME.match(text)
                if stamp:
                    body['timestamp'] = stamp.group(1)
                    text = text[stamp.end():]
                tagged = (_SYSLOG_HOST_TAG.match(text) if stamp else None) or _SYSLOG_TAG_ONLY.match(text)
                if tagged:
                    groups = tagged.groups()
                    if len(groups) == 4:
                        body['hostname'] = groups[0]
                        groups = groups[1:]
                    body['program'] = groups[0]
                    if groups[1]:
                        body['pid'] = groups[1]
                    text = groups[2]
        else:
            body['format'] = 'no priority'
        if len(text) > _SYSLOG_MAX_MESSAGE:
            text, body['truncated'] = text[:_SYSLOG_MAX_MESSAGE], True
        body['message'] = text
        self.records.append((pkt.flow, pkt.when, self.event_type, body))

    def finish(self):
        return self.records


# ---------------------------------------------------------------- ONC RPC
#
# Sun RPC, under NFS and the services around it - Suricata parses NFS
# itself, but not the rest: the portmapper (port 111), which tells a
# client which port each RPC program is on, the mount daemon, the lock
# and status monitors, NIS. One record per call, with its reply: the
# program, version and procedure, who the caller said it was (AUTH_UNIX's
# machine name and uid/gid), and the reply's status. The portmapper's
# replies are an inventory of the RPC services a host runs (DUMP lists
# them all; GETPORT asks for one), and the mount daemon's which exports
# it offers to whom (EXPORT) and who has them mounted (DUMP). A scanner's
# DUMP to port 111 nobody answered is still a record.

_RPC_PROGRAMS = {100000: 'portmapper', 100001: 'rstatd', 100002: 'rusersd', 100003: 'nfs', 100004: 'ypserv',
                 100005: 'mountd', 100007: 'ypbind', 100008: 'walld', 100009: 'yppasswdd', 100011: 'rquotad',
                 100012: 'sprayd', 100021: 'nlockmgr', 100024: 'status', 100026: 'bootparam', 100068: 'cmsd',
                 100069: 'ypxfrd', 100083: 'ttdbserverd', 100227: 'nfs_acl', 100232: 'sadmind', 150001: 'pcnfsd',
                 300019: 'amd'}
_RPC_PROCEDURES = {
    'portmapper': ('NULL', 'SET', 'UNSET', 'GETPORT', 'DUMP', 'CALLIT', 'GETTIME', 'UADDR2TADDR', 'TADDR2UADDR',
                   'GETVERSADDR', 'INDIRECT', 'GETADDRLIST', 'GETSTAT'),
    'mountd': ('NULL', 'MNT', 'DUMP', 'UMNT', 'UMNTALL', 'EXPORT', 'EXPORTALL', 'PATHCONF'),
    'status': ('NULL', 'STAT', 'MON', 'UNMON', 'UNMON_ALL', 'SIMU_CRASH', 'NOTIFY'),
    'nlockmgr': ('NULL', 'TEST', 'LOCK', 'CANCEL', 'UNLOCK', 'GRANTED', 'TEST_MSG', 'LOCK_MSG', 'CANCEL_MSG',
                 'UNLOCK_MSG', 'GRANTED_MSG', 'TEST_RES', 'LOCK_RES', 'CANCEL_RES', 'UNLOCK_RES', 'GRANTED_RES'),
}
# portmapper v3/v4 (rpcbind) number GETADDR where v2 has GETPORT
_RPCBIND_PROCEDURES = ('NULL', 'SET', 'UNSET', 'GETADDR', 'DUMP', 'CALLIT', 'GETTIME', 'UADDR2TADDR',
                       'TADDR2UADDR', 'GETVERSADDR', 'INDIRECT', 'GETADDRLIST', 'GETSTAT')
_RPC_TRANSPORTS = {6: 'tcp', 17: 'udp'}
_RPC_MAX_LIST = 100


def _rpc_program(number):
    return _RPC_PROGRAMS.get(number, str(number)) if number is not None else ''


class RPC:
    """ONC RPC - see the comment above."""
    event_type = 'rpc'
    app_protos = ('rpc', 'portmap', 'mount', 'nlm', 'stat', 'ypbind', 'ypserv', 'yppasswd', 'ypxfr', 'rquota',
                  'rstat', 'rwall', 'spray', 'bootparams', 'pcnfsd', 'klm', 'nfsacl', 'nfsauth', 'sadmind', 'nisplus')
    fields = ('rpc.xid', 'rpc.msgtyp', 'rpc.program', 'rpc.programversion', 'rpc.procedure',
              'vals(rpc.auth.flavor)', 'rpc.auth.machinename', 'rpc.auth.uid', 'rpc.auth.gid', 'vals(rpc.replystat)',
              'vals(rpc.state_accept)', 'portmap.prog', 'portmap.version', 'portmap.proto', 'portmap.port',
              'mount.path', 'vals(mount.status)', 'mount.export.directory', 'mount.export.group',
              'mount.dump.hostname', 'mount.dump.directory')

    def __init__(self):
        self.records = []
        self.open = {}           # (flow key, xid) -> body

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        xid, kind = _int(first('rpc.xid')), _int(first('rpc.msgtyp'))
        if xid is None or kind not in (0, 1):
            return               # tshark's RPC heuristic, matching a packet that isn't
        key = (pkt.flow.key, xid)
        body = self.open.get(key)
        if body is None:
            number = _int(first('rpc.program'))
            body = self.open[key] = {'xid': f'0x{xid:08x}', 'program': _rpc_program(number)}
            if number is not None:
                body['program_number'] = number
            version, procedure = _int(first('rpc.programversion')), _int(first('rpc.procedure'))
            if version is not None:
                body['version'] = version
            if procedure is not None:
                names = _RPCBIND_PROCEDURES if body['program'] == 'portmapper' and (version or 2) > 2 \
                    else _RPC_PROCEDURES.get(body['program'], ())
                body['procedure'] = names[procedure] if procedure < len(names) else f'procedure {procedure}'
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        if kind == 0:
            body['calls'] = body.get('calls', 0) + 1
            flavor = first('vals(rpc.auth.flavor)')
            if flavor:
                body['auth'] = flavor
            for name, field in (('machine_name', 'rpc.auth.machinename'), ('uid', 'rpc.auth.uid'),
                                ('gid', 'rpc.auth.gid')):
                if first(field):
                    body[name] = _int(first(field), first(field)) if name != 'machine_name' else first(field)
            self._call(body, v, first)
        else:
            stat, accept = first('vals(rpc.replystat)'), first('vals(rpc.state_accept)')
            body['reply'] = accept if stat == 'accepted' and accept else stat or 'reply'
            self._reply(body, v, first)

    @staticmethod
    def _call(body, v, first):
        if body['program'] == 'portmapper' and v['portmap.prog']:
            body['query'] = {'program': _rpc_program(_int(first('portmap.prog'))),
                             'version': _int(first('portmap.version')),
                             'transport': _RPC_TRANSPORTS.get(_int(first('portmap.proto')), first('portmap.proto'))}
        if first('mount.path'):
            body['path'] = first('mount.path')

    @staticmethod
    def _reply(body, v, first):
        if body['program'] == 'portmapper':
            if body.get('procedure') == 'DUMP' and v['portmap.prog']:
                body['mappings'] = [
                    {'program': _rpc_program(_int(p)), 'version': _int(ver),
                     'transport': _RPC_TRANSPORTS.get(_int(proto), proto), 'port': _int(port)}
                    for p, ver, proto, port in zip(v['portmap.prog'], v['portmap.version'], v['portmap.proto'],
                                                   v['portmap.port'])][:_RPC_MAX_LIST]
            elif v['portmap.port']:
                port = _int(first('portmap.port'))
                body['port'] = port
                if port == 0:
                    body['reply'] = 'not registered'
        if body['program'] == 'mountd':
            if first('vals(mount.status)'):
                body['mount_status'] = first('vals(mount.status)')
            if v['mount.export.directory']:
                body['exports'] = list(dict.fromkeys(v['mount.export.directory']))[:_RPC_MAX_LIST]
                if v['mount.export.group']:
                    body['export_clients'] = list(dict.fromkeys(v['mount.export.group']))[:_RPC_MAX_LIST]
            if v['mount.dump.hostname']:
                body['mounted_by'] = [f'{host}:{path}' for host, path in
                                      zip(v['mount.dump.hostname'], v['mount.dump.directory'])][:_RPC_MAX_LIST]

    def finish(self):
        return self.records


# ---------------------------------------------------------------- DTLS
#
# TLS over UDP (VPNs, WebRTC, CoAP and IoT security, CAPWAP) - Suricata
# parses TLS over TCP only. One record per connection's handshake, named
# the way Suricata's tls records are: the version agreed, the SNI and
# ALPNs the client asked for, the cipher suite the server picked, the
# JA3/JA3S/JA4 fingerprints, the server's certificate (DTLS 1.2 and
# before send it in the clear), WebRTC's SRTP profile, and how far the
# handshake got - a scanner's ClientHello nobody answered is still a
# record, its JA4 naming the tool.

_DTLS_VERSIONS = {0xfeff: 'DTLS 1.0', 0xfefd: 'DTLS 1.2', 0xfefc: 'DTLS 1.3', 0x0100: 'DTLS 1.0 (OpenSSL pre-0.9.8f)'}
_X509_NAMES = {'2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
               '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC'}
_X509_SAN = '2.5.29.17'
_DTLS_MAX_SANS = 20


def _dtls_version(value):
    number = _int(value)
    return _DTLS_VERSIONS.get(number, value) if number is not None else ''


def _der(data, pos):
    """A DER element at pos: (tag, start of its contents, end)."""
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    if pos + length > len(data):
        raise ValueError('truncated')
    return tag, pos, pos + length


def _der_children(data, start, end):
    while start < end:
        tag, inner, start = _der(data, start)
        yield tag, inner, start


def _oid(raw):
    parts, value = [], 0
    for b in raw:
        value = value << 7 | (b & 0x7f)
        if not b & 0x80:
            parts.append(value)
            value = 0
    first = min(parts[0] // 40, 2) if parts else 0
    return '.'.join(str(n) for n in [first, parts[0] - 40 * first] + parts[1:]) if parts else ''


def _x509_name(data, start, end):
    """A Name as Suricata writes one: 'C=US, O=Example, CN=example.com'."""
    out = []
    for _, rdn, rdn_end in _der_children(data, start, end):
        for _, atv, atv_end in _der_children(data, rdn, rdn_end):
            (_, oid_start, oid_end), value = _der(data, atv), None
            _, value_start, value_end = _der(data, oid_end)
            oid = _oid(data[oid_start:oid_end])
            text = data[value_start:value_end].decode('utf-8', 'replace')
            out.append(f'{_X509_NAMES.get(oid, oid)}={text}')
    return ', '.join(out)


def _x509_time(raw):
    text = raw.decode('ascii', 'replace').rstrip('Z')
    if len(text) == 12:                  # UTCTime: YYMMDDHHMMSS
        text = ('19' if text[:2] >= '50' else '20') + text
    return f'{text[:4]}-{text[4:6]}-{text[6:8]}T{text[8:10]}:{text[10:12]}:{text[12:14]}' if len(text) >= 14 else text


def _x509(hexbytes):
    """What Suricata's tls record says about a certificate (DER, as tshark
    shows its bytes), or {} if it can't be read."""
    import hashlib
    try:
        data = bytes.fromhex(hexbytes.replace(':', ''))
        _, cert, cert_end = _der(data, 0)
        _, tbs, tbs_end = _der(data, cert)
        fields = list(_der_children(data, tbs, tbs_end))
        if fields and fields[0][0] == 0xa0:         # [0] version
            fields = fields[1:]
        (_, serial, serial_end), _, (_, issuer, issuer_end), (_, validity, validity_end), \
            (_, subject, subject_end) = fields[:5]
        times = [data[s:e] for _, s, e in _der_children(data, validity, validity_end)]
        out = {'subject': _x509_name(data, subject, subject_end), 'issuerdn': _x509_name(data, issuer, issuer_end),
               'serial': ':'.join(f'{b:02X}' for b in data[serial:serial_end].lstrip(b'\x00') or b'\x00'),
               'fingerprint': ':'.join(f'{b:02x}' for b in hashlib.sha1(data[:cert_end]).digest())}
        if len(times) == 2:
            out['notbefore'], out['notafter'] = _x509_time(times[0]), _x509_time(times[1])
        for tag, ext, ext_end in fields[5:]:
            if tag != 0xa3:                          # [3] extensions
                continue
            _, seq, seq_end = _der(data, ext)
            for _, item, item_end in _der_children(data, seq, seq_end):
                parts = list(_der_children(data, item, item_end))
                if parts and _oid(data[parts[0][1]:parts[0][2]]) == _X509_SAN:
                    _, names, names_end = _der(data, parts[-1][1])
                    sans = [data[s:e].decode('ascii', 'replace') for t, s, e in _der_children(data, names, names_end)
                            if t == 0x82]            # dNSName
                    if sans:
                        out['san'] = sans[:_DTLS_MAX_SANS]
        return out
    except (ValueError, IndexError):
        return {}


class _DTLSConnection:
    __slots__ = ('body', 'ccs', 'server_hello')

    def __init__(self, body):
        self.body, self.ccs, self.server_hello = body, set(), False


class DTLS:
    """DTLS - see the comment above."""
    event_type = 'dtls'
    app_protos = ('dtls',)
    fields = ('dtls.record.version', 'dtls.handshake.type', 'dtls.handshake.version',
              'dtls.handshake.extensions.supported_version', 'dtls.handshake.extensions_server_name',
              'dtls.handshake.extensions_alpn_str', 'vals(dtls.handshake.ciphersuite)', 'dtls.handshake.ja3',
              'dtls.handshake.ja3_full', 'dtls.handshake.ja3s', 'dtls.handshake.ja3s_full', 'dtls.handshake.ja4',
              'vals(dtls.use_srtp.protection_profile)', 'dtls.handshake.certificate', 'dtls.record.content_type',
              'vals(dtls.alert_message.desc)')

    def __init__(self):
        self.connections = {}       # flow key -> _DTLSConnection, in the order they began

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        conn = self.connections.get(pkt.flow.key)
        if conn is None:
            conn = self.connections[pkt.flow.key] = _DTLSConnection({})
            conn.body['_flow'], conn.body['_when'] = pkt.flow, pkt.when
        body = conn.body
        from_client = (pkt.src, pkt.sport) == (pkt.flow.client, pkt.flow.cport)
        types = {_int(t) for t in v['dtls.handshake.type']}
        if 1 in types:                                    # ClientHello
            body['client_hellos'] = body.get('client_hellos', 0) + 1
            body.setdefault('client_version', _dtls_version(first('dtls.handshake.version')))
            if first('dtls.handshake.extensions_server_name'):
                body['sni'] = first('dtls.handshake.extensions_server_name')
            if v['dtls.handshake.extensions_alpn_str']:
                body['client_alpns'] = list(dict.fromkeys(v['dtls.handshake.extensions_alpn_str']))
            if first('dtls.handshake.ja3'):
                body['ja3'] = {'hash': first('dtls.handshake.ja3'), 'string': first('dtls.handshake.ja3_full')}
            if first('dtls.handshake.ja4'):
                body['ja4'] = first('dtls.handshake.ja4')
            if v['vals(dtls.use_srtp.protection_profile)']:
                body['srtp_profiles'] = list(dict.fromkeys(v['vals(dtls.use_srtp.protection_profile)']))
        if 3 in types:                                    # HelloVerifyRequest
            body['cookie_exchange'] = True
        if 2 in types:                                    # ServerHello
            conn.server_hello = True
            supported = [_dtls_version(x) for x in v['dtls.handshake.extensions.supported_version']]
            body['version'] = supported[-1] if supported else _dtls_version(first('dtls.handshake.version'))
            if v['vals(dtls.handshake.ciphersuite)']:
                body['cipher_suite'] = v['vals(dtls.handshake.ciphersuite)'][-1]
            if first('dtls.handshake.ja3s'):
                body['ja3s'] = {'hash': first('dtls.handshake.ja3s'), 'string': first('dtls.handshake.ja3s_full')}
            if v['dtls.handshake.extensions_alpn_str'] and 1 not in types:
                body['server_alpns'] = list(dict.fromkeys(v['dtls.handshake.extensions_alpn_str']))
            if v['vals(dtls.use_srtp.protection_profile)'] and 1 not in types:
                body['srtp_profile'] = v['vals(dtls.use_srtp.protection_profile)'][0]
        if 11 in types and v['dtls.handshake.certificate'] and 'subject' not in body:
            body.update(_x509(v['dtls.handshake.certificate'][0]))
        if 20 in {_int(t) for t in v['dtls.record.content_type']}:     # ChangeCipherSpec
            conn.ccs.add(from_client)
        for alert in v['vals(dtls.alert_message.desc)']:
            alerts = body.setdefault('alerts', [])
            if len(alerts) < 10:
                alerts.append(f"{'client' if from_client else 'server'}: {alert}")
        if 'version' not in body and first('dtls.record.version'):
            body['record_version'] = _dtls_version(first('dtls.record.version'))

    def finish(self):
        records = []
        for conn in self.connections.values():
            body = conn.body
            flow, when = body.pop('_flow'), body.pop('_when')
            if 'version' not in body:
                body['version'] = body.pop('record_version', '') or body.get('client_version', '')
            body.pop('record_version', None)
            if conn.ccs == {True, False}:
                body['handshake'] = 'completed'
            elif conn.server_hello:
                body['handshake'] = 'server hello'
            elif body.get('cookie_exchange'):
                body['handshake'] = 'cookie exchange only'
            elif body.get('client_hellos'):
                body['handshake'] = 'client hello only'
            else:
                body['handshake'] = 'no handshake seen'
            records.append((flow, when, self.event_type, body))
        return records


# ---------------------------------------------------------------- SOCKS
#
# A SOCKS proxy (port 1080) relays a client's connection to the host it
# names - so the flow shows only the proxy, and the real destination is
# in the handshake. One record per connection, like Zeek's socks.log: the
# version, the login methods the client offered and the one the proxy
# picked, the user name (never the password), the command and the host
# (by address or name) and port asked for, the proxy's answer and the
# address it bound for the relay - and the protocol tshark saw tunneled
# through it afterwards. An open-proxy check the proxy turned away is
# still a record.

_SOCKS_AUTH_METHODS = {0: 'no authentication', 1: 'GSSAPI', 2: 'username/password', 3: 'CHAP',
                       0xff: 'no acceptable methods'}
# The proxy's answer: SOCKS 5's codes, then SOCKS 4's (tshark's vals()
# names only SOCKS 5's)
_SOCKS_RESULTS = {0: 'succeeded', 1: 'general SOCKS server failure', 2: 'connection not allowed by ruleset',
                  3: 'network unreachable', 4: 'host unreachable', 5: 'connection refused', 6: 'TTL expired',
                  7: 'command not supported', 8: 'address type not supported', 90: 'granted',
                  91: 'rejected or failed', 92: "rejected: can't reach the client's identd",
                  93: "rejected: the client's identd gave a different user"}
# Layers tshark gives a tunneled packet's bytes it can't name
_SOCKS_UNNAMED = {'data', 'tcp.segments'}


def _socks_auth_method(value):
    number = _int(value)
    return _SOCKS_AUTH_METHODS.get(number, f'method {number}') if number is not None else ''


class SOCKS:
    """SOCKS 4, 4a and 5 - see the comment above."""
    event_type = 'socks'
    app_protos = ('socks',)
    fields = ('frame.protocols', 'socks.version', 'vals(socks.command)', 'socks.results', 'socks.auth_method',
              'socks.auth_accepted_method', 'socks.auth_status', 'socks.username', 'socks.dst', 'socks.dstV6',
              'socks.remote_name', 'socks.v4a_dns_name', 'socks.dstport', 'socks.port')

    def __init__(self):
        self.records = []
        self.sessions = {}       # flow key -> body

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        layers = first('frame.protocols').split(':')
        above = layers[layers.index('socks') + 1:] if 'socks' in layers else []
        body = self.sessions.get(pkt.flow.key)
        if above:
            # The tunnel: tshark keeps adding the handshake's socks.* fields
            # to every packet relayed after it, so only the layer above counts
            if body is not None and 'tunneled' not in body:
                named = [layer for layer in above if layer not in _SOCKS_UNNAMED]
                body['tunneled'] = named[0] if named else 'unknown'
            return
        host = first('socks.dst') or (ipv6_exploded(first('socks.dstV6')) if first('socks.dstV6') else '')
        port = _int(first('socks.port') or first('socks.dstport'))
        if body is None:
            # tshark calls anything on port 1080 SOCKS - an HTTP proxy check
            # sent there, a DCE/RPC connection whose client port it was - so
            # a record starts only at a client's greeting or request
            if not (v['socks.auth_method'] or (first('vals(socks.command)') and not first('socks.results')
                                                 and (host or first('socks.remote_name')
                                                      or first('socks.v4a_dns_name')))):
                return
            body = self.sessions[pkt.flow.key] = {}
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        if v['socks.auth_method']:
            body['version'] = first('socks.version')
            body['auth_methods'] = [_socks_auth_method(m) for m in v['socks.auth_method']]
        elif first('socks.auth_accepted_method'):
            body['auth_method'] = _socks_auth_method(first('socks.auth_accepted_method'))
            if body['auth_method'] == 'no acceptable methods':
                body['status'] = 'no acceptable authentication method'
        elif first('socks.auth_status'):
            body['login'] = 'succeeded' if _int(first('socks.auth_status')) == 0 else 'failed'
            if body['login'] == 'failed':
                body['status'] = 'login failed'
        elif first('socks.results'):
            code = _int(first('socks.results'))
            body['status'] = _SOCKS_RESULTS.get(code, f'result {code}')
            if host and host not in ('0.0.0.0', '::', '0000:0000:0000:0000:0000:0000:0000:0000'):
                body['bound_host'] = host
            if port:
                body['bound_port'] = port
        elif first('vals(socks.command)'):
            version = first('socks.version')
            body['version'] = '4a' if version == '4' and first('socks.v4a_dns_name') else version
            body['command'] = first('vals(socks.command)').lower().replace('udpassociate', 'UDP associate')
            name = first('socks.remote_name') or first('socks.v4a_dns_name')
            if name:
                body['request_name'] = name
            elif host:
                body['request_host'] = host
            if port is not None:
                body['request_port'] = port
        if first('socks.username'):
            body['user'] = first('socks.username')

    def finish(self):
        return self.records


# ---------------------------------------------------------------- RADIUS
#
# How Wi-Fi (802.1X), VPNs and network devices check a login: the device
# (the NAS) asks a RADIUS server, which accepts, rejects or challenges.
# Like Zeek's radius.log, one record per login - its Access-Request, any
# rounds of challenges (an EAP method's exchange), and the final accept
# or reject: the user name (never the password, which RADIUS hides
# anyway), the device that asked and the client's MAC, the EAP method,
# the address given and the server's reply message. Accounting gets a
# record per message: a session's Start, Stop or update, with its length
# and bytes. A scanner's Access-Request nobody answered is still a record.

_RADIUS_SERVICE_TYPES = {1: 'Login', 2: 'Framed', 3: 'Callback Login', 4: 'Callback Framed', 5: 'Outbound',
                         6: 'Administrative', 7: 'NAS Prompt', 8: 'Authenticate Only', 9: 'Callback NAS Prompt',
                         10: 'Call Check', 11: 'Callback Administrative'}
_RADIUS_PORT_TYPES = {0: 'Async', 1: 'Sync', 2: 'ISDN Sync', 3: 'ISDN Async V.120', 4: 'ISDN Async V.110',
                      5: 'Virtual', 15: 'Ethernet', 16: 'xDSL', 17: 'Cable', 18: 'Wireless - Other',
                      19: 'Wireless - IEEE 802.11', 30: 'PPPoA', 31: 'PPPoEoA', 32: 'PPPoEoE', 33: 'PPPoEoVLAN',
                      34: 'PPPoEoQinQ'}
_RADIUS_ACCT_STATUS = {1: 'Start', 2: 'Stop', 3: 'Interim-Update', 7: 'Accounting-On', 8: 'Accounting-Off'}
_RADIUS_TERMINATE_CAUSES = {1: 'User Request', 2: 'Lost Carrier', 3: 'Lost Service', 4: 'Idle Timeout',
                            5: 'Session Timeout', 6: 'Admin Reset', 7: 'Admin Reboot', 8: 'Port Error',
                            9: 'NAS Error', 10: 'NAS Request', 11: 'NAS Reboot', 12: 'Port Unneeded',
                            13: 'Port Preempted', 14: 'Port Suspended', 15: 'Service Unavailable', 16: 'Callback',
                            17: 'User Error', 18: 'Host Request'}
_RADIUS_RESULTS = {'Access-Accept': 'accepted', 'Access-Reject': 'rejected', 'Accounting-Response': 'acknowledged'}
# EAP types that aren't a login method
_EAP_NOT_METHODS = {'Identity', 'Notification', 'Legacy Nak (Response Only)'}
_EAP_SHORT_NAME = re.compile(r'\((EAP-[^)]+)\)$')


def _radius_named(names, value):
    number = _int(value)
    return names.get(number, str(number)) if number is not None else ''


class RADIUS:
    """RADIUS - see the comment above."""
    event_type = 'radius'
    app_protos = ('radius',)
    fields = ('vals(radius.code)', 'radius.id', 'radius.dup', 'radius.User_Name', 'radius.NAS_IP_Address',
              'radius.NAS_IPv6_Address', 'radius.NAS_Identifier', 'radius.NAS_Port_Type', 'radius.Service_Type',
              'radius.Called_Station_Id', 'radius.Calling_Station_Id', 'radius.Framed-IP-Address',
              'radius.Framed_IP_Address', 'radius.Reply_Message', 'vals(eap.type)', 'radius.Acct_Status_Type',
              'radius.Acct_Session_Id', 'radius.Acct_Session_Time', 'radius.Acct_Input_Octets',
              'radius.Acct_Output_Octets', 'radius.Acct_Terminate_Cause')

    def __init__(self):
        self.records = []
        self.logins = {}         # flow key -> the login under way on it
        self.open = {}           # (flow key, id) -> the record its request is in
        self.started = {}        # id(record) -> its first request's time

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        code, ident = first('vals(radius.code)'), _int(first('radius.id'))
        if not code or ident is None:
            return
        key = (pkt.flow.key, ident)
        if code.endswith('-Request') or code == 'Status-Server':
            if key in self.open and first('radius.dup'):
                self.open[key]['retransmissions'] = self.open[key].get('retransmissions', 0) + 1
                return
            body = self.logins.get(pkt.flow.key) if code == 'Access-Request' else None
            if body is None:
                body = {'message': 'Accounting-Request' if code == 'Accounting-Request' else code}
                self.records.append((pkt.flow, pkt.when, self.event_type, body))
                self.started[id(body)] = pkt.when
                if code == 'Access-Request':
                    self.logins[pkt.flow.key] = body
            body['requests'] = body.get('requests', 0) + 1
            self.open[key] = body
            self._request(body, v, first)
            return
        body = self.open.pop(key, None)
        if body is None:
            return               # a response to a request before the capture began
        body['reply'] = code
        if code == 'Access-Challenge':
            body['challenges'] = body.get('challenges', 0) + 1
        else:
            body['result'] = _RADIUS_RESULTS.get(code, code)
            if body.get('message') == 'Access-Request':
                self.logins.pop(pkt.flow.key, None)
            # from the first request - a login's every round, like Zeek's ttl
            body['response_time'] = round(pkt.when - self.started[id(body)], 6)
        if first('radius.Reply_Message'):
            body['reply_message'] = ' '.join(v['radius.Reply_Message'])[:512]
        self._addresses(body, v, first)
        self._eap(body, v)

    def _request(self, body, v, first):
        for name, field in (('user', 'radius.User_Name'), ('nas_identifier', 'radius.NAS_Identifier'),
                            ('called_station', 'radius.Called_Station_Id'),
                            ('calling_station', 'radius.Calling_Station_Id'),
                            ('session_id', 'radius.Acct_Session_Id')):
            if first(field):
                body[name] = first(field)
        nas = first('radius.NAS_IP_Address') or (ipv6_exploded(first('radius.NAS_IPv6_Address'))
                                                 if first('radius.NAS_IPv6_Address') else '')
        if nas:
            body['nas_ip'] = nas
        if first('radius.NAS_Port_Type'):
            body['port_type'] = _radius_named(_RADIUS_PORT_TYPES, first('radius.NAS_Port_Type'))
        if first('radius.Service_Type'):
            body['service_type'] = _radius_named(_RADIUS_SERVICE_TYPES, first('radius.Service_Type'))
        if first('radius.Acct_Status_Type'):
            body['message'] = 'Accounting ' + _radius_named(_RADIUS_ACCT_STATUS, first('radius.Acct_Status_Type'))
        for name, field in (('session_time', 'radius.Acct_Session_Time'), ('bytes_in', 'radius.Acct_Input_Octets'),
                            ('bytes_out', 'radius.Acct_Output_Octets')):
            if _int(first(field)) is not None:
                body[name] = _int(first(field))
        if first('radius.Acct_Terminate_Cause'):
            body['terminate_cause'] = _radius_named(_RADIUS_TERMINATE_CAUSES, first('radius.Acct_Terminate_Cause'))
        self._addresses(body, v, first)
        self._eap(body, v)

    @staticmethod
    def _addresses(body, v, first):
        framed = first('radius.Framed-IP-Address') or first('radius.Framed_IP_Address')
        if framed:
            body['framed_ip'] = framed

    @staticmethod
    def _eap(body, v):
        for kind in v['vals(eap.type)']:
            if kind and kind not in _EAP_NOT_METHODS:
                short = _EAP_SHORT_NAME.search(kind)
                method = short.group(1) if short else kind
                if method not in body.setdefault('eap_methods', []):
                    body['eap_methods'].append(method)

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


# ---------------------------------------------------------------- BACnet
#
# Building automation (HVAC, lighting, access control), over UDP 47808
# (BACnet/IP, which tshark calls bvlc) or straight over Ethernet. Three
# record types, since reads dwarf everything else: 'bacnet', one per
# action - a confirmed request other than a read (a write, a file write,
# a reinitialize or communication-control with its password, a
# subscription) paired with its reply, and each unconfirmed message
# other than I-Am and value notifications (event notifications, time
# syncs, and Who-Is/Who-Has discovery - one record per sender and question,
# counted, since a workstation can ask the same thing every few seconds
# for a day); 'bacnet_property', one per object and
# property read or reported on each connection (reads and change-of-value
# notifications counted, the last value kept); and 'bacnet_device', one
# per device announcing itself (I-Am), with its vendor. Names come from
# tshark (vals()), so its vendor and property lists stay its own. tshark
# runs a ReadPropertyMultiple reply's values together, so a value is kept
# only when a message carries exactly one.

_BACNET_READS = {'readProperty', 'readPropertyMultiple', 'readRange', 'atomicReadFile'}
_BACNET_DISCOVERY = {'who-Is', 'who-Has'}
_BACNET_VALUE_NOTIFICATIONS = {'confirmedCOVNotification', 'unconfirmedCOVNotification'}
# Messages whose first object is the device sending them, the object
# they're about following
_BACNET_FROM_DEVICE = _BACNET_VALUE_NOTIFICATIONS | {'confirmedEventNotification', 'unconfirmedEventNotification'}
_BACNET_VALUE_FIELDS = ('bacapp.present_value.real', 'bacapp.present_value.double', 'bacapp.present_value.uint',
                        'bacapp.present_value.int', 'bacapp.present_value.enum_index', 'bacapp.present_value.boolean',
                        'bacapp.present_value.char_string')
_BACNET_BINARY_OBJECTS = {'binary-input', 'binary-output', 'binary-value'}
_BACNET_REINIT_STATES = {0: 'coldstart', 1: 'warmstart', 2: 'start-backup', 3: 'end-backup', 4: 'start-restore',
                         5: 'end-restore', 6: 'abort-restore', 7: 'activate-changes'}
_BACNET_ENABLE = {0: 'enable', 1: 'disable', 2: 'disable-initiation'}
# APDU types (bacapp.type)
_BACNET_CONFIRMED, _BACNET_UNCONFIRMED, _BACNET_SIMPLE_ACK, _BACNET_COMPLEX_ACK = 0, 1, 2, 3
_BACNET_ERROR, _BACNET_REJECT, _BACNET_ABORT = 5, 6, 7


def _bacnet_tags(data, pos):
    """A BACnet APDU's tags from pos: (context tag number, value bytes),
    opening and closing tags skipped."""
    while pos < len(data):
        first = data[pos]
        pos += 1
        number, lvt = first >> 4, first & 7
        if number == 15 and pos < len(data):
            number, pos = data[pos], pos + 1
        if first & 8 and lvt in (6, 7):
            continue
        length = lvt
        if lvt == 5 and pos < len(data):
            length, pos = data[pos], pos + 1
            if length in (254, 255):
                size = 2 if length == 254 else 4
                length, pos = int.from_bytes(data[pos:pos + size], 'big'), pos + size
        yield number, data[pos:pos + length]
        pos += length


def _bacnet_string(value):
    """A character string: its character set byte, then the text."""
    if not value:
        return ''
    codec = {0: 'utf-8', 4: 'utf-16-be'}.get(value[0], 'latin-1')
    return value[1:].decode(codec, 'replace')


def _bacnet_request_details(service, hexbytes):
    """What tshark shows only as text: a reinitialize's state and
    password, a communication control's duration, enable/disable and
    password - read from the APDU's own bytes."""
    try:
        data = bytes.fromhex(hexbytes.replace(':', ''))
    except ValueError:
        return {}
    if len(data) < 4:
        return {}
    pos = 6 if data[0] & 0x08 else 4        # a segmented request's header is longer
    tags = dict(_bacnet_tags(data, pos))
    details = {}
    if service == 'reinitializeDevice':
        if 0 in tags:
            details['state'] = _BACNET_REINIT_STATES.get(int.from_bytes(tags[0], 'big'), str(int.from_bytes(tags[0], 'big')))
        if 1 in tags:
            details['password'] = _bacnet_string(tags[1])
    elif service == 'deviceCommunicationControl':
        if 0 in tags:
            details['duration'] = int.from_bytes(tags[0], 'big')
        if 1 in tags:
            details['state'] = _BACNET_ENABLE.get(int.from_bytes(tags[1], 'big'), str(int.from_bytes(tags[1], 'big')))
        if 2 in tags:
            details['password'] = _bacnet_string(tags[2])
    return details


def _bacnet_named(names, numbers):
    """tshark's names for a field's values, its numbers where it has none."""
    return [name or number for name, number in zip(names, numbers)] if len(names) == len(numbers) else list(numbers)


class _BACnetSummary:
    __slots__ = ('flow', 'first', 'body')

    def __init__(self, flow, first, body):
        self.flow, self.first, self.body = flow, first, body


class BACnet:
    """BACnet - see the comment above."""
    event_type = 'bacnet'
    app_protos = ('bvlc', 'bacnet', 'bacapp')
    fields = ('bacapp.type', 'bacapp.invoke_id', 'bacapp.confirmed_service', 'vals(bacapp.confirmed_service)',
              'bacapp.unconfirmed_service', 'vals(bacapp.unconfirmed_service)', 'bacapp.objectType',
              'vals(bacapp.objectType)', 'bacapp.instance_number', 'bacapp.property_identifier',
              'vals(bacapp.property_identifier)', 'bacapp.vendor_identifier', 'vals(bacapp.vendor_identifier)',
              'vals(bacapp.error_class)', 'vals(bacapp.error_code)', 'vals(bacapp.reject_reason)',
              'vals(bacapp.abort_reason)', 'bacapp.who_is.low_limit', 'bacapp.who_is.high_limit',
              '@bacapp', 'bacnet.dnet', 'bacnet.dadr_mstp', 'bacnet.dadr_eth', 'bacnet.dadr_tmp', 'bacnet.snet',
              'bacnet.sadr_mstp', 'bacnet.sadr_eth', 'bacnet.sadr_tmp') + _BACNET_VALUE_FIELDS

    def __init__(self):
        self.records = []
        # (flow key, routed device, invoke id) -> [(service, 'action', body)
        # or (service, 'read', summary)], oldest first. Devices behind a
        # router share its address, and each numbers its own requests'
        # invoke ids, so the routed device - a request's destination
        # network and address, its reply's source - is part of the key;
        # and a client can reuse an invoke id before its reply comes (a
        # write and a read both [1]), so a reply naming its service takes
        # the oldest request of that service.
        self.pending = {}
        self.properties = {}   # (flow key, service, object, properties) -> _BACnetSummary
        self.devices = {}      # (flow key, device instance) -> _BACnetSummary
        self.discovery = {}    # (flow key, service, range, object) -> body

    @staticmethod
    def _service(v, kind):
        return (_bacnet_named(v[f'vals(bacapp.{kind}_service)'], v[f'bacapp.{kind}_service']) or [''])[0]

    @staticmethod
    def _objects(v):
        types = _bacnet_named(v['vals(bacapp.objectType)'], v['bacapp.objectType'])
        return [f'{t},{i}' for t, i in zip(types, v['bacapp.instance_number'])]

    @staticmethod
    def _value(v, obj):
        """The message's one value, if it carries exactly one."""
        found = [(f, x) for f in _BACNET_VALUE_FIELDS for x in v[f]]
        if len(found) != 1:
            return None
        field, text = found[0]
        if field.endswith('.enum_index') and obj and obj.split(',')[0] in _BACNET_BINARY_OBJECTS:
            return {'0': 'inactive', '1': 'active'}.get(text, text)
        if field.endswith(('.real', '.double')):
            try:
                return float(text)
            except ValueError:
                return text
        if field.endswith('.boolean'):
            return text in ('1', 'True')
        if field.endswith('.char_string'):
            return text
        number = _int(text)
        return number if number is not None else text

    def feed(self, pkt, v):
        apdu = _int((v['bacapp.type'] or [''])[0])
        if apdu is None:
            return
        flow = pkt.flow
        invoke = _int((v['bacapp.invoke_id'] or [''])[0])
        side = 'd' if apdu == _BACNET_CONFIRMED else 's'
        routed = tuple((v[f'bacnet.{side}{f}'] or [''])[0] for f in ('net', 'adr_mstp', 'adr_eth', 'adr_tmp'))
        pending_key = (flow.key, routed, invoke)
        objects = self._objects(v)
        props = list(dict.fromkeys(_bacnet_named(v['vals(bacapp.property_identifier)'], v['bacapp.property_identifier'])))
        if apdu == _BACNET_CONFIRMED:
            service = self._service(v, 'confirmed')
            if service in _BACNET_READS:
                obj = objects[0] if objects else ''
                if len(objects) > 1 and service == 'readPropertyMultiple':
                    obj += f' (+{len(objects) - 1} more)'
                summary = self._summary(pkt, service, obj, props)
                summary.body['count'] += 1
                self._wait(pending_key, (service, 'read', summary))
            elif service in _BACNET_VALUE_NOTIFICATIONS:
                self._notification(pkt, v, service, objects, props)
            else:
                body = self._action(pkt, v, service, 'confirmed', objects, props)
                body['result'] = 'no reply'
                self._wait(pending_key, (service, 'action', body))
        elif apdu == _BACNET_UNCONFIRMED:
            service = self._service(v, 'unconfirmed')
            if service == 'i-Am':
                self._device(pkt, v, objects)
            elif service in _BACNET_VALUE_NOTIFICATIONS:
                self._notification(pkt, v, service, objects, props)
            else:
                self._action(pkt, v, service, 'unconfirmed', objects, props)
        elif apdu in (_BACNET_SIMPLE_ACK, _BACNET_COMPLEX_ACK, _BACNET_ERROR, _BACNET_REJECT, _BACNET_ABORT):
            # A segmented reply's later segments find nothing waiting
            waiting = self.pending.get(pending_key)
            if not waiting:
                return
            service = self._service(v, 'confirmed')
            entry = next((w for w in waiting if w[0] == service), None) if service else waiting[0]
            if entry is None:
                return
            waiting.remove(entry)
            if not waiting:
                del self.pending[pending_key]
            _, kind, target = entry
            result = self._result(apdu, v)
            if kind == 'action':
                target['result'] = result
                return
            body = target.body
            if result != 'ok':
                body['errors'] += 1
                body['last_error'] = result
                return
            value = self._value(v, objects[0] if objects else '') if apdu == _BACNET_COMPLEX_ACK else None
            if value is not None:
                body['last_value'] = value
                body['last_update'] = pkt.when

    def _wait(self, key, entry):
        waiting = self.pending.setdefault(key, [])
        waiting.append(entry)
        # a request never answered shouldn't hold its slot forever
        if len(waiting) > 8:
            del waiting[0]

    @staticmethod
    def _result(apdu, v):
        if apdu in (_BACNET_SIMPLE_ACK, _BACNET_COMPLEX_ACK):
            return 'ok'
        if apdu == _BACNET_ERROR:
            parts = [x for x in ((v['vals(bacapp.error_class)'] or [''])[0], (v['vals(bacapp.error_code)'] or [''])[0]) if x]
            return 'error: ' + ': '.join(parts) if parts else 'error'
        if apdu == _BACNET_REJECT:
            return 'rejected: ' + ((v['vals(bacapp.reject_reason)'] or ['?'])[0])
        return 'aborted: ' + ((v['vals(bacapp.abort_reason)'] or ['?'])[0])

    def _action(self, pkt, v, service, kind, objects, props):
        body = {'service': service, 'kind': kind}
        if service in _BACNET_FROM_DEVICE and len(objects) > 1:
            body['device'], objects = objects[0], objects[1:]
        if objects:
            body['object'] = objects[0]
        if props:
            body['property'] = ', '.join(props[:5]) + (' ...' if len(props) > 5 else '')
        value = self._value(v, body.get('object'))
        if value is not None and service in ('writeProperty', 'writePropertyMultiple', 'writeGroup'):
            body['value'] = value
        if service == 'who-Is' and v['bacapp.who_is.low_limit']:
            body['range'] = f"{v['bacapp.who_is.low_limit'][0]}-{(v['bacapp.who_is.high_limit'] or ['?'])[0]}"
        if service in ('reinitializeDevice', 'deviceCommunicationControl') and v['@bacapp']:
            body.update(_bacnet_request_details(service, v['@bacapp'][0]))
        if service in _BACNET_DISCOVERY:
            key = (pkt.flow.key, service, body.get('range'), body.get('object'))
            asked = self.discovery.get(key)
            if asked is not None:
                asked['count'] += 1
                asked['last_seen'] = pkt.when
                return asked
            body['count'], body['last_seen'] = 1, pkt.when
            self.discovery[key] = body
        self.records.append((pkt.flow, pkt.when, 'bacnet', body))
        return body

    def _summary(self, pkt, service, obj, props):
        label = ', '.join(props[:5]) + (' ...' if len(props) > 5 else '')
        key = (pkt.flow.key, service, obj, label)
        summary = self.properties.get(key)
        if summary is None:
            body = {'service': service, 'object': obj, 'count': 0, 'errors': 0}
            if label:
                body['property'] = label
            summary = self.properties[key] = _BACnetSummary(pkt.flow, pkt.when, body)
        return summary

    def _notification(self, pkt, v, service, objects, props):
        """A change-of-value notification: the device sending it, then the
        object it reports on."""
        obj = objects[1] if len(objects) > 1 else (objects[0] if objects else '')
        summary = self._summary(pkt, service, obj, props)
        summary.body['count'] += 1
        if objects and len(objects) > 1:
            summary.body['device'] = objects[0]
        value = self._value(v, obj)
        if value is not None:
            summary.body['last_value'] = value
            summary.body['last_update'] = pkt.when

    def _device(self, pkt, v, objects):
        instance = _int(objects[0].split(',')[-1]) if objects else None
        key = (pkt.flow.key, instance)
        device = self.devices.get(key)
        if device is None:
            body = {'device': instance, 'announcements': 0}
            vendor_ids = v['bacapp.vendor_identifier']
            if vendor_ids:
                body['vendor_id'] = _int(vendor_ids[0])
                names = v['vals(bacapp.vendor_identifier)']
                if names and names[0] and names[0] != vendor_ids[0]:
                    body['vendor'] = names[0]
            device = self.devices[key] = _BACnetSummary(pkt.flow, pkt.when, body)
        device.body['announcements'] += 1
        device.body['last_seen'] = pkt.when

    def finish(self):
        records = list(self.records)
        for body in self.discovery.values():
            body['last_seen'] = _iso_utc(body['last_seen'])
        for summary in self.properties.values():
            if 'last_update' in summary.body:
                summary.body['last_update'] = _iso_utc(summary.body['last_update'])
            records.append((summary.flow, summary.first, 'bacnet_property', summary.body))
        for device in self.devices.values():
            device.body['last_seen'] = _iso_utc(device.body['last_seen'])
            records.append((device.flow, device.first, 'bacnet_device', device.body))
        return records


# ---------------------------------------------------------------- Windows Browser
#
# NetBIOS datagrams (UDP 138) carrying the Windows Browser protocol: each
# machine announces itself to its domain or workgroup every few minutes -
# its name, Windows version and roles (domain controller, SQL server,
# master browser...) - and the browsers hold elections and hand out backup
# lists. A passive inventory of the Windows machines on a network. The
# messages repeat, so one record per sending host, name and kind of
# message, counted; a datagram to another mailslot (NETLOGON...) is
# counted the same way under its mailslot's name.

_BROWSER_ROLES = (
    (0x1, 'workstation'), (0x2, 'server'), (0x4, 'SQL server'), (0x8, 'domain controller'),
    (0x10, 'backup controller'), (0x20, 'time source'), (0x40, 'Apple'), (0x80, 'Novell'),
    (0x100, 'domain member'), (0x200, 'print server'), (0x400, 'dial-in'), (0x800, 'Xenix'),
    (0x1000, 'NT workstation'), (0x2000, 'WfW'), (0x8000, 'NT server'), (0x10000, 'potential browser'),
    (0x20000, 'backup browser'), (0x40000, 'master browser'), (0x80000, 'domain master browser'),
    (0x100000, 'OSF'), (0x200000, 'VMS'), (0x400000, 'Windows 95+'), (0x800000, 'DFS'))


def _netbios_name(name):
    """'DUALRUNNING<1d>' -> 'DUALRUNNING'."""
    return name.split('<', 1)[0].strip() if name else ''


class Browser:
    """Windows Browser - see the comment above."""
    event_type = 'browser'
    app_protos = ('nbdgm',)
    fields = ('nbdgm.source_name', 'nbdgm.destination_name', 'mailslot.name', 'vals(browser.command)',
              'browser.server', 'browser.mb_server', 'browser.os_major', 'browser.os_minor', 'browser.server_type',
              'browser.comment', 'browser.proto_major', 'browser.proto_minor', 'browser.response_computer_name',
              'browser.backup.server', 'browser.browser_to_promote')

    def __init__(self):
        self.summaries = {}    # (source address, source name, message) -> [flow, first seen, body]

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        source = _netbios_name(first('nbdgm.source_name'))
        if not source and not first('mailslot.name'):
            return
        command = first('vals(browser.command)')
        message = command or f"mailslot {first('mailslot.name') or '?'}"
        key = (pkt.src, source, message)
        summary = self.summaries.get(key)
        if summary is None:
            body = {'message': message, 'source_name': source, 'count': 0}
            destination = _netbios_name(first('nbdgm.destination_name'))
            if destination:
                body['destination_name'] = destination
            summary = self.summaries[key] = [pkt.flow, pkt.when, body]
        body = summary[2]
        body['count'] += 1
        body['last_seen'] = pkt.when
        if command:
            self._details(body, v, first)

    @staticmethod
    def _details(body, v, first):
        """What a browser message says, kept from its latest copy."""
        if first('browser.server'):
            body['name'] = first('browser.server')
        if first('browser.os_major'):
            body['os_version'] = f"{first('browser.os_major')}.{first('browser.os_minor') or 0}"
        types = first('browser.server_type')
        if types:
            try:
                bits = int(types, 16) if types.startswith('0x') else int(types)
            except ValueError:
                bits = 0
            body['roles'] = [name for bit, name in _BROWSER_ROLES if bits & bit]
        if first('browser.comment'):
            body['comment'] = first('browser.comment')
        if first('browser.mb_server'):
            body['master_browser'] = first('browser.mb_server')
        if first('browser.proto_major'):
            body['browser_version'] = f"{first('browser.proto_major')}.{first('browser.proto_minor') or 0}"
        if first('browser.response_computer_name'):
            body['reply_to'] = first('browser.response_computer_name')
        if v['browser.backup.server']:
            body['backup_servers'] = list(dict.fromkeys(v['browser.backup.server']))[:20]
        if first('browser.browser_to_promote'):
            body['promote'] = first('browser.browser_to_promote')

    def finish(self):
        records = []
        for flow, when, body in self.summaries.values():
            body['last_seen'] = _iso_utc(body['last_seen'])
            records.append((flow, when, 'browser', body))
        return records


# ---------------------------------------------------------------- LLDP and CDP
#
# Switches, routers, phones, PLCs and some PCs announce themselves to
# their neighbor on each port every half minute or so - LLDP (the IEEE
# standard) and CDP (Cisco's) - by Ethernet multicast, never routed: so
# these records are a passive inventory of the devices on the captured
# link. One record per sending MAC, device and port, counted, with what
# its latest announcement said: the device's name, description or
# platform and software, what it is (bridge, router, phone...), its
# management addresses and VLAN, and LLDP-MED's inventory (maker, model,
# serial number). An LLDP announcement with a time to live of 0 is a
# port shutting down.

_LLDP_CAPABILITIES = ((0x1, 'other'), (0x2, 'repeater'), (0x4, 'bridge'), (0x8, 'WLAN access point'),
                      (0x10, 'router'), (0x20, 'telephone'), (0x40, 'DOCSIS cable device'), (0x80, 'station'),
                      (0x100, 'C-VLAN'), (0x200, 'S-VLAN'), (0x400, 'TPMR'))
_CDP_CAPABILITIES = ((0x1, 'router'), (0x2, 'transparent bridge'), (0x4, 'source route bridge'), (0x8, 'switch'),
                     (0x10, 'host'), (0x20, 'IGMP'), (0x40, 'repeater'), (0x80, 'phone'), (0x100, 'remotely managed'),
                     (0x200, 'CVTA'), (0x400, 'MAC relay'))
_LLDP_MAX_ADDRESSES = 20


def _capabilities(value, names):
    bits = _int(value, 0)
    return [name for bit, name in names if bits & bit]


def _lldp_id(hexbytes):
    """An LLDP chassis or port ID that tshark only shows as bytes: its
    text when it's printable (a PROFINET station name, a host name),
    otherwise its bytes, colon-separated."""
    try:
        raw = bytes.fromhex(hexbytes.replace(':', ''))
    except ValueError:
        return hexbytes
    text = raw.decode('ascii', 'replace').strip()
    if raw and text.isprintable() and '�' not in text:
        return ' '.join(text.split())     # an S7 pads its ID's parts with spaces
    return ':'.join(f'{b:02x}' for b in raw)


def _addresses(*lists):
    """Addresses, each once, without the unset 0.0.0.0 and ::."""
    seen = dict.fromkeys(a for values in lists for a in values if a and a not in ('0.0.0.0', '::'))
    return list(seen)[:_LLDP_MAX_ADDRESSES]


class _Neighbors:
    """LLDP's and CDP's shared bookkeeping: one record per sending MAC,
    device and port (see the comment above)."""

    def __init__(self):
        self.devices = {}      # (source MAC, device, port) -> [flow, first seen, body]

    def _record(self, pkt, device, port):
        key = (pkt.src, device, port)
        entry = self.devices.get(key)
        if entry is None:
            entry = self.devices[key] = [pkt.flow, pkt.when, {'count': 0}]
        body = entry[2]
        body['count'] += 1
        body['last_seen'] = pkt.when
        return body

    def finish(self):
        records = []
        for flow, when, body in self.devices.values():
            body['last_seen'] = _iso_utc(body['last_seen'])
            records.append((flow, when, self.event_type, body))
        return records


class LLDP(_Neighbors):
    """LLDP - see the comment above."""
    event_type = 'lldp'
    app_protos = ('lldp',)
    fields = ('lldp.chassis.subtype', 'lldp.chassis.id', 'lldp.chassis.id.mac', 'lldp.chassis.id.ip4',
              'lldp.chassis.id.ip6', 'lldp.port.subtype', 'lldp.port.id', 'lldp.port.id.mac', 'lldp.port.id.ip4',
              'lldp.port.id.ip6', 'lldp.port.desc', 'lldp.tlv.system.name', 'lldp.tlv.system.desc',
              'lldp.tlv.system_cap', 'lldp.tlv.enable_system_cap', 'lldp.time_to_live', 'lldp.mgn.addr.ip4',
              'lldp.mgn.addr.ip6', 'lldp.ieee.802_1.port_vlan.id', 'lldp.ieee.802_1.vlan.name',
              'lldp.media.manufacturer', 'lldp.media.model', 'lldp.media.sn', 'lldp.media.hardware',
              'lldp.media.firmware', 'lldp.media.software', 'lldp.media.asset')
    _INVENTORY = (('manufacturer', 'lldp.media.manufacturer'), ('model', 'lldp.media.model'),
                  ('serial_number', 'lldp.media.sn'), ('hardware_revision', 'lldp.media.hardware'),
                  ('firmware_revision', 'lldp.media.firmware'), ('software_revision', 'lldp.media.software'),
                  ('asset_id', 'lldp.media.asset'))

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        chassis = (first('lldp.chassis.id.mac') or first('lldp.chassis.id.ip4') or first('lldp.chassis.id.ip6')
                   or _lldp_id(first('lldp.chassis.id')))
        port = (first('lldp.port.id') or first('lldp.port.id.mac') or first('lldp.port.id.ip4')
                or first('lldp.port.id.ip6'))
        if not chassis and not port:
            return
        body = self._record(pkt, chassis, port)
        body['chassis_id'], body['port_id'] = chassis, port
        for key, field in (('port_description', 'lldp.port.desc'), ('system_name', 'lldp.tlv.system.name'),
                           ('system_description', 'lldp.tlv.system.desc')) + self._INVENTORY:
            if first(field):
                body[key] = first(field)
        enabled = first('lldp.tlv.enable_system_cap') or first('lldp.tlv.system_cap')
        if enabled:
            body['capabilities'] = _capabilities(enabled, _LLDP_CAPABILITIES)
        addresses = _addresses(v['lldp.mgn.addr.ip4'], v['lldp.mgn.addr.ip6'])
        if addresses:
            body['management_addresses'] = addresses
        vlan = _int(first('lldp.ieee.802_1.port_vlan.id'))
        if vlan:
            body['vlan'] = vlan
        if v['lldp.ieee.802_1.vlan.name']:
            body['vlan_names'] = list(dict.fromkeys(v['lldp.ieee.802_1.vlan.name']))[:_LLDP_MAX_ADDRESSES]
        ttl = _int(first('lldp.time_to_live'))
        if ttl is not None:
            body['ttl'] = ttl
            if ttl == 0:
                body['shutdowns'] = body.get('shutdowns', 0) + 1


class CDP(_Neighbors):
    """CDP - see the comment above."""
    event_type = 'cdp'
    app_protos = ('cdp',)
    fields = ('cdp.version', 'cdp.ttl', 'cdp.deviceid', 'cdp.portid', 'cdp.platform', 'cdp.software_version',
              'cdp.capabilities', 'cdp.nrgyz.ip_address', 'cdp.nrgyz.ipv6_address', 'cdp.native_vlan',
              'cdp.voice_vlan', 'cdp.vtp_management_domain', 'cdp.duplex', 'cdp.system_name', 'cdp.location',
              'cdp.model_number', 'cdp.system_serial_number')

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        device, port = first('cdp.deviceid'), first('cdp.portid')
        if not device and not port:
            return
        body = self._record(pkt, device, port)
        body['device_id'], body['port_id'] = device, port
        if v['cdp.software_version']:
            body['software_version'] = '\n'.join(v['cdp.software_version'])
        for key, field in (('platform', 'cdp.platform'), ('vtp_domain', 'cdp.vtp_management_domain'),
                           ('system_name', 'cdp.system_name'), ('location', 'cdp.location'),
                           ('model', 'cdp.model_number'), ('serial_number', 'cdp.system_serial_number')):
            if first(field):
                body[key] = first(field)
        if first('cdp.capabilities'):
            body['capabilities'] = _capabilities(first('cdp.capabilities'), _CDP_CAPABILITIES)
        addresses = _addresses(v['cdp.nrgyz.ip_address'], v['cdp.nrgyz.ipv6_address'])
        if addresses:
            body['addresses'] = addresses
        for key, field in (('native_vlan', 'cdp.native_vlan'), ('voice_vlan', 'cdp.voice_vlan'),
                           ('version', 'cdp.version'), ('ttl', 'cdp.ttl')):
            number = _int(first(field))
            if number is not None:
                body[key] = number
        if first('cdp.duplex'):
            body['duplex'] = 'full' if first('cdp.duplex') in ('1', 'True') else 'half'


# ---------------------------------------------------------------- GOOSE
#
# IEC 61850 GOOSE: a protection relay publishes its dataset's values by
# Ethernet multicast - repeated as a heartbeat, and in a burst when one
# changes, stNum counting the changes and sqNum the repeats. Interlocks
# and trips travel this way. One record per state change of each
# publisher's control block: its values (and which changed), how often it
# was repeated, and any gap or reset in stNum.

# goose.Data's types, in the order a message lists its values
_GOOSE_VALUE_FIELDS = {3: 'goose.boolean', 4: 'goose.bit_string', 5: 'goose.integer', 6: 'goose.unsigned',
                       7: 'goose.floating_point', 9: 'goose.octet_string', 10: 'goose.visible_string',
                       17: 'goose.utc_time'}
_GOOSE_MAX_VALUES = 64


class GOOSE:
    """GOOSE - see the comment above."""
    event_type = 'goose'
    app_protos = ('goose',)
    fields = ('goose.appid', 'goose.gocbRef', 'goose.datSet', 'goose.goID', 'goose.stNum', 'goose.sqNum',
              'goose.simulation', 'goose.confRev', 'goose.ndsCom', 'goose.t', 'goose.Data') \
        + tuple(_GOOSE_VALUE_FIELDS.values())

    def __init__(self):
        self.records = []
        self.streams = {}      # (publisher, gocbRef) -> its current state's body

    @staticmethod
    def _values(v):
        """The message's values in order: goose.Data lists each one's type,
        and each type's field its values."""
        pending = {field: list(v[field]) for field in _GOOSE_VALUE_FIELDS.values()}
        values = []
        for kind in v['goose.Data']:
            field = _GOOSE_VALUE_FIELDS.get(_int(kind))
            if field is None:
                continue        # a structure or array: its members follow it
            value = pending[field].pop(0) if pending[field] else ''
            if field == 'goose.boolean':
                value = value in ('1', 'True')
            elif field in ('goose.integer', 'goose.unsigned'):
                value = _int(value, value)
            values.append(value)
        return values

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        stnum = _int(first('goose.stNum'))
        if stnum is None:
            return
        key = (pkt.src, first('goose.gocbRef'))
        previous = self.streams.get(key)
        if previous is not None and previous['stnum'] == stnum:
            previous['repeats'] += 1
            return
        values = self._values(v)
        body = {'gocb_ref': first('goose.gocbRef'), 'dataset': first('goose.datSet'), 'go_id': first('goose.goID'),
                'appid': _int(first('goose.appid'), first('goose.appid')), 'stnum': stnum,
                'sqnum': _int(first('goose.sqNum')), 'conf_rev': _int(first('goose.confRev')), 'repeats': 0,
                'values': values[:_GOOSE_MAX_VALUES]}
        if first('goose.t'):
            body['event_time'] = first('goose.t')
        if first('goose.simulation') in ('1', 'True'):
            body['simulation'] = True
        if first('goose.ndsCom') in ('1', 'True'):
            body['needs_commissioning'] = True
        if previous is not None:
            changed = [i for i, (a, b) in enumerate(zip(previous['values'], body['values'])) if a != b]
            if changed:
                body['changed'] = changed
            if stnum < previous['stnum']:
                body['stnum_reset_from'] = previous['stnum']
                body['anomaly'] = f"stNum reset from {previous['stnum']}"
            elif stnum > previous['stnum'] + 1:
                body['stnum_gap'] = stnum - previous['stnum'] - 1
                body['anomaly'] = f"stNum skipped {body['stnum_gap']}"
        self.streams[key] = body
        self.records.append((pkt.flow, pkt.when, 'goose', body))

    def finish(self):
        return list(self.records)


# ---------------------------------------------------------------- OPC UA
#
# OPC UA binary (opc.tcp, port 4840), industrial automation's
# client/server protocol: a client opens a secure channel, creates and
# activates a session as some user, then reads, browses, subscribes,
# writes and calls methods on the server's nodes. Its messages nest
# deeply (even a request header carries node ids), so it's read from the
# structured pass's JSON trees. Two record types: 'opcua', one per
# connection - its endpoint, security policy and mode, the client
# application and session, the user (and the password, when the token
# isn't encrypted - with security policy None it often isn't), whether
# activation worked, and how many of each service it called; and
# 'opcua_action', one per change - a node written (with the value), a
# method called (with its arguments), a node or reference added or
# deleted - with that operation's own status. With SignAndEncrypt the
# messages after the channel opens can't be read, which the session
# record counts (encrypted_messages). tshark recognizes OPC UA on port
# 4840; on another port it's a plain TCP connection.

_OPCUA_STATUS = {
    0x0000: 'Good', 0x002d: 'GoodSubscriptionTransferred', 0x002e: 'GoodCompletesAsynchronously',
    0x002f: 'GoodOverload', 0x0030: 'GoodClamped', 0x0096: 'GoodLocalOverride', 0x00a2: 'GoodEntryInserted',
    0x00a3: 'GoodEntryReplaced', 0x00a5: 'GoodNoData', 0x00a6: 'GoodMoreData', 0x00a7: 'GoodCommunicationEvent',
    0x00a8: 'GoodShutdownEvent', 0x00a9: 'GoodCallAgain', 0x00aa: 'GoodNonCriticalTimeout',
    0x00ba: 'GoodResultsMayBeIncomplete', 0x00d9: 'GoodDataIgnored', 0x00dc: 'GoodEdited',
    0x00dd: 'GoodPostActionFailed', 0x00e0: 'GoodDependentValueChanged', 0x4000: 'Uncertain',
    0x406c: 'UncertainReferenceOutOfServer', 0x408f: 'UncertainNoCommunicationLastUsableValue',
    0x4090: 'UncertainLastUsableValue', 0x4091: 'UncertainSubstituteValue', 0x4092: 'UncertainInitialValue',
    0x4093: 'UncertainSensorNotAccurate', 0x4094: 'UncertainEngineeringUnitsExceeded', 0x4095: 'UncertainSubNormal',
    0x40a4: 'UncertainDataSubNormal', 0x40bc: 'UncertainReferenceNotDeleted',
    0x40c0: 'UncertainNotAllNodesAvailable', 0x40de: 'UncertainDominantValueChanged',
    0x40e2: 'UncertainDependentValueChanged', 0x8000: 'Bad', 0x8001: 'BadUnexpectedError',
    0x8002: 'BadInternalError', 0x8003: 'BadOutOfMemory', 0x8004: 'BadResourceUnavailable',
    0x8005: 'BadCommunicationError', 0x8006: 'BadEncodingError', 0x8007: 'BadDecodingError',
    0x8008: 'BadEncodingLimitsExceeded', 0x8009: 'BadUnknownResponse', 0x800a: 'BadTimeout',
    0x800b: 'BadServiceUnsupported', 0x800c: 'BadShutdown', 0x800d: 'BadServerNotConnected',
    0x800e: 'BadServerHalted', 0x800f: 'BadNothingToDo', 0x8010: 'BadTooManyOperations',
    0x8011: 'BadDataTypeIdUnknown', 0x8012: 'BadCertificateInvalid', 0x8013: 'BadSecurityChecksFailed',
    0x8014: 'BadCertificateTimeInvalid', 0x8015: 'BadCertificateIssuerTimeInvalid',
    0x8016: 'BadCertificateHostNameInvalid', 0x8017: 'BadCertificateUriInvalid',
    0x8018: 'BadCertificateUseNotAllowed', 0x8019: 'BadCertificateIssuerUseNotAllowed',
    0x801a: 'BadCertificateUntrusted', 0x801b: 'BadCertificateRevocationUnknown',
    0x801c: 'BadCertificateIssuerRevocationUnknown', 0x801d: 'BadCertificateRevoked',
    0x801e: 'BadCertificateIssuerRevoked', 0x801f: 'BadUserAccessDenied', 0x8020: 'BadIdentityTokenInvalid',
    0x8021: 'BadIdentityTokenRejected', 0x8022: 'BadSecureChannelIdInvalid', 0x8023: 'BadInvalidTimestamp',
    0x8024: 'BadNonceInvalid', 0x8025: 'BadSessionIdInvalid', 0x8026: 'BadSessionClosed',
    0x8027: 'BadSessionNotActivated', 0x8028: 'BadSubscriptionIdInvalid', 0x802a: 'BadRequestHeaderInvalid',
    0x802b: 'BadTimestampsToReturnInvalid', 0x802c: 'BadRequestCancelledByClient', 0x8031: 'BadNoCommunication',
    0x8032: 'BadWaitingForInitialData', 0x8033: 'BadNodeIdInvalid', 0x8034: 'BadNodeIdUnknown',
    0x8035: 'BadAttributeIdInvalid', 0x8036: 'BadIndexRangeInvalid', 0x8037: 'BadIndexRangeNoData',
    0x8038: 'BadDataEncodingInvalid', 0x8039: 'BadDataEncodingUnsupported', 0x803a: 'BadNotReadable',
    0x803b: 'BadNotWritable', 0x803c: 'BadOutOfRange', 0x803d: 'BadNotSupported', 0x803e: 'BadNotFound',
    0x803f: 'BadObjectDeleted', 0x8040: 'BadNotImplemented', 0x8041: 'BadMonitoringModeInvalid',
    0x8042: 'BadMonitoredItemIdInvalid', 0x8043: 'BadMonitoredItemFilterInvalid',
    0x8044: 'BadMonitoredItemFilterUnsupported', 0x8045: 'BadFilterNotAllowed', 0x8046: 'BadStructureMissing',
    0x8047: 'BadEventFilterInvalid', 0x8048: 'BadContentFilterInvalid', 0x8049: 'BadFilterOperandInvalid',
    0x804a: 'BadContinuationPointInvalid', 0x804b: 'BadNoContinuationPoints', 0x804c: 'BadReferenceTypeIdInvalid',
    0x804d: 'BadBrowseDirectionInvalid', 0x804e: 'BadNodeNotInView', 0x804f: 'BadServerUriInvalid',
    0x8050: 'BadServerNameMissing', 0x8051: 'BadDiscoveryUrlMissing', 0x8052: 'BadSemaphoreFileMissing',
    0x8053: 'BadRequestTypeInvalid', 0x8054: 'BadSecurityModeRejected', 0x8055: 'BadSecurityPolicyRejected',
    0x8056: 'BadTooManySessions', 0x8057: 'BadUserSignatureInvalid', 0x8058: 'BadApplicationSignatureInvalid',
    0x8059: 'BadNoValidCertificates', 0x805a: 'BadRequestCancelledByRequest', 0x805b: 'BadParentNodeIdInvalid',
    0x805c: 'BadReferenceNotAllowed', 0x805d: 'BadNodeIdRejected', 0x805e: 'BadNodeIdExists',
    0x805f: 'BadNodeClassInvalid', 0x8060: 'BadBrowseNameInvalid', 0x8061: 'BadBrowseNameDuplicated',
    0x8062: 'BadNodeAttributesInvalid', 0x8063: 'BadTypeDefinitionInvalid', 0x8064: 'BadSourceNodeIdInvalid',
    0x8065: 'BadTargetNodeIdInvalid', 0x8066: 'BadDuplicateReferenceNotAllowed', 0x8067: 'BadInvalidSelfReference',
    0x8068: 'BadReferenceLocalOnly', 0x8069: 'BadNoDeleteRights', 0x806a: 'BadServerIndexInvalid',
    0x806b: 'BadViewIdUnknown', 0x806d: 'BadTooManyMatches', 0x806e: 'BadQueryTooComplex', 0x806f: 'BadNoMatch',
    0x8070: 'BadMaxAgeInvalid', 0x8071: 'BadHistoryOperationInvalid', 0x8072: 'BadHistoryOperationUnsupported',
    0x8073: 'BadWriteNotSupported', 0x8074: 'BadTypeMismatch', 0x8075: 'BadMethodInvalid',
    0x8076: 'BadArgumentsMissing', 0x8077: 'BadTooManySubscriptions', 0x8078: 'BadTooManyPublishRequests',
    0x8079: 'BadNoSubscription', 0x807a: 'BadSequenceNumberUnknown', 0x807b: 'BadMessageNotAvailable',
    0x807c: 'BadInsufficientClientProfile', 0x807d: 'BadTcpServerTooBusy', 0x807e: 'BadTcpMessageTypeInvalid',
    0x807f: 'BadTcpSecureChannelUnknown', 0x8080: 'BadTcpMessageTooLarge', 0x8081: 'BadTcpNotEnoughResources',
    0x8082: 'BadTcpInternalError', 0x8083: 'BadTcpEndpointUrlInvalid', 0x8084: 'BadRequestInterrupted',
    0x8085: 'BadRequestTimeout', 0x8086: 'BadSecureChannelClosed', 0x8087: 'BadSecureChannelTokenUnknown',
    0x8088: 'BadSequenceNumberInvalid', 0x8089: 'BadConfigurationError', 0x808a: 'BadNotConnected',
    0x808b: 'BadDeviceFailure', 0x808c: 'BadSensorFailure', 0x808d: 'BadOutOfService',
    0x808e: 'BadDeadbandFilterInvalid', 0x8097: 'BadRefreshInProgress', 0x8098: 'BadConditionAlreadyDisabled',
    0x8099: 'BadConditionDisabled', 0x809a: 'BadEventIdUnknown', 0x809b: 'BadNoData', 0x809d: 'BadDataLost',
    0x809e: 'BadDataUnavailable', 0x809f: 'BadEntryExists', 0x80a0: 'BadNoEntryExists',
    0x80a1: 'BadTimestampNotSupported', 0x80ab: 'BadInvalidArgument', 0x80ac: 'BadConnectionRejected',
    0x80ad: 'BadDisconnect', 0x80ae: 'BadConnectionClosed', 0x80af: 'BadInvalidState', 0x80b0: 'BadEndOfStream',
    0x80b1: 'BadNoDataAvailable', 0x80b2: 'BadWaitingForResponse', 0x80b3: 'BadOperationAbandoned',
    0x80b4: 'BadExpectedStreamToBlock', 0x80b5: 'BadWouldBlock', 0x80b6: 'BadSyntaxError',
    0x80b7: 'BadMaxConnectionsReached', 0x80b8: 'BadRequestTooLarge', 0x80b9: 'BadResponseTooLarge',
    0x80bb: 'BadEventNotAcknowledgeable', 0x80bd: 'BadInvalidTimestampArgument',
    0x80be: 'BadProtocolVersionUnsupported', 0x80bf: 'BadStateNotActive', 0x80c1: 'BadFilterOperatorInvalid',
    0x80c2: 'BadFilterOperatorUnsupported', 0x80c3: 'BadFilterOperandCountMismatch',
    0x80c4: 'BadFilterElementInvalid', 0x80c5: 'BadFilterLiteralInvalid', 0x80c6: 'BadIdentityChangeNotSupported',
    0x80c8: 'BadNotTypeDefinition', 0x80c9: 'BadViewTimestampInvalid', 0x80ca: 'BadViewParameterMismatch',
    0x80cb: 'BadViewVersionInvalid', 0x80cc: 'BadConditionAlreadyEnabled', 0x80cd: 'BadDialogNotActive',
    0x80ce: 'BadDialogResponseInvalid', 0x80cf: 'BadConditionBranchAlreadyAcked',
    0x80d0: 'BadConditionBranchAlreadyConfirmed', 0x80d1: 'BadConditionAlreadyShelved',
    0x80d2: 'BadConditionNotShelved', 0x80d3: 'BadShelvingTimeOutOfRange', 0x80d4: 'BadAggregateListMismatch',
    0x80d5: 'BadAggregateNotSupported', 0x80d6: 'BadAggregateInvalidInputs', 0x80d7: 'BadBoundNotFound',
    0x80d8: 'BadBoundNotSupported', 0x80da: 'BadAggregateConfigurationRejected', 0x80db: 'BadTooManyMonitoredItems',
    0x80e1: 'BadDominantValueChanged', 0x80e3: 'BadDependentValueChanged', 0x80e4: 'BadRequestNotAllowed',
    0x80e5: 'BadTooManyArguments', 0x80e6: 'BadSecurityModeInsufficient'}
_OPCUA_SECURITY_MODES = {1: 'None', 2: 'Sign', 3: 'SignAndEncrypt'}
_OPCUA_TOKENS = {321: 'anonymous', 324: 'username', 327: 'certificate', 940: 'issued'}
_OPCUA_ATTRIBUTES = {
    1: 'NodeId', 2: 'NodeClass', 3: 'BrowseName', 4: 'DisplayName', 5: 'Description', 6: 'WriteMask',
    7: 'UserWriteMask', 8: 'IsAbstract', 9: 'Symmetric', 10: 'InverseName', 11: 'ContainsNoLoops',
    12: 'EventNotifier', 13: 'Value', 14: 'DataType', 15: 'ValueRank', 16: 'ArrayDimensions', 17: 'AccessLevel',
    18: 'UserAccessLevel', 19: 'MinimumSamplingInterval', 20: 'Historizing', 21: 'Executable',
    22: 'UserExecutable', 23: 'DataTypeDefinition', 24: 'RolePermissions', 25: 'UserRolePermissions',
    26: 'AccessRestrictions', 27: 'AccessLevelEx'}
# Requests that change the server, and the list each one's operations are in
_OPCUA_CHANGES = {'WriteRequest': 'NodesToWrite', 'CallRequest': 'MethodsToCall', 'AddNodesRequest': 'NodesToAdd',
                  'DeleteNodesRequest': 'NodesToDelete', 'AddReferencesRequest': 'ReferencesToAdd',
                  'DeleteReferencesRequest': 'ReferencesToDelete'}
_OPCUA_MAX_ACTIONS_PER_REQUEST = 100


def _opcua_hex(text):
    """An enumeration or status code tshark writes as hex ('0x0000000d')."""
    try:
        return int(text, 16) if str(text).startswith('0x') else int(text)
    except (TypeError, ValueError):
        return None


def _opcua_status(text):
    """A status code's name (tshark's), or its hex."""
    code = _opcua_hex(text)
    if code is None:
        return str(text)
    if code & 0xffff == 0 and (code >> 16) in _OPCUA_STATUS:
        return _OPCUA_STATUS[code >> 16]
    return f'0x{code:08x}'


def _child(tree, name):
    """A JSON subtree's child by its label's name - tshark keys a
    structure 'Name: Type'."""
    if not isinstance(tree, dict):
        return None
    for key, value in tree.items():
        if key == name or key.split(':', 1)[0] == name:
            return value
    return None


def _items(array):
    """An 'Array of X' subtree's elements, in order."""
    if not isinstance(array, dict):
        return []
    return [value for key, value in array.items() if key.startswith('[') and isinstance(value, dict)]


def _opcua_node(tree):
    """A NodeId subtree as OPC UA writes one: 'ns=1;s=the.answer', 'i=85'."""
    if not isinstance(tree, dict):
        return ''
    ns = tree.get('opcua.nodeid.nsindex') or tree.get('opcua.nodeid.nsid') or '0'
    for field, kind in (('numeric', 'i'), ('string', 's'), ('guid', 'g'), ('bytestring', 'b')):
        value = tree.get(f'opcua.nodeid.{field}')
        if value is not None:
            return (f'ns={ns};' if ns != '0' else '') + f'{kind}={value}'
    return ''


def _opcua_variant(tree):
    """A Variant subtree's value: a scalar, or the first few of an array."""
    if not isinstance(tree, dict):
        return None
    values = [v for k, v in _flatten(tree).items() if k.startswith('opcua.') and not k.startswith('opcua.variant.')
              and k not in ('opcua.ArraySize',)]
    flat = [x for v in values for x in v]
    if not flat:
        return None
    if len(flat) == 1:
        return flat[0]
    return ', '.join(str(x) for x in flat[:10]) + (' ...' if len(flat) > 10 else '')


def _opcua_password(token):
    """A UserName token's password, if it was sent in the clear."""
    password = token.get('opcua.Password')
    if password is None or token.get('opcua.EncryptionAlgorithm'):
        return None
    try:
        return bytes.fromhex(password.replace(':', '')).decode('utf-8', 'replace')
    except ValueError:
        return None


class _OPCUASession:
    __slots__ = ('flow', 'first', 'body', 'waiting')

    def __init__(self, flow, first):
        self.flow, self.first = flow, first
        self.body = {'services': {}, 'errors': 0}
        self.waiting = {}      # request id -> (service, [action bodies])


class OPCUA:
    """OPC UA - see the comment above."""
    event_type = 'opcua'
    app_protos = ('opcua',)
    tshark_protocols = ('opcua',)
    layers = ('opcua',)
    display_filter = 'opcua'

    def __init__(self):
        self.sessions = {}     # flow key -> _OPCUASession
        self.actions = []

    def feed_json(self, pkt, layers):
        session = self.sessions.get(pkt.flow.key)
        if session is None:
            session = self.sessions[pkt.flow.key] = _OPCUASession(pkt.flow, pkt.when)
        for pdu in _pdus(layers.get('opcua')):
            if isinstance(pdu, dict):
                self._message(pkt, session, pdu)

    def _message(self, pkt, session, pdu):
        body = session.body
        kind = pdu.get('opcua.transport.type')
        if kind == 'HEL' and pdu.get('opcua.transport.endpoint'):
            body.setdefault('endpoint', pdu['opcua.transport.endpoint'])
        elif kind == 'ERR':
            body['transport_error'] = _opcua_status(pdu.get('opcua.transport.error', ''))
        elif kind == 'OPN' and pdu.get('opcua.security.spu'):
            body.setdefault('security_policy', pdu['opcua.security.spu'].rsplit('#', 1)[-1])
        message = _child(pdu, 'Message')
        if not isinstance(message, dict):
            # A channel's security policy is in the clear; with one other
            # than None its mode may be SignAndEncrypt (which an encrypted
            # OPN hides), and a final chunk that doesn't decode is encrypted
            if kind == 'MSG' and pdu.get('opcua.transport.chunk') == 'F' and body.get('security_policy') not in (None, 'None'):
                body['encrypted_messages'] = body.get('encrypted_messages', 0) + 1
            return
        name = next((k.split(':', 1)[0] for k in message if not k.startswith('TypeId')), None)
        tree = message.get(name) if name in message else _child(message, name) if name else None
        if not name or not isinstance(tree, dict):
            return
        request_id = pdu.get('opcua.sequence.rqid')
        if name.endswith('Request'):
            self._request(pkt, session, name, tree, request_id)
        elif name.endswith('Response') or name == 'ServiceFault':
            self._response(session, name, tree, request_id)

    def _request(self, pkt, session, name, tree, request_id):
        body = session.body
        service = name[:-len('Request')]
        body['services'][service] = body['services'].get(service, 0) + 1
        if name == 'OpenSecureChannelRequest':
            mode = _opcua_hex(tree.get('opcua.MessageSecurityMode'))
            if mode in _OPCUA_SECURITY_MODES:
                body['security_mode'] = _OPCUA_SECURITY_MODES[mode]
        elif name == 'CreateSessionRequest':
            client = _child(tree, 'ClientDescription') or {}
            app_name = (_child(client, 'ApplicationName') or {}).get('opcua.loctext.Text') if isinstance(client, dict) else None
            for key, value in (('client_application', app_name), ('client_uri', client.get('opcua.ApplicationUri')),
                               ('client_product', client.get('opcua.ProductUri')),
                               ('session_name', tree.get('opcua.SessionName')),
                               ('endpoint', tree.get('opcua.EndpointUrl'))):
                if value:
                    body[key] = value if key != 'endpoint' else body.get('endpoint', value)
        elif name == 'ActivateSessionRequest':
            token_tree = _child(tree, 'UserIdentityToken') or {}
            type_id = _int((_child(token_tree, 'TypeId') or {}).get('opcua.nodeid.numeric'), None)
            token = next((v for k, v in token_tree.items() if k.endswith('IdentityToken') or 'IdentityToken:' in k), {})                 if isinstance(token_tree, dict) else {}
            if type_id in _OPCUA_TOKENS:
                body['user_token'] = _OPCUA_TOKENS[type_id]
            if isinstance(token, dict):
                if token.get('opcua.PolicyId'):
                    body['user_policy'] = token['opcua.PolicyId']
                if token.get('opcua.UserName'):
                    body['username'] = token['opcua.UserName']
                password = _opcua_password(token)
                if password is not None:
                    body['password'] = password
                elif token.get('opcua.Password'):
                    body['password_encrypted'] = True
        actions = self._changes(pkt, name, tree) if name in _OPCUA_CHANGES else []
        if request_id is not None:
            session.waiting[request_id] = (service, actions)
            if len(session.waiting) > 256:
                session.waiting.pop(next(iter(session.waiting)))

    def _changes(self, pkt, name, tree):
        actions = []
        for item in _items(_child(tree, _OPCUA_CHANGES[name]))[:_OPCUA_MAX_ACTIONS_PER_REQUEST]:
            action = {'service': name[:-len('Request')]}
            if name == 'WriteRequest':
                action['node'] = _opcua_node(_child(item, 'NodeId'))
                attribute = _opcua_hex(item.get('opcua.AttributeId'))
                if attribute is not None:
                    action['attribute'] = _OPCUA_ATTRIBUTES.get(attribute, str(attribute))
                value = _opcua_variant(_child(_child(item, 'Value') or {}, 'Value'))
                if value is not None:
                    action['value'] = value
            elif name == 'CallRequest':
                action['node'] = _opcua_node(_child(item, 'MethodId'))
                action['object'] = _opcua_node(_child(item, 'ObjectId'))
                arguments = [_opcua_variant(arg) for arg in _items(_child(item, 'InputArguments'))]
                if arguments:
                    action['arguments'] = [a for a in arguments[:10] if a is not None]
            elif name == 'AddNodesRequest':
                action['node'] = _opcua_node(_child(item, 'RequestedNewNodeId'))
                action['parent'] = _opcua_node(_child(item, 'ParentNodeId'))
                browse = _child(item, 'BrowseName') or {}
                if isinstance(browse, dict) and browse.get('opcua.qualname.Name'):
                    action['browse_name'] = browse['opcua.qualname.Name']
            elif name == 'DeleteNodesRequest':
                action['node'] = _opcua_node(_child(item, 'NodeId'))
            else:
                action['node'] = _opcua_node(_child(item, 'SourceNodeId'))
                target = _child(item, 'TargetNodeId')
                if isinstance(target, dict):
                    action['target'] = _opcua_node(target)
            action['result'] = 'no response'
            self.actions.append((pkt.flow, pkt.when, 'opcua_action', action))
            actions.append(action)
        return actions

    def _response(self, session, name, tree, request_id):
        body = session.body
        header = _child(tree, 'ResponseHeader') or {}
        result = _opcua_status(header.get('opcua.ServiceResult', '0x00000000')) if isinstance(header, dict) else 'Good'
        waiting = session.waiting.pop(request_id, None) if request_id is not None else None
        service, actions = waiting if waiting else (name[:-len('Response')], [])
        if name == 'ServiceFault' or not result.startswith('Good'):
            body['errors'] += 1
            body['last_error'] = f'{service}: {result}'
        if service == 'ActivateSession':
            body['activation'] = result
        if not actions:
            return
        results = _child(tree, 'Results')
        statuses = []
        if isinstance(results, dict):
            listed = results.get('opcua.Results')
            if listed is not None:
                statuses = listed if isinstance(listed, list) else [listed]
            else:
                statuses = [item.get('opcua.StatusCode') for item in _items(results)]
        for i, action in enumerate(actions):
            if not result.startswith('Good'):
                action['result'] = result
            elif i < len(statuses) and statuses[i] is not None:
                action['result'] = _opcua_status(statuses[i])
            else:
                action['result'] = result

    def finish(self):
        records = []
        for session in self.sessions.values():
            # a lone response, its request before the capture, says nothing
            if session.body['services'] or len(session.body) > 2:
                records.append((session.flow, session.first, 'opcua', session.body))
        return records + self.actions


# ---------------------------------------------------------------- structured protocols
#
# Protocols whose messages nest - an OPC UA write's node ids beside its
# request header's, several commands in one packet - can't be read from flat
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
PROTOCOLS = (LLMNR, NBNS, DHCPv6, Syslog, DTLS, RPC, SOCKS, RADIUS, SSDP, S7comm, Telnet, IEC104, BACnet, GOOSE, Browser, LLDP, CDP)
# ... and from the structured pass (shark_analyzer._structured_pass): none
# yet - it's for a protocol whose messages nest, which flat fields can't
# keep apart (several commands per packet, a token inside a command).
STRUCTURED_PROTOCOLS = (OPCUA,)
# Flow application protocols with transaction records here - every other
# one gets a connection tab (db.CONNECTION_TYPE_PREFIX) instead.
RECORDED_APP_PROTOS = frozenset(p for proto in PROTOCOLS + STRUCTURED_PROTOCOLS for p in proto.app_protos)
