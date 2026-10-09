#!/usr/bin/env python3
"""tshark's part of a PCAP analysis: the protocols Suricata doesn't parse.

Suricata stays the source of truth for every protocol it parses. Alongside
it, the same capture is queued here for tshark, which decodes far more
protocols - but packet by packet, the way Wireshark shows them. This
module turns that packet stream into Suricata-shaped records, written to
shark.db (the same schema as the analysis's events.db), and once both are
done merges into events.db what Suricata lacks (merge).

It builds one 'flow' record per conversation (tshark's tcp.stream /
udp.stream numbers, or addresses for anything without a stream), in
Suricata's own flow-event layout - addresses, ports, packet and byte
counts per direction, start and end - plus the protocols tshark found in
it and its Community ID, which matches Suricata's community_id for the
same flow. shark_protocols adds one record per transaction for the
protocols it describes (LLMNR, NBNS, SSDP, S7comm).

tshark runs once per capture with plain field output (-T fields): its
JSON output is several times slower and many times larger for the same
packets (measured: 532 MB pcap, 10.6s and 81 MB of fields vs 168s and
8.5 GB of full JSON). It runs at low CPU and I/O priority, one capture
at a time, under a timeout and a memory limit (config.SHARK_MAX_MEMORY_BYTES,
across the build and its tshark). tshark's memory grows with the capture's
packet count (about 930 bytes per packet measured), so captures over
config.SHARK_BACKGROUND_MAX_PACKETS only run when the user asks. The
Settings switch (enabled/set_enabled) turns tshark off altogether.

Files in the analysis directory:
    shark.db       the records, written to shark.db.tmp then renamed, so
                   a reader never sees a half-built database
    .shark_error   why the last run failed
"""

import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone

import sqlite3

import config
from db import (create_shark_db, iter_events_json, replace_tshark_events, suricata_identified_flows,
                tshark_merge_stamp, _iso_epoch)
from shark_protocols import PROTOCOLS, RECORDED_APP_PROTOS, STRUCTURED_PROTOCOLS, Packet

SHARK_DB = 'shark.db'
SHARK_ERROR = '.shark_error'
SHARK_ARTIFACTS = (SHARK_DB, SHARK_DB + '-wal', SHARK_DB + '-shm', SHARK_DB + '.tmp', SHARK_ERROR)
# Stamped into each shark.db (SQLite's user_version). Bump it whenever a
# change here or in shark_protocols changes what a run produces: a
# shark.db stamped with an older version is rebuilt the next time its
# status is asked for, so existing analyses pick up the change.
SHARK_FORMAT_VERSION = 10

# The fields every packet is read for, one per column of tshark's
# tab-separated output, in this order - then each of shark_protocols'
# fields. Every occurrence of a repeated field is output, joined by
# _AGGREGATOR; these base fields take the last one, so a tunneled packet
# (IP in GRE/VXLAN, etc.) reports its inner addresses and ports - the flow
# Suricata also reports.
_FIELDS = (
    'frame.time_epoch', 'frame.len', 'frame.protocols',
    'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'ip.proto', 'ipv6.nxt',
    'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport',
    'tcp.stream', 'udp.stream', 'tcp.flags.syn', 'tcp.flags.ack',
    'eth.src', 'eth.dst', 'communityid', 'frame.number',
)
(_F_TIME, _F_LEN, _F_PROTOS, _F_IP_SRC, _F_IP_DST, _F_IP6_SRC, _F_IP6_DST, _F_IP_PROTO,
 _F_IP6_NXT, _F_TCP_SPORT, _F_TCP_DPORT, _F_UDP_SPORT, _F_UDP_DPORT, _F_TCP_STREAM,
 _F_UDP_STREAM, _F_SYN, _F_ACK, _F_ETH_SRC, _F_ETH_DST, _F_CID, _F_FRAME) = range(len(_FIELDS))
# Each field once: tshark fills only one column of a field asked for twice,
# and protocols share fields (SSDP reads HTTP's) - so each protocol finds
# its fields by name (_COLUMN), not by position.
# The fields _is_reply reads to orient a flow by its first request or
# reply - requested whether or not any protocol here keeps records of them.
_ORIENTATION_FIELDS = ('dns.flags.response', 'nbns.flags.response', 'http.response.code', 'http.request.method',
                       'ftp.response.code', 'ftp.request.command', 's7comm.header.rosctr', 'tls.handshake.type')
_PROTOCOL_FIELDS = tuple(dict.fromkeys(f for f in [f for proto in PROTOCOLS for f in proto.fields] + list(_ORIENTATION_FIELDS)
                                       if f not in _FIELDS))
_ALL_FIELDS = _FIELDS + _PROTOCOL_FIELDS
_COLUMN = {field: i for i, field in enumerate(_ALL_FIELDS)}
# Joins a repeated field's values. tshark escapes control characters
# inside a value (a tab comes out as the two characters \t), so this can
# never appear in one.
_AGGREGATOR = '\x1f'

# IP protocol numbers Suricata names in a flow's proto field.
_IP_PROTO_NAMES = {'1': 'ICMP', '2': 'IGMP', '6': 'TCP', '17': 'UDP', '47': 'GRE',
                   '50': 'ESP', '58': 'IPv6-ICMP', '89': 'OSPF', '112': 'VRRP', '132': 'SCTP'}

# tshark's names for protocols Suricata calls something else - a flow's
# app_proto uses Suricata's name, so the two views agree (its
# shark.protocols keeps tshark's own names).
SURICATA_APP_PROTO_NAMES = {'mbtcp': 'modbus', 'smb2': 'smb', 'kerberos': 'krb5', 'isakmp': 'ike',
                            'vnc': 'rfb', 'pop': 'pop3', 'bt-dht': 'bittorrent-dht'}

_TRANSPORT_LAYERS = {'tcp', 'udp', 'sctp'}
# Layers that only carry another protocol, or carry undecoded payload -
# never a flow's application protocol. tpkt/cotp carry S7comm and MMS,
# nbss carries SMB, and the rest are tshark's names for raw data or
# reassembly bookkeeping.
_CARRIER_LAYERS = {'tpkt', 'cotp', 'nbss', 'tcp.segments', 'data', 'data-text-lines', 'media'}
# Layers that are the application protocol unless another follows them:
# ONC RPC on its own (portmapper) is the protocol, but carries NFS.
_WRAPPER_LAYERS = {'rpc'}


def shark_db_path(dir_path):
    return os.path.join(dir_path, SHARK_DB)


def tshark_command(pcap_path):
    """The tshark command that dumps _ALL_FIELDS for every packet."""
    cmd = ['tshark', '-n', '-r', pcap_path, '--enable-protocol', 'communityid',
           '-T', 'fields', '-E', 'separator=\t', '-E', 'occurrence=a', '-E', 'aggregator=' + _AGGREGATOR]
    for field in _ALL_FIELDS:
        cmd += ['-e', field]
    return cmd


def app_protocol(protocols):
    """A packet's application protocol from its frame.protocols stack
    ('eth:ethertype:ip:tcp:tls' -> 'tls'): the first layer above the
    transport that isn't a carrier ('...:tcp:tpkt:cotp:s7comm' ->
    's7comm'), or, with no TCP/UDP/SCTP layer, the topmost layer
    ('eth:ethertype:arp' -> 'arp'). '' when there's nothing above the
    transport (a bare SYN or ACK)."""
    layers = protocols.split(':') if protocols else []
    above = None
    for i, layer in enumerate(layers):
        if layer in _TRANSPORT_LAYERS:
            above = layers[i + 1:]
            break
    if above is None:
        candidates = [layer for layer in layers if layer not in _CARRIER_LAYERS and layer != 'ethertype']
        return candidates[-1] if candidates else ''
    above = [layer for layer in above if layer not in _CARRIER_LAYERS]
    for i, layer in enumerate(above):
        if layer not in _WRAPPER_LAYERS or i == len(above) - 1:
            return SURICATA_APP_PROTO_NAMES.get(layer, layer)
    return ''


_EXPLODED = {}


def ipv6_exploded(address):
    """An IPv6 address written out in full, the way Suricata logs every
    one (2001:0db8:0000:...), so filters and pivots match across both
    views. Unparseable input comes back unchanged."""
    if address not in _EXPLODED:
        if len(_EXPLODED) > 100000:
            _EXPLODED.clear()
        try:
            _EXPLODED[address] = ipaddress.IPv6Address(address).exploded
        except ValueError:
            _EXPLODED[address] = address
    return _EXPLODED[address]


def _iso(epoch):
    """Suricata's timestamp format, so both views sort and compare alike."""
    when = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return when.strftime('%Y-%m-%dT%H:%M:%S.%f+0000')


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _is_group_address(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_multicast or (ip.version == 4 and (address == '255.255.255.255' or address.endswith('.255')))


def _flag(value):
    return {'1': True, 'True': True, '0': False, 'False': False}.get(value)


def _first_value(cols, field):
    i = _COLUMN[field]
    return cols[i].split(_AGGREGATOR)[0] if i < len(cols) and cols[i] else ''


def _is_reply(cols):
    """Whether a packet is a server's reply (True), a client's request
    (False), or can't say (None), from the protocols that mark it:
    DNS/mDNS/LLMNR and NBNS's response flag, an HTTP/SSDP or FTP response
    vs request, an S7comm ack vs job, a TLS server vs client hello.
    Modbus marks neither."""
    for field in ('dns.flags.response', 'nbns.flags.response'):
        flag = _flag(_first_value(cols, field))
        if flag is not None:
            return flag
    for reply, request in (('http.response.code', 'http.request.method'),
                           ('ftp.response.code', 'ftp.request.command')):
        if _first_value(cols, reply):
            return True
        if _first_value(cols, request):
            return False
    rosctr = _first_value(cols, 's7comm.header.rosctr')
    if rosctr in ('1', '2', '3'):
        return rosctr != '1'
    return {'1': False, '2': True}.get(_first_value(cols, 'tls.handshake.type'))


class _Flow:
    __slots__ = ('key', 'proto', 'ip_v', 'client', 'server', 'cport', 'sport', 'first', 'last',
                 'pkts_ts', 'pkts_tc', 'bytes_ts', 'bytes_tc', 'protocols', 'app_proto', 'community_id',
                 'stream', 'client_set_by_syn', 'client_set_by_message', 'first_frame', 'last_frame')

    def __init__(self, key, proto, ip_v, src, dst, sport, dport, when, stream):
        self.key, self.proto, self.ip_v, self.stream = key, proto, ip_v, stream
        self.client, self.server, self.cport, self.sport = src, dst, sport, dport
        self.first = self.last = when
        self.pkts_ts = self.pkts_tc = self.bytes_ts = self.bytes_tc = 0
        self.protocols = {}
        self.app_proto = ''
        self.community_id = ''
        self.client_set_by_syn = self.client_set_by_message = False
        self.first_frame = self.last_frame = 0     # its first and last packet's frame numbers

    def _swap(self):
        self.client, self.server = self.server, self.client
        self.cport, self.sport = self.sport, self.cport
        self.pkts_ts, self.pkts_tc = self.pkts_tc, self.pkts_ts
        self.bytes_ts, self.bytes_tc = self.bytes_tc, self.bytes_ts

    def orient(self, src, sport, is_reply):
        """The flow's first request or reply (see _is_reply) settles which
        side is the client, unless a SYN already has: a capture that starts
        mid-conversation can open on the server's reply - whose sender
        would otherwise be taken for the client, and every record on the
        flow addressed backwards. Suricata keeps the first sender as the
        client (and then doesn't recognize the protocol), so these flows
        are the one place the two views' directions differ."""
        if self.client_set_by_syn or self.client_set_by_message:
            return
        self.client_set_by_message = True
        sent_by_client = src == self.client and sport == self.cport
        # Never make a multicast or broadcast address the client: an
        # announcement (an mDNS response to the group) is a reply nobody
        # asked for, and the group sent nothing.
        if is_reply == sent_by_client and not _is_group_address(self.server):
            self._swap()

    def add(self, src, sport, length, when, app, community_id, syn_only, from_client=None):
        """from_client, if given, says which way the packet went instead
        of src/sport (an ICMP error about this flow - see build_records)."""
        # The client is whoever sent the SYN; failing that (a capture that
        # starts mid-connection, or UDP), whoever sent the first packet.
        if syn_only and not self.client_set_by_syn:
            if src != self.client or sport != self.cport:
                self._swap()
            self.client_set_by_syn = True
        if from_client is None:
            from_client = src == self.client and sport == self.cport
        if from_client:
            self.pkts_ts += 1
            self.bytes_ts += length
        else:
            self.pkts_tc += 1
            self.bytes_tc += length
        self.first, self.last = min(self.first, when), max(self.last, when)
        if app:
            self.protocols[app] = self.protocols.get(app, 0) + 1
            if not self.app_proto:
                self.app_proto = app
        if community_id and not self.community_id:
            self.community_id = community_id

    def record(self, when, event_type, body):
        """A transaction record on this flow, addressed client to server
        like the flow itself (Suricata addresses its transactions the same
        way)."""
        event = {'timestamp': _iso(when), 'event_type': event_type,
                 'src_ip': self.client, 'dest_ip': self.server, 'proto': self.proto, event_type: body}
        if self.ip_v:
            event['ip_v'] = self.ip_v
        if self.proto in ('TCP', 'UDP', 'SCTP'):
            event['src_port'], event['dest_port'] = self.cport, self.sport
        if self.community_id:
            event['community_id'] = self.community_id
        return event

    def event(self):
        flow = {
            'pkts_toserver': self.pkts_ts, 'pkts_toclient': self.pkts_tc,
            'bytes_toserver': self.bytes_ts, 'bytes_toclient': self.bytes_tc,
            'start': _iso(self.first), 'end': _iso(self.last),
            'age': int(self.last - self.first),
        }
        event = {
            'timestamp': _iso(self.first), 'event_type': 'flow',
            'src_ip': self.client, 'dest_ip': self.server, 'proto': self.proto,
            'app_proto': self.app_proto, 'flow': flow,
            'shark': {'protocols': dict(sorted(self.protocols.items(), key=lambda kv: -kv[1]))},
        }
        if self.ip_v:
            event['ip_v'] = self.ip_v
        if self.proto in ('TCP', 'UDP', 'SCTP'):
            event['src_port'], event['dest_port'] = self.cport, self.sport
        if self.stream is not None:
            event['shark']['stream'] = self.stream
        if self.community_id:
            event['community_id'] = self.community_id
        return event


_ESCAPE = re.compile(r'\\(x[0-9a-fA-F]{2}|.)')
_ESCAPES = {'t': '\t', 'n': '\n', 'r': '\r', '\\': '\\'}


def _unescape(value):
    """Undo tshark's escaping of a field value: \\t, \\n, \\r, \\\\ and \\xNN."""
    if '\\' not in value:
        return value
    return _ESCAPE.sub(lambda m: _ESCAPES.get(m.group(1)) or (chr(int(m.group(1)[1:], 16))
                                                            if m.group(1)[0] == 'x' else m.group(1)), value)


def _last(value):
    return value.rsplit(_AGGREGATOR, 1)[-1]


def build_records(lines):
    """Turn tshark's per-packet field lines (tshark_command's output) into
    records: one flow per conversation, in order of first packet, then
    shark_protocols' transaction records."""
    return list(iter_records(lines))


def iter_records(lines, pcap_path=None, deadline=None):
    """build_records' records, one at a time: a flow's is built as it's
    handed out and the flow then let go, so a capture's flows - most of
    its records - never exist twice over, or all at once as records.
    Given the capture's path, the structured protocols' records too
    (_structured_pass) - for which tshark reads it again."""
    flows = {}
    last_frame = 0
    protocols = [(proto(), [_COLUMN[field] for field in proto.fields]) for proto in PROTOCOLS]
    for line in lines:
        cols = line.rstrip('\n').split('\t')
        if len(cols) < len(_FIELDS):
            continue
        f = [_last(c) for c in cols[:len(_FIELDS)]]
        try:
            when = float(f[_F_TIME])
        except ValueError:
            continue
        length = _int(f[_F_LEN])
        app = app_protocol(f[_F_PROTOS])
        # An ICMP error (port unreachable, TTL exceeded...) carries a copy
        # of the packet it's about, whose addresses and ports are what the
        # last-occurrence fields read - so it lands in that packet's flow,
        # where Suricata (almost always) counts it too. It travels the other
        # way from the copy, so its direction comes from its own (outer)
        # source, and the copy is never fed to the protocol records as a
        # real message.
        icmp_error = ':icmp:ip:' in f[_F_PROTOS] or ':icmpv6:ipv6:' in f[_F_PROTOS]
        if icmp_error:
            app = ''
            outer_src = cols[_F_IP_SRC].split(_AGGREGATOR)[0] if f[_F_IP_SRC] else \
                ipv6_exploded(cols[_F_IP6_SRC].split(_AGGREGATOR)[0])
        if f[_F_IP_SRC] or f[_F_IP6_SRC]:
            ip_v = 4 if f[_F_IP_SRC] else 6
            if ip_v == 4:
                src, dst = f[_F_IP_SRC], f[_F_IP_DST]
            else:
                src, dst = ipv6_exploded(f[_F_IP6_SRC]), ipv6_exploded(f[_F_IP6_DST])
        else:
            ip_v, src, dst = 0, f[_F_ETH_SRC], f[_F_ETH_DST]
        stream = None
        if f[_F_TCP_STREAM]:
            proto, stream = 'TCP', _int(f[_F_TCP_STREAM])
            sport, dport = _int(f[_F_TCP_SPORT]), _int(f[_F_TCP_DPORT])
            key = ('tcp', stream)
        elif f[_F_UDP_STREAM]:
            proto, stream = 'UDP', _int(f[_F_UDP_STREAM])
            sport, dport = _int(f[_F_UDP_SPORT]), _int(f[_F_UDP_DPORT])
            key = ('udp', stream)
        else:
            number = f[_F_IP_PROTO] or f[_F_IP6_NXT]
            proto = _IP_PROTO_NAMES.get(number, number) if ip_v else (app.upper() or 'ETH')
            sport = dport = 0
            key = (proto, app if not ip_v else '') + tuple(sorted((src, dst)))
        syn_only = f[_F_SYN] in ('1', 'True') and f[_F_ACK] not in ('1', 'True')
        flow = flows.get(key)
        if flow is None:
            flow = flows[key] = _Flow(key, proto, ip_v, src, dst, sport, dport, when, stream)
        if icmp_error:
            flow.add(src, sport, length, when, '', '', False, from_client=outer_src == flow.client)
            continue
        flow.add(src, sport, length, when, app, f[_F_CID], syn_only)
        frame = _int(f[_F_FRAME])
        flow.first_frame = flow.first_frame or frame
        flow.last_frame = last_frame = frame
        if not (flow.client_set_by_syn or flow.client_set_by_message):
            # A SYN-ACK is a reply too: a stream that opens on one (a
            # server re-sending it after the connection was reset) has
            # the server sending first.
            syn_ack = f[_F_SYN] in ('1', 'True') and f[_F_ACK] in ('1', 'True')
            is_reply = True if syn_ack else _is_reply(cols)
            if is_reply is not None:
                flow.orient(src, sport, is_reply)
        packet = None
        for handler, columns in protocols:
            # A protocol only sees packets of its own protocols: tshark
            # reuses one dissector's fields for others (mDNS and LLMNR carry
            # dns.* fields, SSDP http.* ones), so fields alone can't say
            # whose packet it is.
            if app not in handler.app_protos:
                continue
            values = [cols[i] if i < len(cols) else '' for i in columns]
            if not any(values):
                continue
            if packet is None:
                packet = Packet(_int(f[_F_FRAME]), when, flow, sport, dport, app, src, dst)
            handler.feed(packet, {name: [_unescape(x) for x in value.split(_AGGREGATOR)] if value else []
                                  for name, value in zip(handler.fields, values)})
    structured = [proto() for proto in STRUCTURED_PROTOCOLS] if pcap_path else []
    if structured:
        _structured_pass(pcap_path, flows, structured, last_frame, deadline)
    ordered = sorted(flows.values(), key=lambda fl: fl.first)
    flows.clear()
    for i, flow in enumerate(ordered):
        ordered[i] = None    # the transaction records below hold the flows they need
        yield flow.event()
    del ordered
    for handler in [handler for handler, _ in protocols] + structured:
        for flow, when, event_type, body in handler.finish():
            yield flow.record(when, event_type, body)


# The layers every structured-pass packet is read for, to find its flow
_STRUCTURED_BASE = ('eth', 'ethertype', 'vlan', 'ip', 'ipv6', 'tcp', 'udp')
_STRUCTURED_MAX_RANGES = 500


def _frame_ranges(flows, max_ranges=_STRUCTURED_MAX_RANGES):
    """The frame number ranges covering these flows - each flow whole,
    since TCP reassembly needs every segment - merged, and merged again
    across the smallest gaps until there are at most max_ranges."""
    ranges = sorted((fl.first_frame, fl.last_frame) for fl in flows if fl.first_frame)
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    while len(merged) > max_ranges:
        gaps = sorted(range(len(merged) - 1), key=lambda i: merged[i + 1][0] - merged[i][1])[:len(merged) - max_ranges]
        for i in sorted(gaps, reverse=True):
            merged[i][1] = merged[i + 1][1]
            del merged[i + 1]
    return [tuple(r) for r in merged]


def _structured_command(source, handlers):
    protocols = ','.join(dict.fromkeys(_STRUCTURED_BASE + tuple(p for h in handlers for p in h.tshark_protocols)))
    layers = ' '.join(dict.fromkeys(('frame',) + _STRUCTURED_BASE[3:] + tuple(l for h in handlers for l in h.layers)))
    return ['tshark', '-n', '-r', source, '--disable-all-protocols', '--enable-protocol', protocols,
            '-Y', ' || '.join(f'({h.display_filter})' for h in handlers),
            '-T', 'json', '--no-duplicate-keys', '-J', layers]


def _json_packets(stream):
    """tshark -T json's packets, one at a time: each is an object opening
    and closing at two spaces' indent, so the whole array never has to be
    held to parse it."""
    buf = []
    for line in stream:
        if line.startswith('  {'):
            buf = [line]
        elif buf:
            if line.startswith('  }'):
                buf.append('}')
                try:
                    yield json.loads(''.join(buf))['_source']['layers']
                except (ValueError, KeyError):
                    pass
                buf = []
            else:
                buf.append(line)


def _last_layer(layers, name):
    layer = layers.get(name)
    return layer[-1] if isinstance(layer, list) and layer else layer


def _structured_flow(layers, index):
    """The first pass's flow a structured-pass packet belongs to: by its
    addresses and ports (the innermost, as the first pass reads them),
    then the flow of those that was open at the time."""
    ip, ipv6 = _last_layer(layers, 'ip'), _last_layer(layers, 'ipv6')
    if ip:
        src, dst = ip.get('ip.src'), ip.get('ip.dst')
    elif ipv6:
        src, dst = ipv6_exploded(ipv6.get('ipv6.src', '')), ipv6_exploded(ipv6.get('ipv6.dst', ''))
    else:
        return None
    for proto in ('tcp', 'udp'):
        layer = _last_layer(layers, proto)
        if layer:
            sport, dport = _int(layer.get(f'{proto}.srcport')), _int(layer.get(f'{proto}.dstport'))
            break
    else:
        return None
    candidates = index.get((proto.upper(), frozenset(((src, sport), (dst, dport)))))
    if not candidates:
        return None
    try:
        when = float(_last_layer(layers, 'frame').get('frame.time_epoch'))
    except (TypeError, ValueError, AttributeError):
        return candidates[0]
    open_then = [fl for fl in candidates if fl.first - 1 <= when <= fl.last + 1]
    return open_then[0] if open_then else min(candidates, key=lambda fl: abs(fl.first - when))


def _structured_pass(pcap_path, flows, handlers, total_frames, deadline=None):
    """Feed the structured protocols (shark_protocols.STRUCTURED_PROTOCOLS)
    from a second tshark run that writes their packets as JSON trees. It
    runs only if the first pass found any of their flows, and - unless
    those flows span most of the capture - only over a copy of their
    packets (editcap, which copies without decoding), since tshark has to
    read every packet of whatever it's given."""
    relevant = [fl for fl in flows.values()
                if fl.proto in ('TCP', 'UDP') and any(p in fl.protocols for h in handlers for p in h.app_protos)]
    active = [h for h in handlers if any(p in fl.protocols for fl in relevant for p in h.app_protos)]
    if not active:
        return
    index = {}
    for fl in sorted(relevant, key=lambda fl: fl.first):
        index.setdefault((fl.proto, frozenset(((fl.client, fl.cport), (fl.server, fl.sport)))), []).append(fl)
    ranges = _frame_ranges(relevant)
    remaining = None if deadline is None else max(1.0, deadline - time.monotonic())
    with tempfile.TemporaryDirectory(prefix='shark-') as tmp:
        source = pcap_path
        if sum(end - start + 1 for start, end in ranges) < 0.7 * max(total_frames, 1) and shutil.which('editcap'):
            source = os.path.join(tmp, 'subset.pcapng')
            subprocess.run(['editcap', '-r', pcap_path, source] + [f'{a}-{b}' for a, b in ranges],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=remaining)
        # TZ=UTC: tshark writes absolute times (SMB's file times) in local time
        with tempfile.TemporaryFile(mode='w+', errors='replace') as stderr_file, \
                subprocess.Popen(_structured_command(source, active), stdout=subprocess.PIPE, stderr=stderr_file,
                                 text=True, errors='replace', env=dict(os.environ, TZ='UTC'),
                                 preexec_fn=_low_priority) as proc:
            killer = threading.Timer(remaining, proc.kill) if remaining else None
            if killer:
                killer.start()
            try:
                for layers in _json_packets(proc.stdout):
                    flow = _structured_flow(layers, index)
                    if flow is None:
                        continue
                    frame = _last_layer(layers, 'frame') or {}
                    try:
                        when = float(frame.get('frame.time_epoch'))
                    except (TypeError, ValueError):
                        continue
                    packet = Packet(_int(frame.get('frame.number')), when, flow, flow.cport, flow.sport)
                    for handler in active:
                        if any(name in layers for name in handler.layers):
                            handler.feed_json(packet, layers)
                proc.wait()
            finally:
                if killer:
                    killer.cancel()
            if proc.returncode != 0:
                stderr_file.seek(0)
                lines = stderr_file.read(64 * 1024).strip().splitlines()
                raise RuntimeError('tshark (structured pass) ' + (lines[-1] if lines else
                                   ('timed out' if proc.returncode < 0 else f'exit code {proc.returncode}')))


def build_flows(lines):
    """Just build_records' flow records."""
    return [e for e in build_records(lines) if e['event_type'] == 'flow']


def _low_priority():
    """preexec_fn for tshark: lowest CPU priority, so a background run
    yields to Suricata and to the user's own work."""
    try:
        os.nice(19)
    except OSError:
        pass


def run_tshark(pcap_path, timeout=None, on_start=None, consume=list):
    """Run tshark over pcap_path and return consume(its records) - by
    default, the records as a list; analyze's build streams them into
    shark.db instead. Raises RuntimeError if tshark is missing, fails, is
    killed, or exceeds the timeout. on_start, if given, is called with the
    tshark process as soon as it starts."""
    if not shutil.which('tshark'):
        raise RuntimeError('tshark is not installed')
    cmd = tshark_command(pcap_path)
    if shutil.which('ionice'):
        cmd = ['ionice', '-c', '3'] + cmd   # idle I/O class - allowed without privileges
    timeout = config.SHARK_RUN_TIMEOUT if timeout is None else timeout
    timed_out = threading.Event()
    # stderr goes to a file, not a pipe: it's only read once tshark exits,
    # and a pipe that filled with warnings meanwhile would stall tshark.
    with tempfile.TemporaryFile(mode='w+', errors='replace') as stderr_file, \
            subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr_file, text=True,
                             errors='replace', preexec_fn=_low_priority) as proc:
        if on_start:
            on_start(proc)

        def _kill():
            timed_out.set()
            proc.kill()
        killer = threading.Timer(timeout, _kill)
        killer.start()
        try:
            events = consume(iter_records(proc.stdout, pcap_path, time.monotonic() + timeout))
            proc.wait()
        finally:
            killer.cancel()
        stderr_file.seek(0)
        stderr = stderr_file.read(64 * 1024)
    if timed_out.is_set():
        raise RuntimeError(f'tshark timed out after {timeout}s')
    if proc.returncode < 0:
        raise RuntimeError('tshark was stopped')
    if proc.returncode != 0:
        detail = stderr.strip().splitlines()[-1] if stderr.strip() else f'exit code {proc.returncode}'
        raise RuntimeError(f'tshark failed: {detail}')
    return events


def _child_command(dir_path, pcap_path):
    cmd = [sys.executable, '-m', 'shark_analyzer', 'build', dir_path, pcap_path]
    if shutil.which('ionice'):
        cmd = ['ionice', '-c', '3'] + cmd
    return cmd


def _group_memory(pgid):
    """Bytes of memory the processes of one process group hold (resident
    set) - the build and its tshark, which runs in the build's group."""
    total = 0
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            with open(f'/proc/{pid}/stat') as f:
                fields = f.read().rsplit(')', 1)[1].split()
            if int(fields[2]) == pgid:            # field 5 of stat, the process group
                total += int(fields[21]) * _PAGE_SIZE   # field 24, resident pages
        except (OSError, ValueError, IndexError):
            continue
    return total


_PAGE_SIZE = os.sysconf('SC_PAGE_SIZE') if hasattr(os, 'sysconf') else 4096


def _watch_memory(proc, too_big):
    """Stop a build whose processes together pass SHARK_MAX_MEMORY_BYTES -
    tshark's memory grows with the capture's packet count, and a capture
    with millions of small packets could otherwise take all of it."""
    while proc.poll() is None:
        if _group_memory(proc.pid) > config.SHARK_MAX_MEMORY_BYTES:
            too_big.set()
            _kill_group(proc)
            return
        time.sleep(config.SHARK_MEMORY_CHECK_SECONDS)


def _kill_group(proc):
    """Kill a build and its tshark: the build leads its own process group."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def analyze(dir_path, pcap_path, on_start=None):
    """Build dir_path's shark.db from pcap_path, in a child process (build)
    at the lowest CPU and I/O priority - so building the records competes
    with neither the server's own Python nor Suricata, and the memory it
    took goes back when it exits. On failure, .shark_error says why -
    unless the run was cancelled, whose directory is being cleared or
    removed. on_start is called with the child process (the queue kills
    its process group to cancel it)."""
    _remove(os.path.join(dir_path, SHARK_ERROR))
    with tempfile.TemporaryFile(mode='w+', errors='replace') as stderr_file:
        proc = subprocess.Popen(_child_command(dir_path, pcap_path), cwd=os.path.dirname(os.path.abspath(__file__)),
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr_file,
                                preexec_fn=_low_priority, start_new_session=True)
        if on_start:
            on_start(proc)
        too_big = threading.Event()
        watchdog = threading.Thread(target=_watch_memory, args=(proc, too_big), daemon=True)
        watchdog.start()
        try:
            # The build enforces tshark's own timeout; this one is for a
            # build that hangs after it
            proc.wait(timeout=config.SHARK_RUN_TIMEOUT + 600)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            proc.wait()
        watchdog.join()
        if not too_big.is_set() and (proc.returncode == 0 or _was_cancelled(dir_path)
                                     or os.path.exists(os.path.join(dir_path, SHARK_ERROR))):
            return
        stderr_file.seek(0)
        lines = stderr_file.read()[-64 * 1024:].strip().splitlines()
    if too_big.is_set():
        detail = (f'it needed more than {config.SHARK_MAX_MEMORY_BYTES / 1024 ** 3:g} GB of memory '
                  '(tshark needs about 1 KB per packet)')
    else:
        # It died without saying why: killed (out of memory, most often) or crashed
        detail = lines[-1] if lines else ('killed - out of memory?' if proc.returncode == -signal.SIGKILL
                                          else f'exit code {proc.returncode}')
    _remove(shark_db_path(dir_path) + '.tmp')
    try:
        with open(os.path.join(dir_path, SHARK_ERROR), 'w') as f:
            f.write(f'tshark analysis stopped: {detail}'[:500])
    except OSError:
        pass


def build(dir_path, pcap_path):
    """analyze's child process: run tshark and write its records into
    shark.db as they're built, committing as it goes. On failure, writes
    the reason to .shark_error. Returns whether it succeeded."""
    db_path = shark_db_path(dir_path)
    tmp_path = db_path + '.tmp'
    started = time.monotonic()
    try:
        for name in (tmp_path, tmp_path + '-wal', tmp_path + '-shm'):
            _remove(name)
        run_tshark(pcap_path, consume=lambda records: create_shark_db(tmp_path, records))
        conn = sqlite3.connect(tmp_path)
        try:
            conn.execute(f'PRAGMA user_version = {SHARK_FORMAT_VERSION}')
            # How long the run took, tshark and building the records both
            # (status() reports it once the run is ready)
            conn.execute('CREATE TABLE shark_run (seconds REAL)')
            conn.execute('INSERT INTO shark_run VALUES (?)', (time.monotonic() - started,))
            conn.commit()
        finally:
            conn.close()
        os.replace(tmp_path, db_path)
        return True
    except Exception as e:
        _remove(tmp_path)
        try:
            with open(os.path.join(dir_path, SHARK_ERROR), 'w') as f:
                f.write(str(e)[:500])
        except OSError:
            pass
        return False


def _remove(path):
    try:
        os.unlink(path)
    except OSError:
        pass


# ----------------------------------------------------------------------
# The queue: one tshark run at a time, in the order they were asked for.
# ----------------------------------------------------------------------

_lock = threading.Lock()
_queue = deque()          # dir_paths waiting, each with its pcap path in _pending
_pending = {}             # dir_path -> pcap_path
_running = None           # dir_path being analyzed now, or None
_running_since = None     # when it started (time.time()), for status()'s elapsed
_running_proc = None      # its tshark process, once started
_cancelled = set()        # dir_paths whose running job was cancelled
_worker = None


def _was_cancelled(dir_path):
    with _lock:
        return dir_path in _cancelled


def _set_running_proc(proc):
    global _running_proc
    with _lock:
        _running_proc = proc
        if _running in _cancelled:   # cancelled before the build had started
            _kill_group(proc)


def _work():
    global _running, _running_since, _running_proc, _worker
    while True:
        with _lock:
            if not _queue:
                _running = _worker = None
                return
            dir_path = _queue.popleft()
            pcap_path = _pending.pop(dir_path)
            _running, _running_since = dir_path, time.time()
        if os.path.isfile(pcap_path):
            analyze(dir_path, pcap_path, on_start=_set_running_proc)
            if not _was_cancelled(dir_path):
                merge(dir_path)
        with _lock:
            _running = _running_since = _running_proc = None
            _cancelled.discard(dir_path)


def enqueue(dir_path, pcap_path):
    """Queue a tshark run for this analysis, unless one is already
    queued or running for it. Returns True if it was queued."""
    global _worker
    with _lock:
        if dir_path in _pending or dir_path == _running:
            return False
        _queue.append(dir_path)
        _pending[dir_path] = pcap_path
        if _worker is None:
            _worker = threading.Thread(target=_work, daemon=True)
            _worker.start()
    return True


def cancel(dir_path):
    """Stop this analysis's tshark run (reanalyze/delete): drop it
    from the queue, or kill its tshark if it's running."""
    with _lock:
        if dir_path in _pending:
            del _pending[dir_path]
            _queue.remove(dir_path)
        elif dir_path == _running:
            _cancelled.add(dir_path)
            if _running_proc is not None:
                _kill_group(_running_proc)


_PACKET_COUNTS = {}     # (path, size, mtime) -> packet count


def packet_count(pcap_path):
    """A capture's packet count (capinfos, which reads it without decoding -
    a fraction of a second for millions of packets), or None if it can't be
    counted. Remembered per file, since status() asks on every poll."""
    try:
        st = os.stat(pcap_path)
    except OSError:
        return None
    key = (pcap_path, st.st_size, st.st_mtime)
    if key not in _PACKET_COUNTS:
        count = None
        if shutil.which('capinfos'):
            try:
                out = subprocess.run(['capinfos', '-c', '-M', '-T', '-r', pcap_path], capture_output=True,
                                     text=True, timeout=120).stdout
                count = int(out.strip().rsplit('\t', 1)[1])
            except (subprocess.SubprocessError, OSError, ValueError, IndexError):
                count = None
        if len(_PACKET_COUNTS) > 1000:
            _PACKET_COUNTS.clear()
        _PACKET_COUNTS[key] = count
    return _PACKET_COUNTS[key]


def background_eligible(pcap_path):
    """Whether a capture is small enough to analyze without being asked: by
    its packet count - what tshark's memory follows - or, when that can't
    be counted, by its size."""
    count = packet_count(pcap_path)
    if count is not None:
        return count <= config.SHARK_BACKGROUND_MAX_PACKETS
    try:
        return os.path.getsize(pcap_path) <= config.SHARK_BACKGROUND_MAX_BYTES
    except OSError:
        return False


SHARK_SETTINGS = 'shark_settings.json'


def enabled(data_dir):
    """Whether tshark runs at all - the Settings switch, kept in the
    data directory (on unless turned off)."""
    try:
        with open(os.path.join(data_dir, SHARK_SETTINGS)) as f:
            return json.load(f).get('enabled', True) is not False
    except (OSError, ValueError, AttributeError):
        return True


def set_enabled(data_dir, on):
    path = os.path.join(data_dir, SHARK_SETTINGS)
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump({'enabled': bool(on)}, f)
    os.replace(tmp, path)


def run_seconds(db_path):
    """How long the run that built a shark.db took, or None if it didn't
    record that."""
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        try:
            row = conn.execute('SELECT seconds FROM shark_run').fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return row[0] if row else None


def format_version(db_path):
    """The SHARK_FORMAT_VERSION a shark.db was built with (0 if unknown)."""
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        try:
            return conn.execute('PRAGMA user_version').fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


# ----------------------------------------------------------------------
# Merging into the analysis's own events.db: Suricata stays the source of
# truth for every protocol it parses; tshark adds what it can't see.
# ----------------------------------------------------------------------

# Suricata 8's app-layer parsers (suricata --list-app-layer-protos), in the
# names tshark's app_proto uses, plus what it logs below the app layer
# (ICMP flows, ARP). static/socrates.js keeps the same list.
SURICATA_APP_PROTOS = frozenset((
    'http', 'ftp', 'ftp-data', 'smtp', 'tls', 'ssh', 'imap', 'smb', 'dcerpc', 'dns', 'modbus', 'enip', 'dnp3', 'nfs',
    'ntp', 'tftp', 'ike', 'krb5', 'quic', 'dhcp', 'sip', 'rfb', 'mqtt', 'pgsql', 'telnet', 'websocket', 'ldap', 'doh2',
    'rdp', 'http2', 'bittorrent-dht', 'pop3', 'mdns', 'snmp', 'icmp', 'ipv6-icmp', 'icmpv6', 'arp'))
# ... less the ones it recognizes but writes no records for - tshark's
# records of those are still the only ones there are.
SURICATA_RECORDED_APP_PROTOS = SURICATA_APP_PROTOS - {'telnet', 'imap'}

_merge_locks = {}
_merge_locks_lock = threading.Lock()


def _merge_lock(dir_path):
    with _merge_locks_lock:
        return _merge_locks.setdefault(dir_path, threading.Lock())


def _merge_stamp(db_path):
    """Which shark.db a merge came from: its format and modification time."""
    return f'{SHARK_FORMAT_VERSION}:{os.path.getmtime(db_path):.6f}'


def merge_rows(shark_rows, identified):
    """The rows of a shark.db (its stored JSON, one at a time) that belong
    in the analysis's events.db: records of protocols Suricata doesn't
    parse, and - as connection rows, CONNECTION_TYPE_PREFIX + protocol -
    flows of protocols that have neither Suricata's parsing nor records of
    their own here. Nothing on a flow Suricata identified - gave a protocol
    and backed it with records (by Community ID and time, from
    db.suricata_identified_flows): there Suricata's word stands, as on a
    scanner's HTTP request to an rsh port, which tshark, going by the port,
    calls rsh."""
    from db import CONNECTION_TYPE_PREFIX

    def suricata_knows(cid, first, last):
        return any(start - 1 <= last and first <= end + 1 for start, end in identified.get(cid, ()))
    for data in shark_rows:
        event = json.loads(data)
        event_type = event.get('event_type', '')
        cid = event.get('community_id')
        if event_type == 'flow':
            app = event.get('app_proto') or ''
            if not app or app in SURICATA_APP_PROTOS or app in RECORDED_APP_PROTOS:
                continue
            flow = event.get('flow') or {}
            first, last = _iso_epoch(flow.get('start')), _iso_epoch(flow.get('end'))
            if first is not None and suricata_knows(cid, first, last if last is not None else first):
                continue
            event['event_type'] = CONNECTION_TYPE_PREFIX + app
        else:
            if event_type.replace('_', '-') in SURICATA_RECORDED_APP_PROTOS:
                continue
            when = _iso_epoch(event.get('timestamp'))
            if when is not None and suricata_knows(cid, when, when):
                continue
        yield event


def merge(dir_path):
    """Add tshark's rows (merge_rows) to the analysis's events.db - once
    both Suricata (its events.db imported, no .phase left) and tshark
    (a current shark.db) are done, whichever finishes last calls this. A
    later shark.db (a retried run) replaces the rows of an earlier one.
    Returns how many rows were added, or None if it wasn't time to."""
    shark_db = shark_db_path(dir_path)
    events_db = os.path.join(dir_path, 'events.db')
    with _merge_lock(dir_path):
        if not (os.path.exists(shark_db) and os.path.exists(events_db)) or \
                os.path.exists(os.path.join(dir_path, '.phase')) or format_version(shark_db) != SHARK_FORMAT_VERSION:
            return None
        stamp = _merge_stamp(shark_db)
        if tshark_merge_stamp(events_db) == stamp:
            return None
        added = replace_tshark_events(events_db, merge_rows(iter_events_json(shark_db),
                                                            suricata_identified_flows(events_db)), stamp)
    from analysis_cache import evict_analysis_cache
    evict_analysis_cache(os.path.basename(os.path.normpath(dir_path)))
    return added


_merging = set()


def merge_soon(dir_path):
    """merge() in the background, unless one is already under way for
    this analysis - a status poll that finds it unmerged asks again every
    couple of seconds."""
    with _merge_locks_lock:
        if dir_path in _merging:
            return
        _merging.add(dir_path)

    def run():
        try:
            merge(dir_path)
        except Exception:
            pass       # status() keeps reporting it unmerged; the next poll retries
        finally:
            with _merge_locks_lock:
                _merging.discard(dir_path)
    threading.Thread(target=run, daemon=True).start()


def merged(dir_path):
    """Whether the analysis's events.db has the current shark.db's rows."""
    shark_db = shark_db_path(dir_path)
    try:
        return tshark_merge_stamp(os.path.join(dir_path, 'events.db')) == _merge_stamp(shark_db)
    except OSError:
        return False


def status(dir_path, pcap_path=None):
    """This analysis's tshark state: 'ready' (with the run's
    'seconds', for a shark.db that recorded them), 'queued', 'running'
    (with 'elapsed' seconds so far), 'error' (with 'message'), 'too_large'
    (over the background limit, not yet asked for) or 'not_started'. A shark.db built by an older
    tshark (see SHARK_FORMAT_VERSION) is removed here, so the
    analysis reads as not started and gets rebuilt."""
    db_path = shark_db_path(dir_path)
    if os.path.exists(db_path):
        with _lock:
            busy = dir_path == _running or dir_path in _pending
        if busy or format_version(db_path) == SHARK_FORMAT_VERSION:
            if not busy:
                seconds = run_seconds(db_path)
                return {'status': 'ready'} if seconds is None else {'status': 'ready', 'seconds': round(seconds)}
        else:
            for name in (SHARK_DB, SHARK_DB + '-wal', SHARK_DB + '-shm'):
                _remove(os.path.join(dir_path, name))
    with _lock:
        if dir_path == _running:
            return {'status': 'running', 'elapsed': max(0, int(time.time() - _running_since))}
        if dir_path in _pending:
            return {'status': 'queued', 'position': list(_queue).index(dir_path) + 1}
    error_path = os.path.join(dir_path, SHARK_ERROR)
    if os.path.exists(error_path):
        try:
            with open(error_path) as f:
                message = f.read().strip()
        except OSError:
            message = ''
        return {'status': 'error', 'message': message or 'tshark analysis failed'}
    if pcap_path and not background_eligible(pcap_path):
        return {'status': 'too_large'}
    return {'status': 'not_started'}


def wait_idle(timeout=60):
    """Block until the queue is empty and nothing is running (tests)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _lock:
            if not _queue and _running is None:
                return True
        time.sleep(0.05)
    return False


if __name__ == '__main__':
    # analyze's child: python3 -m shark_analyzer build <analysis dir> <pcap>
    if len(sys.argv) == 4 and sys.argv[1] == 'build':
        sys.exit(0 if build(sys.argv[2], sys.argv[3]) else 1)
    sys.exit('usage: python3 -m shark_analyzer build <analysis dir> <pcap>')
