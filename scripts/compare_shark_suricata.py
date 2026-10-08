#!/usr/bin/env python3
"""Compare SHAR-CRATES's records for a PCAP with Suricata's (eve.json).

For every record type both views build - flow, dns, http, tls, modbus -
records are matched by Community ID plus that type's transaction key, and
every field the two share is compared. Prints counts per type and each
difference, and exits 1 if there are any.

Differences aren't automatically bugs: the tools can legitimately
disagree (a flow that starts mid-capture, reassembly after packet loss,
a field one of them doesn't log). Each one should be either fixed in
shark_analyzer/shark_protocols or understood and documented.

Usage:
    python3 scripts/compare_shark_suricata.py <pcap> <eve.json>
    python3 scripts/compare_shark_suricata.py <analysis dir>   # its pcap, eve.json and shark.db

Also importable: compare(suricata_events, shark_events) -> report dict.
"""

import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


def _dns_key(e):
    return e['dns']['id'], tuple(q['rrname'] for q in e['dns'].get('queries', []))


def _dns_fields(e):
    d = e['dns']
    return {
        'queries': [(q['rrname'], q['rrtype']) for q in d.get('queries', [])],
        'answered': d.get('type') == 'response',
        'rcode': d.get('rcode') if d.get('type') == 'response' else None,
        'answers': sorted((a['rrname'], a['rrtype'], a.get('rdata', ''), a.get('ttl')) for a in d.get('answers', [])),
    }


def _http_fields(e):
    h = e['http']
    return {k: h.get(k) for k in ('hostname', 'url', 'http_user_agent', 'http_method', 'protocol',
                                  'status', 'http_refer', 'http_content_type', 'length')}


def _tls_fields(e):
    t = e['tls']
    return {'sni': t.get('sni'), 'version': t.get('version'),
            'ja3': (t.get('ja3') or {}).get('hash'), 'ja3s': (t.get('ja3s') or {}).get('hash'),
            'ja4': t.get('ja4'), 'client_alpns': t.get('client_alpns')}


def _modbus_side(side):
    if not side:
        return None
    out = {k: side.get(k) for k in ('transaction_id', 'unit_id', 'function_raw', 'function_code',
                                    'access_type', 'category')}
    out['exception'] = (side.get('exception') or {}).get('code')
    if 'read' in side and 'address' in side['read']:
        out['read'] = (side['read']['address'], side['read'].get('quantity'))
    if 'write' in side and 'address' in side['write']:
        out['write'] = (side['write']['address'], side['write'].get('data'))
    return out


def _modbus_fields(e):
    m = e['modbus']
    return {'request': _modbus_side(m.get('request')), 'response': _modbus_side(m.get('response'))}


def _flow_fields(e):
    f = e['flow']
    return {'src': (e.get('src_ip'), e.get('src_port')), 'dest': (e.get('dest_ip'), e.get('dest_port')),
            # Suricata says 'failed' where it found no application protocol
            'proto': e.get('proto'), 'app_proto': None if e.get('app_proto') in (None, '', 'failed') else e['app_proto'],
            **{k: f.get(k) for k in ('pkts_toserver', 'pkts_toclient', 'bytes_toserver', 'bytes_toclient',
                                     'start', 'end')}}


def _reversed_flow(fields):
    """A flow's fields seen from its other side."""
    out = dict(fields, src=fields['dest'], dest=fields['src'])
    for a, b in (('pkts_toserver', 'pkts_toclient'), ('bytes_toserver', 'bytes_toclient')):
        out[a], out[b] = fields[b], fields[a]
    return out


def _ftp_fields(e):
    f = e['ftp']
    return {k: f.get(k) for k in ('command', 'command_data', 'completion_code', 'reply', 'dynamic_port', 'mode',
                                  'reply_received')}


def _ftp_data_fields(e):
    return {k: e['ftp_data'].get(k) for k in ('command', 'filename')}


# type -> (key within a flow, fields compared). Records with the same key on
# one flow (a second TYPE command) are matched in order.
TYPES = {
    'flow': (lambda e: (), _flow_fields),
    'dns': (_dns_key, _dns_fields),
    'http': (lambda e: (e['http'].get('http_method'), e['http'].get('url')), _http_fields),
    'tls': (lambda e: (), _tls_fields),
    'modbus': (lambda e: (e['modbus'].get('request') or e['modbus'].get('response') or {}).get('transaction_id'),
               _modbus_fields),
    'ftp': (lambda e: (e['ftp'].get('command'), e['ftp'].get('command_data')), _ftp_fields),
    'ftp_data': (lambda e: e['ftp_data'].get('filename'), _ftp_data_fields),
    'quic': (lambda e: (), lambda e: {k: (e['quic'].get(k) or {}).get('hash') if k in ('ja3', 'ja3s') else e['quic'].get(k)
                                      for k in ('version', 'sni', 'ja3', 'ja3s', 'ja4')}),
    'mdns': (lambda e: (e['mdns'].get('type'), tuple(q['rrname'] for q in e['mdns'].get('queries', []))),
             lambda e: {'queries': [(q['rrname'], q['rrtype']) for q in e['mdns'].get('queries', [])],
                        'answers': sorted(tuple(sorted(a.items())) for a in e['mdns'].get('answers', [])),
                        'rcode': e['mdns'].get('rcode')}),
}


def _suricata_dns(events):
    """Suricata logs a DNS request and its response as separate records;
    pair them into one per transaction, the way SHAR-CRATES does: in time
    order, a request opens a transaction unless the same question is
    already waiting on that flow with that ID (a retransmission); a
    response closes the waiting one, and one with nothing waiting after an
    answered transaction is the same response again."""
    transactions, waiting, answered = [], {}, set()
    dns = sorted((e for e in events if e.get('event_type') == 'dns'), key=lambda e: e.get('timestamp', ''))
    for e in dns:
        d = e['dns']
        q = d.get('queries') or [{}]
        key = (e.get('community_id'), d.get('id'), q[0].get('rrname'), q[0].get('rrtype'))
        if d.get('type') == 'request':
            if key not in waiting:
                waiting[key] = len(transactions)
                transactions.append(e)
        elif key in waiting:
            transactions[waiting.pop(key)] = e
            answered.add(key)
        elif key not in answered:
            transactions.append(e)
            answered.add(key)
    return transactions


def _suricata_quic(events):
    """Suricata logs several 'quic' records per connection (most just its
    version); merge them into one per connection, like SHAR-CRATES."""
    merged = {}
    for e in sorted((e for e in events if e.get('event_type') == 'quic'), key=lambda e: e.get('timestamp', '')):
        m = merged.setdefault(e.get('community_id'), dict(e, quic={}))
        for k, v in e['quic'].items():
            m['quic'].setdefault(k, v)
    return list(merged.values())


def compare(suricata_events, shark_events):
    """{'type': {'suricata': n, 'shark': n, 'matched': n, 'differences': [...]}},
    and for flows 'reoriented': how many SHAR-CRATES addresses the other
    way round from Suricata - its client is whoever made the first
    request, or was answered first, where Suricata's is whoever sent the
    first packet (shark_analyzer._Flow.orient). A reoriented flow is
    compared from Suricata's side, so only its other fields can differ."""
    suricata = ([e for e in suricata_events if e.get('event_type') not in ('dns', 'quic')]
                + _suricata_dns(suricata_events) + _suricata_quic(suricata_events))
    report = {}
    for etype, (key_of, fields_of) in TYPES.items():
        def index(events):
            # Records sharing a key (a reused 5-tuple's flows have one
            # Community ID) are matched in time order - flows by their
            # start, since Suricata writes a flow out when it ends.
            out, seen = {}, {}
            for e in sorted(events, key=lambda e: (e.get('flow') or {}).get('start') or e.get('timestamp') or ''):
                if e.get('event_type') == etype:
                    base = (e.get('community_id'), key_of(e))
                    seen[base] = seen.get(base, -1) + 1
                    out[base + (seen[base],)] = [e]
            return out
        a, b = index(suricata), index(shark_events)
        result = {'suricata': sum(map(len, a.values())), 'shark': sum(map(len, b.values())),
                  'matched': 0, 'differences': []}
        if etype == 'flow':
            result['reoriented'] = 0
        for key in sorted(set(a) | set(b), key=str):
            if key not in b:
                result['differences'].append({'key': key, 'only': 'suricata', 'record': fields_of(a[key][0])})
                continue
            if key not in a:
                result['differences'].append({'key': key, 'only': 'shark', 'record': fields_of(b[key][0])})
                continue
            fa, fb = fields_of(a[key][0]), fields_of(b[key][0])
            if etype == 'flow' and fa['src'] == fb['dest'] and fa['dest'] == fb['src'] and fa['src'] != fa['dest']:
                fb = _reversed_flow(fb)
                result['reoriented'] += 1
            diff = {k: (fa.get(k), fb.get(k)) for k in fa if fa.get(k) != fb.get(k)}
            if diff:
                result['differences'].append({'key': key, 'fields': diff})
            else:
                result['matched'] += 1
        report[etype] = result
    return report


def _load_eve(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _load_shark_db(path):
    conn = sqlite3.connect(path)
    try:
        return [json.loads(row[0]) for row in conn.execute('SELECT json_data FROM events')]
    finally:
        conn.close()


def main(argv):
    if len(argv) == 2 and os.path.isdir(argv[1]):
        from storage import find_pcap_file
        eve = os.path.join(argv[1], 'eve.json')
        shark_db = os.path.join(argv[1], 'shark.db')
        if os.path.exists(shark_db):
            shark = _load_shark_db(shark_db)
        else:
            from shark_analyzer import run_tshark
            shark = run_tshark(os.path.join(argv[1], find_pcap_file(argv[1])))
    elif len(argv) == 3:
        from shark_analyzer import run_tshark
        eve, shark = argv[2], run_tshark(argv[1])
    else:
        print(__doc__)
        return 2
    report = compare(_load_eve(eve), shark)
    total = 0
    for etype, r in report.items():
        print(f"{etype:7} suricata {r['suricata']:6}  shark {r['shark']:6}  matched {r['matched']:6}  "
              f"differences {len(r['differences'])}"
              + (f"  reoriented {r['reoriented']}" if r.get('reoriented') else ''))
        for d in r['differences']:
            total += 1
            print('   ', json.dumps(d, default=str))
    return 1 if total else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
