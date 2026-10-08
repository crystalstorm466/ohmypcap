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
            'proto': e.get('proto'), 'app_proto': e.get('app_proto') or None,
            **{k: f.get(k) for k in ('pkts_toserver', 'pkts_toclient', 'bytes_toserver', 'bytes_toclient',
                                     'start', 'end')}}


# type -> (key within a flow, fields compared)
TYPES = {
    'flow': (lambda e: (), _flow_fields),
    'dns': (_dns_key, _dns_fields),
    'http': (lambda e: (e['http'].get('http_method'), e['http'].get('url')), _http_fields),
    'tls': (lambda e: (), _tls_fields),
    'modbus': (lambda e: (e['modbus'].get('request') or e['modbus'].get('response') or {}).get('transaction_id'),
               _modbus_fields),
}


def _suricata_dns(events):
    """Suricata logs a DNS request and its response as separate records;
    merge them into one per transaction, like SHAR-CRATES."""
    merged = {}
    for e in events:
        if e.get('event_type') != 'dns':
            continue
        key = (e.get('community_id'), e['dns'].get('id'))
        if e['dns'].get('type') == 'request' or key not in merged:
            if key in merged and e['dns'].get('type') == 'request':
                continue
            merged[key] = e
        if e['dns'].get('type') == 'response':
            merged[key] = e
    return list(merged.values())


def compare(suricata_events, shark_events):
    """{'type': {'suricata': n, 'shark': n, 'matched': n, 'differences': [...]}}."""
    suricata = [e for e in suricata_events if e.get('event_type') != 'dns'] + _suricata_dns(suricata_events)
    report = {}
    for etype, (key_of, fields_of) in TYPES.items():
        def index(events):
            out = {}
            for e in events:
                if e.get('event_type') == etype:
                    occurrences = out.setdefault((e.get('community_id'), key_of(e)), [])
                    occurrences.append(e)
            return out
        a, b = index(suricata), index(shark_events)
        result = {'suricata': sum(map(len, a.values())), 'shark': sum(map(len, b.values())),
                  'matched': 0, 'differences': []}
        for key in sorted(set(a) | set(b), key=str):
            if key not in b:
                result['differences'].append({'key': key, 'only': 'suricata', 'record': fields_of(a[key][0])})
                continue
            if key not in a:
                result['differences'].append({'key': key, 'only': 'shark', 'record': fields_of(b[key][0])})
                continue
            fa, fb = fields_of(a[key][0]), fields_of(b[key][0])
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
              f"differences {len(r['differences'])}")
        for d in r['differences']:
            total += 1
            print('   ', json.dumps(d, default=str))
    return 1 if total else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
