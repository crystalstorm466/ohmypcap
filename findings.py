"""Findings: what the protocol records show is worth a look - a weakness, a
control action, a probe - gathered from every protocol into one list.

Each rule is one SQL condition over one event type's records in events.db,
so a rule reads only its own type's rows (by idx_event_type), and a short
detail line made from the matching record. A detail never carries a
password, even where the record keeps one.
"""

import json
import sqlite3

from db import (
    _build_search_terms,
    _build_where_conditions,
    _db_connection,
    _events_select,
    _has_acknowledged_alerts_table,
    _has_events_table,
    _has_fts5,
    get_row_notes,
)

SEVERITIES = ('high', 'medium', 'low')

# Matches shown per rule - the counts are always exact
MAX_PER_RULE = 500


def _j(event_type, path):
    return f"json_extract(json_data, '$.{event_type}.{path}')"


def _has(event_type, path, values):
    """Any of a list field's items is one of values."""
    quoted = ', '.join("'" + v.replace("'", "''") + "'" for v in values)
    return (f"EXISTS (SELECT 1 FROM json_each(json_data, '$.{event_type}.{path}') "
            f"WHERE value IN ({quoted}))")


def _in(event_type, path, values):
    quoted = ', '.join("'" + v.replace("'", "''") + "'" for v in values)
    return f'{_j(event_type, path)} IN ({quoted})'


def _join(*parts):
    return ' '.join(str(p) for p in parts if p not in (None, '', [], {}))


def _list(values, limit=3):
    values = list(values or ())
    more = f' (+{len(values) - limit} more)' if len(values) > limit else ''
    return ', '.join(str(v) for v in values[:limit]) + more


_IEC104_CONTROL = ('Single command', 'Double command', 'Regulating step command', 'Set point (normalized)',
                   'Set point (scaled)', 'Set point (float)', 'Bitstring command', 'Reset process',
                   'Parameter activation')
# The alerts a TLS endpoint sends when it refuses the other's certificate
# (tshark's names)
_TLS_CERT_ALERTS = ('Bad Certificate', 'Unsupported Certificate', 'Certificate Revoked', 'Certificate Expired',
                    'Certificate Unknown', 'Unknown CA')
# A certificate outside its validity at the time of the connection - not
# today, or every old capture's would be expired. Suricata writes the
# validity dates in UTC, and - the container's clock being UTC - the
# record's time too (2026-01-01T00:00:00.000000+0000).
_TLS_OUT_OF_DATE = (f"({_j('tls', 'notafter')} < substr(timestamp, 1, 19) "
                    f"OR {_j('tls', 'notbefore')} > substr(timestamp, 1, 19))")


def _tls_certificate(b):
    """The certificate a TLS record names, and for which host."""
    return _join(b.get('subject'), f"(for {b['sni']})" if b.get('sni') else '')


_DEFAULT_ROUTE = (f"EXISTS (SELECT 1 FROM json_each(json_data, '$.rip.routes') "
                  f"WHERE value LIKE '0.0.0.0/0 %' OR value LIKE '::/0 %')")


class Rule:
    __slots__ = ('id', 'severity', 'event_type', 'title', 'condition', 'detail', 'why')

    def __init__(self, id, severity, event_type, title, condition, detail, why):
        self.id, self.severity, self.event_type, self.title = id, severity, event_type, title
        self.condition, self.detail, self.why = condition, detail, why


# Most severe first; within a severity, roughly by how rarely the thing
# found is innocent
RULES = (
    Rule('ipmi_cipher_zero', 'high', 'ipmi', 'IPMI accepts cipher zero',
         _has('ipmi', 'weaknesses', ['cipher zero accepted']),
         lambda b: _join('privilege', b.get('requested_privilege')),
         "An IPMI 2.0 controller that accepts cipher suite 0 logs anyone in with any password "
         "(CVE-2013-4782)."),
    Rule('ipmi_anonymous', 'high', 'ipmi', 'IPMI allows anonymous logins',
         _has('ipmi', 'weaknesses', ['anonymous login', 'null user names']),
         lambda b: _list(w for w in b.get('weaknesses', ()) if w in ('anonymous login', 'null user names')),
         'A management controller that takes a login with no user name, or a null user, gives '
         'full control of the server to anyone who can reach it.'),
    Rule('ipmi_weak_auth', 'high', 'ipmi', 'IPMI offers weak authentication',
         _has('ipmi', 'weaknesses', ['no authentication offered', 'cleartext password']),
         lambda b: _list(w for w in b.get('weaknesses', ()) if w in ('no authentication offered',
                                                                    'cleartext password')),
         'An IPMI 1.5 login with no authentication, or with the password sent as it is.'),
    Rule('opcua_cleartext_password', 'high', 'opcua', 'OPC UA password sent unencrypted',
         f"{_j('opcua', 'password')} IS NOT NULL",
         lambda b: _join('user', b.get('username'), 'on', b.get('endpoint')),
         'The login password crossed the network readable - anyone on the path has it.'),
    Rule('telnet_login', 'high', 'telnet', 'Telnet login in the clear',
         f"(coalesce({_j('telnet', 'username')}, '') != '' OR coalesce({_j('telnet', 'password')}, '') != '')",
         lambda b: _join(f"user {b['username']}" if b.get('username') else 'a password, no user name',
                         '- login failed' if b.get('login') == 'failed' else ''),
         "Telnet sends the user name and password as typed; the device's banner is on the record."),
    Rule('s7_plc_control', 'high', 's7comm', 'S7 PLC started or stopped',
         _in('s7comm', 'function', ['PLC Stop', 'PLC Control']),
         lambda b: _join(b.get('function'), (b.get('response') or {}).get('error')),
         "A Siemens PLC's run state changed over the network - the step before reprogramming it, "
         "or stopping the process it runs."),
    Rule('s7_download', 'high', 's7comm', 'S7 program download',
         _in('s7comm', 'function', ['Request download', 'Download block', 'Download ended']),
         lambda b: b.get('function', ''),
         "Program blocks written to a Siemens PLC - how its logic is changed."),
    Rule('bacnet_device_control', 'high', 'bacnet', 'BACnet device restarted or silenced',
         _in('bacnet', 'service', ['reinitializeDevice', 'deviceCommunicationControl']),
         lambda b: _join(b.get('service'), b.get('state'), b.get('result')),
         'A building controller told to restart, or to stop talking, over the network.'),
    Rule('goose_anomaly', 'high', 'goose', 'GOOSE state number jumped or reset',
         f"{_j('goose', 'anomaly')} IS NOT NULL",
         lambda b: b.get('anomaly', ''),
         "A protection relay's state number should only go up by one - a jump or reset is what a "
         "forged or replayed message looks like."),
    Rule('slp_registration', 'high', 'slp', 'SLP accepts registrations',
         f"{_j('slp', 'function')} = 'Service Registration' AND {_j('slp', 'status')} = 'OK'",
         lambda b: _join(b.get('url'), f"({b['length']} bytes)" if b.get('length') else ''),
         'A host that registers services from anyone can be made to send large replies to a '
         'forged address (CVE-2023-29552).'),

    Rule('tls_certificate_refused', 'medium', 'tls_failure', 'TLS certificate refused',
         _has('tls_failure', 'alerts', [f'{side}: {a}' for side in ('client', 'server') for a in _TLS_CERT_ALERTS]),
         lambda b: _join(next((a for a in b.get('alerts', ()) if a.split(': ', 1)[-1] in _TLS_CERT_ALERTS), ''),
                         '-' if b.get('subject') else '', _tls_certificate(b)),
         "One end refused the other's certificate - untrusted (Unknown CA), expired, revoked or otherwise bad. "
         "Self-signed devices, TLS-inspecting proxies and someone in the middle all look like this. Seen "
         "where the alert went out readable: always in TLS 1.2 and earlier, and in TLS 1.3 from some clients "
         "(OpenSSL's) - whose certificate, encrypted, goes unnamed."),
    Rule('s7_write', 'medium', 's7comm', 'S7 PLC memory written',
         _in('s7comm', 'function', ['Write Var']),
         lambda b: _list(i.get('area') for i in b.get('items', ()) if i.get('area'))
         or _join(b.get('item_count') or (b.get('response') or {}).get('item_count'), 'items'),
         "Values written straight into a Siemens PLC's memory."),
    Rule('iec104_control', 'medium', 'iec104', 'IEC 104 control command',
         _in('iec104', 'action', list(_IEC104_CONTROL)),
         lambda b: _join(b.get('action'), 'to IOA', b.get('ioa'), '-', b.get('result')),
         'A command or set point sent to a substation - switching or adjusting equipment.'),
    Rule('opcua_change', 'medium', 'opcua_action', 'OPC UA write or method call',
         '1',
         lambda b: _join(b.get('service'), b.get('node'), '-', b.get('result')),
         'A client changed a node, called a method, or added or deleted nodes.'),
    Rule('socks_open', 'medium', 'socks', 'SOCKS proxy without authentication',
         f"{_j('socks', 'auth_method')} = 'no authentication' AND {_j('socks', 'status')} = 'succeeded'",
         lambda b: _join('to', b.get('request_name') or b.get('request_host'), b.get('request_port')),
         'An open proxy relays anyone - often how traffic is laundered through a host.'),
    Rule('xdmcp_offered', 'medium', 'xdmcp', 'XDMCP login screen offered',
         _in('xdmcp', 'result', ['willing', 'accepted', 'managed']),
         lambda b: _join(b.get('server_host_name'), '-', b.get('result')),
         "An X login manager answering the network hands out a graphical login, unencrypted."),
    Rule('rip_default_route', 'medium', 'rip', 'RIP default route announced',
         _DEFAULT_ROUTE,
         lambda b: _list(r for r in b.get('routes', ()) if r.startswith(('0.0.0.0/0 ', '::/0 '))),
         'Whoever announces the default route gets the traffic for everywhere else - expected '
         'from a router, not from any other host.'),
    Rule('rip_cleartext_password', 'medium', 'rip', 'RIPv2 password in the clear',
         f"{_j('rip', 'authentication')} = 'simple password'",
         lambda b: _join(b.get('route_count'), 'routes'),
         'Simple-password authentication sends the password readable with every update.'),
    Rule('tunnel_return', 'medium', 'tunnel', 'Tunnel packet addressed back to its sender',
         f"{_j('tunnel', 'returns_to_sender')} = 1",
         lambda b: b.get('type', ''),
         "A scanner's test of whether a host unwraps tunnels from anyone - and would forward "
         "spoofed traffic."),
    Rule('rpc_exports', 'medium', 'rpc', 'NFS exports listed',
         f"{_j('rpc', 'exports')} IS NOT NULL",
         lambda b: _list(b.get('exports')),
         "A host listing its NFS shares to whoever asked."),
    Rule('syslog_critical', 'medium', 'syslog', 'Critical syslog message',
         _in('syslog', 'severity', ['emerg', 'alert', 'crit']),
         lambda b: _join(b.get('hostname'), b.get('program'), '-', (b.get('message') or '')[:120]),
         'A device logging an emergency, alert or critical condition.'),

    Rule('tls_certificate_out_of_date', 'low', 'tls', 'TLS certificate expired or not yet valid',
         _TLS_OUT_OF_DATE,
         lambda b: _join('valid', (b.get('notbefore') or '?')[:10], 'to', (b.get('notafter') or '?')[:10], '-',
                         _tls_certificate(b)),
         'The server offered a certificate outside its validity dates at the time - a forgotten renewal, a '
         'device with its clock wrong, or a certificate made up on the spot.'),
    Rule('tls_self_signed', 'low', 'tls', 'TLS self-signed certificate',
         f"{_j('tls', 'issuerdn')} = {_j('tls', 'subject')} AND {_j('tls', 'subject')} != ''",
         _tls_certificate,
         "A certificate that vouches for itself: common on appliances and lab servers, and what malware "
         "and interception tools generate. No client trusts one unless told to."),
    Rule('rip_whole_table', 'low', 'rip', 'RIP routing table handed out',
         f"{_j('rip', 'whole_table')} = 1 AND {_j('rip', 'responses')} IS NOT NULL",
         lambda b: _join(b.get('route_count'), 'routes'),
         'A router answered a request for its whole table - a map of the network for the asking.'),
    Rule('rpc_portmapper', 'low', 'rpc', 'RPC services listed',
         f"{_j('rpc', 'mappings')} IS NOT NULL",
         lambda b: _join(len(b.get('mappings') or ()), 'services'),
         "A portmapper listing every RPC service the host runs."),
    Rule('bacnet_write', 'low', 'bacnet', 'BACnet property or file written',
         _in('bacnet', 'service', ['writeProperty', 'writePropertyMultiple', 'atomicWriteFile']),
         lambda b: _join(b.get('service'), b.get('object'), b.get('property'), '-', b.get('result')),
         "Routine in building automation, but how a controller's setpoints and schedules are "
         "changed."),
    Rule('slp_answered', 'low', 'slp', 'SLP service answers',
         f"{_j('slp', 'response')} IS NOT NULL AND {_j('slp', 'function')} != 'Service Registration'",
         lambda b: _join(b.get('function'), '-', b.get('status')),
         'Exposed to the internet, SLP is how scanners find ESXi hosts and amplifiers.'),
    Rule('coap_discovery', 'low', 'coap', 'CoAP resources listed',
         f"{_j('coap', 'resources')} IS NOT NULL",
         lambda b: _list(b.get('resources')),
         "A device answering /.well-known/core with what it serves."),
    Rule('l2tp_no_auth', 'low', 'l2tp', 'L2TP tunnel without tunnel authentication',
         f"{_j('l2tp', 'state')} = 'established' AND {_j('l2tp', 'tunnel_authentication')} IS NULL",
         lambda b: _join(b.get('client_host_name'), 'to', b.get('server_host_name')),
         "Common, with IPsec protecting it - seen at all, this control connection is outside IPsec."),
    Rule('radius_reject', 'low', 'radius', 'RADIUS login rejected',
         f"{_j('radius', 'result')} = 'rejected'",
         lambda b: _join('user', b.get('user'), 'via', b.get('nas_ip')),
         'Many of them, for many users, is password guessing.'),
)

RULES_BY_ID = {r.id: r for r in RULES}


def _rule_sql(conn, rule, terms, has_fts, columns):
    """The SELECT of columns (of events) for rule's matches, and its
    parameters - a search joins the FTS index, whose own json_data column
    means every reference to events' must be qualified then."""
    alias = 'e.' if terms and has_fts else ''
    qualify = (lambda sql: sql.replace('json_data', 'e.json_data')) if alias else (lambda sql: sql)
    cols = ', '.join(alias + c if c != 'COUNT(*)' else c for c in columns)
    select, type_col = _events_select(terms, has_fts, cols, cols)
    conditions, params = _build_where_conditions(_has_acknowledged_alerts_table(conn), terms, has_fts,
                                                 rule.event_type, type_col)
    conditions.append(f'({qualify(rule.condition)})')
    return f"{select} WHERE {' AND '.join(conditions)}", params, alias


def query_findings(db_path, q=None, counts_only=False):
    """Every rule's matches in events.db: {'rules': [{id, title, severity,
    event_type, why, count}], 'findings': [{rule, severity, title, detail,
    event}]} - the findings in RULES' order (most severe first), then by
    time. A search (q)
    narrows both, as it does every tab."""
    result = {'rules': [], 'findings': []}
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return result
        types = {row[0] for row in conn.execute('SELECT DISTINCT event_type FROM events')}
        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False
        for rule in RULES:
            if rule.event_type not in types:
                continue
            try:
                sql, params, _ = _rule_sql(conn, rule, terms, has_fts, ['COUNT(*)'])
                count = conn.execute(sql, params).fetchone()[0]
            except sqlite3.OperationalError:
                continue
            if not count:
                continue
            result['rules'].append({'id': rule.id, 'title': rule.title, 'severity': rule.severity,
                                    'event_type': rule.event_type, 'why': rule.why, 'count': count})
            if counts_only:
                continue
            sql, params, alias = _rule_sql(conn, rule, terms, has_fts, ['id', 'json_data'])
            for row_id, data in conn.execute(f'{sql} ORDER BY {alias}timestamp LIMIT {MAX_PER_RULE}', params):
                try:
                    event = json.loads(data)
                except ValueError:
                    continue
                event['id'] = row_id
                body = event.get(rule.event_type) or {}
                try:
                    detail = rule.detail(body)
                except (AttributeError, TypeError, KeyError):
                    detail = ''
                result['findings'].append({'rule': rule.id, 'severity': rule.severity, 'title': rule.title,
                                           'detail': str(detail), 'event': event})
    if result['findings']:
        ids = sorted({f['event']['id'] for f in result['findings']})
        notes = {}
        for i in range(0, len(ids), 500):
            notes.update(get_row_notes(db_path, 'events', ids[i:i + 500]))
        for f in result['findings']:
            if f['event']['id'] in notes:
                f['event']['row_note'] = notes[f['event']['id']]
    order = {r.id: i for i, r in enumerate(RULES)}
    result['findings'].sort(key=lambda f: (order[f['rule']], f['event'].get('timestamp') or ''))
    return result
