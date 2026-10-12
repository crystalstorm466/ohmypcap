#!/usr/bin/env python3
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import db
import findings


def _record(event_type, body, n=0, **top):
    event = {'event_type': event_type, 'timestamp': f'2026-01-01T00:00:{n:02d}.000000+0000',
             'src_ip': '10.0.0.5', 'src_port': 40000 + n, 'dest_ip': '10.0.0.9', 'dest_port': 1000 + n,
             'proto': 'UDP', 'source': 'tshark', event_type: body}
    event.update(top)
    return event


# A record each rule matches, by rule id - shaped as shark_protocols.py
# writes them
MATCHES = {
    'ipmi_cipher_zero': ('ipmi', {'requested_privilege': 'administrator', 'weaknesses': ['cipher zero accepted']}),
    'ipmi_anonymous': ('ipmi', {'weaknesses': ['anonymous login']}),
    'ipmi_weak_auth': ('ipmi', {'weaknesses': ['cleartext password']}),
    'opcua_cleartext_password': ('opcua', {'username': 'user1', 'password': 'hunter2',
                                           'endpoint': 'opc.tcp://plc:4840/'}),
    'telnet_login': ('telnet', {'banner': 'MOXA', 'username': 'admin', 'password': 'moxa-secret',
                                'login': 'failed'}),
    's7_plc_control': ('s7comm', {'function': 'PLC Stop'}),
    's7_download': ('s7comm', {'function': 'Download block'}),
    'bacnet_device_control': ('bacnet', {'service': 'reinitializeDevice', 'state': 'coldstart',
                                         'password': 'bacnet-secret', 'result': 'ok'}),
    'goose_anomaly': ('goose', {'anomaly': 'stNum skipped 4', 'stnum_gap': 4}),
    'slp_registration': ('slp', {'function': 'Service Registration', 'status': 'OK',
                                 'url': 'service:printer:lpr://198.51.100.14'}),
    's7_write': ('s7comm', {'function': 'Write Var', 'response': {'item_count': 1}}),
    'iec104_control': ('iec104', {'action': 'Single command', 'ioa': 2, 'result': 'confirmed'}),
    'opcua_change': ('opcua_action', {'service': 'Write', 'node': 'ns=1;s=x', 'result': 'Good'}),
    'socks_open': ('socks', {'auth_method': 'no authentication', 'status': 'succeeded',
                             'request_name': 'files.example.net', 'request_port': 80}),
    'xdmcp_offered': ('xdmcp', {'result': 'willing', 'server_host_name': 'labsrv'}),
    'rip_default_route': ('rip', {'command': 'response', 'routes': ['10.2.0.0/16 metric 1', '0.0.0.0/0 metric 1']}),
    'rip_cleartext_password': ('rip', {'authentication': 'simple password', 'route_count': 3}),
    'tunnel_return': ('tunnel', {'type': 'IP-in-IP', 'returns_to_sender': True}),
    'rpc_exports': ('rpc', {'exports': ['/srv/nfs']}),
    'syslog_critical': ('syslog', {'severity': 'crit', 'hostname': 'fw01', 'message': 'disk failing'}),
    'rip_whole_table': ('rip', {'command': 'request', 'whole_table': True, 'responses': 1, 'route_count': 2}),
    'rpc_portmapper': ('rpc', {'mappings': [{'program': 'nfs'}, {'program': 'mountd'}]}),
    'bacnet_write': ('bacnet', {'service': 'writeProperty', 'object': 'analog-value,0', 'result': 'ok'}),
    'slp_answered': ('slp', {'function': 'Service Request', 'response': 'Service Reply', 'status': 'OK'}),
    'coap_discovery': ('coap', {'resources': ['/sensors/temp']}),
    'l2tp_no_auth': ('l2tp', {'state': 'established', 'client_host_name': 'WIN-CLIENT7'}),
    'radius_reject': ('radius', {'result': 'rejected', 'user': 'bob', 'nas_ip': '10.1.0.2'}),
}

# Records like those the rules look for that no rule should match
NON_MATCHES = [
    ('ipmi', {'weaknesses': []}),
    ('ipmi', {'result': 'answered'}),
    ('opcua', {'username': 'user1', 'password_encrypted': True}),
    ('telnet', {'banner': 'MOXA'}),
    ('telnet', {'banner': 'MOXA', 'username': '', 'password': ''}),
    ('s7comm', {'function': 'Read Var'}),
    ('bacnet', {'service': 'readProperty'}),
    ('goose', {'changed': ['a']}),
    ('slp', {'function': 'Service Registration'}),
    ('iec104', {'action': 'Interrogation', 'result': 'confirmed, terminated'}),
    ('socks', {'auth_method': 'username/password', 'status': 'succeeded'}),
    ('socks', {'auth_method': 'no authentication', 'status': 'rejected'}),
    ('xdmcp', {'result': 'unwilling'}),
    ('rip', {'command': 'response', 'routes': ['10.0.0.0/8 metric 1', '10.0.0.0/24 metric 2']}),
    ('rip', {'command': 'request', 'whole_table': True}),
    ('tunnel', {'type': 'GRE'}),
    ('syslog', {'severity': 'err'}),
    ('l2tp', {'state': 'established', 'tunnel_authentication': True}),
    ('l2tp', {'state': 'refused'}),
    ('radius', {'result': 'accepted'}),
]


class TestFindings(unittest.TestCase):
    def _db(self, events):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        eve = os.path.join(tmp, 'eve.json')
        with open(eve, 'w') as f:
            for e in events:
                f.write(json.dumps(e) + '\n')
        path = os.path.join(tmp, 'events.db')
        db.create_sqlite_db(path, eve)
        return path

    def test_every_rule_has_a_match_here(self):
        self.assertEqual(set(MATCHES), set(findings.RULES_BY_ID))

    def test_rules_are_ordered_most_severe_first(self):
        ranks = [findings.SEVERITIES.index(r.severity) for r in findings.RULES]
        self.assertEqual(ranks, sorted(ranks))

    def test_each_rule_finds_its_record(self):
        events = [_record(t, b, i) for i, (t, b) in enumerate(MATCHES.values())]
        result = findings.query_findings(self._db(events))
        found = {}
        for f in result['findings']:
            found.setdefault(f['rule'], []).append(f['event'][f['event']['event_type']])
        for rule, (event_type, body) in MATCHES.items():
            self.assertIn(body, found.get(rule, []), f'{rule} should find its record')

    def test_lookalikes_are_not_findings(self):
        events = [_record(t, b, i) for i, (t, b) in enumerate(NON_MATCHES)]
        result = findings.query_findings(self._db(events))
        self.assertEqual(result['findings'], [], [(f['rule'], f['event']) for f in result['findings']])
        self.assertEqual(result['rules'], [])

    def test_no_detail_carries_a_password(self):
        events = [_record(t, b, i) for i, (t, b) in enumerate(MATCHES.values())]
        result = findings.query_findings(self._db(events))
        details = ' '.join(f['detail'] for f in result['findings'])
        for secret in ('hunter2', 'moxa-secret', 'bacnet-secret'):
            self.assertNotIn(secret, details)
        by_rule = {f['rule']: f['detail'] for f in result['findings']}
        self.assertEqual(by_rule['telnet_login'], 'user admin - login failed')
        self.assertEqual(by_rule['opcua_cleartext_password'], 'user user1 on opc.tcp://plc:4840/')
        self.assertEqual(by_rule['rip_default_route'], '0.0.0.0/0 metric 1')
        self.assertEqual(by_rule['s7_write'], '1 items')

    def test_counts_and_order(self):
        events = [_record('bacnet', {'service': 'writeProperty'}, i) for i in range(3)]
        events.append(_record('ipmi', {'weaknesses': ['cipher zero accepted', 'anonymous login']}, 9))
        result = findings.query_findings(self._db(events))
        self.assertEqual([(r['id'], r['count']) for r in result['rules']],
                         [('ipmi_cipher_zero', 1), ('ipmi_anonymous', 1), ('bacnet_write', 3)])
        self.assertEqual([f['rule'] for f in result['findings']],
                         ['ipmi_cipher_zero', 'ipmi_anonymous', 'bacnet_write', 'bacnet_write', 'bacnet_write'])
        self.assertEqual(result['findings'][0]['severity'], 'high')
        self.assertIn('CVE-2013-4782', result['rules'][0]['why'])
        counts = findings.query_findings(self._db(events), counts_only=True)
        self.assertEqual(counts['findings'], [])
        self.assertEqual(sum(r['count'] for r in counts['rules']), 5)

    def test_a_rule_shows_at_most_its_cap(self):
        events = [_record('bacnet', {'service': 'writeProperty'}, i % 60) for i in range(findings.MAX_PER_RULE + 7)]
        result = findings.query_findings(self._db(events))
        self.assertEqual(result['rules'][0]['count'], findings.MAX_PER_RULE + 7)
        self.assertEqual(len(result['findings']), findings.MAX_PER_RULE)

    def test_search_narrows_findings(self):
        events = [_record('tunnel', {'type': 'GRE', 'returns_to_sender': True}, 1),
                  _record('tunnel', {'type': 'VXLAN', 'returns_to_sender': True}, 2, dest_ip='192.0.2.77')]
        path = self._db(events)
        result = findings.query_findings(path, q=['192.0.2.77'])
        self.assertEqual([f['event']['tunnel']['type'] for f in result['findings']], ['VXLAN'])
        self.assertEqual(result['rules'][0]['count'], 1)
        self.assertEqual(findings.query_findings(path, q=['nothing-like-this'])['rules'], [])

    def test_findings_carry_their_row_notes(self):
        path = self._db([_record('tunnel', {'type': 'GRE', 'returns_to_sender': True}, 1)])
        row_id = findings.query_findings(path)['findings'][0]['event']['id']
        db.set_row_note(path, 'events', row_id, 'checked - our scanner')
        self.assertEqual(findings.query_findings(path)['findings'][0]['event']['row_note'], 'checked - our scanner')

    def test_an_analysis_with_no_events(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        path = os.path.join(tmp, 'events.db')
        db.init_empty_db(path)
        self.assertEqual(findings.query_findings(path), {'rules': [], 'findings': []})

if __name__ == '__main__':
    unittest.main()
