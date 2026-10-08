"""Tests for shark_analyzer.py - SHAR-CRATES, the tshark view of a PCAP:
grouping tshark's per-packet fields into Suricata-shaped flow records,
the background queue, and the API that serves shark.db. Tests that need
real tshark output skip when tshark isn't installed."""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import config
import shark_analyzer
import socrates as server
import storage
from db import init_empty_db, query_events_sqlite
from samples import build_pcap_sample

HAS_TSHARK = bool(shutil.which('tshark'))


def _line(**fields):
    """One tshark field line (tshark_command's column order)."""
    return '\t'.join(str(fields.get(name.replace('.', '_'), '')) for name in shark_analyzer._FIELDS) + '\n'


def _tcp(t, src, sport, dst, dport, stream, protos='eth:ethertype:ip:tcp', length=60, syn='0', ack='1', cid='1:abc='):
    return _line(frame_time_epoch=t, frame_len=length, frame_protocols=protos, ip_src=src, ip_dst=dst,
                 ip_proto=6, tcp_srcport=sport, tcp_dstport=dport, tcp_stream=stream,
                 tcp_flags_syn=syn, tcp_flags_ack=ack, communityid=cid)


class TestAppProtocol(unittest.TestCase):
    def test_first_layer_above_the_transport(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:tls'), 'tls')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:udp:dns'), 'dns')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:http:data-text-lines'), 'http')

    def test_carrier_layers_are_skipped(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:tpkt:cotp:s7comm'), 's7comm')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:nbss:smb2'), 'smb', "Suricata's name for it")

    def test_bare_transport_and_undecoded_payload_have_none(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp'), '')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:data'), '')

    def test_no_transport_uses_the_top_layer(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:arp'), 'arp')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:icmp'), 'icmp')
        self.assertEqual(shark_analyzer.app_protocol(''), '')


class TestBuildFlows(unittest.TestCase):
    def test_one_flow_per_tcp_stream_counted_per_direction(self):
        lines = [
            _tcp(1.0, '10.0.0.1', 40000, '10.0.0.2', 80, 0, syn='1', ack='0', length=74),
            _tcp(1.1, '10.0.0.2', 80, '10.0.0.1', 40000, 0, syn='1', ack='1', length=74),
            _tcp(1.2, '10.0.0.1', 40000, '10.0.0.2', 80, 0, protos='eth:ethertype:ip:tcp:http', length=200),
            _tcp(1.5, '10.0.0.2', 80, '10.0.0.1', 40000, 0, protos='eth:ethertype:ip:tcp:http', length=900),
        ]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual((flow['src_ip'], flow['src_port'], flow['dest_ip'], flow['dest_port']),
                         ('10.0.0.1', 40000, '10.0.0.2', 80))
        self.assertEqual((flow['proto'], flow['app_proto'], flow['event_type'], flow['ip_v']), ('TCP', 'http', 'flow', 4))
        self.assertEqual(flow['flow']['pkts_toserver'], 2)
        self.assertEqual(flow['flow']['pkts_toclient'], 2)
        self.assertEqual(flow['flow']['bytes_toserver'], 274)
        self.assertEqual(flow['flow']['bytes_toclient'], 974)
        self.assertEqual(flow['flow']['start'], '1970-01-01T00:00:01.000000+0000')
        self.assertEqual(flow['flow']['end'], '1970-01-01T00:00:01.500000+0000')
        self.assertEqual(flow['timestamp'], flow['flow']['start'])
        self.assertEqual(flow['community_id'], '1:abc=')
        self.assertEqual(flow['shark'], {'protocols': {'http': 2}, 'stream': 0})

    def test_syn_decides_the_client_when_the_capture_starts_mid_handshake(self):
        """A capture whose first packet is the server's SYN-ACK still names
        the SYN's sender as the client, as Suricata does."""
        lines = [
            _tcp(1.0, '10.0.0.2', 80, '10.0.0.1', 40000, 0, syn='1', ack='1'),
            _tcp(1.1, '10.0.0.1', 40000, '10.0.0.2', 80, 0, syn='1', ack='0'),
            _tcp(1.2, '10.0.0.1', 40000, '10.0.0.2', 80, 0),
        ]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual((flow['src_ip'], flow['dest_port']), ('10.0.0.1', 80))
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (2, 1))

    def test_without_a_syn_the_first_sender_is_the_client(self):
        lines = [_tcp(1.0, '10.0.0.2', 80, '10.0.0.1', 40000, 0), _tcp(1.1, '10.0.0.1', 40000, '10.0.0.2', 80, 0)]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual(flow['src_ip'], '10.0.0.2')

    def test_flows_are_ordered_by_first_packet(self):
        lines = [_tcp(5.0, '10.0.0.1', 1, '10.0.0.2', 2, 1), _tcp(1.0, '10.0.0.3', 3, '10.0.0.4', 4, 0),
                 _tcp(6.0, '10.0.0.1', 1, '10.0.0.2', 2, 1)]
        self.assertEqual([f['src_ip'] for f in shark_analyzer.build_flows(lines)], ['10.0.0.3', '10.0.0.1'])

    def test_udp_flow(self):
        lines = [
            _line(frame_time_epoch=1, frame_len=80, frame_protocols='eth:ethertype:ip:udp:dns', ip_src='10.0.0.1',
                  ip_dst='10.0.0.53', ip_proto=17, udp_srcport=5000, udp_dstport=53, udp_stream=0),
            _line(frame_time_epoch=2, frame_len=120, frame_protocols='eth:ethertype:ip:udp:dns', ip_src='10.0.0.53',
                  ip_dst='10.0.0.1', ip_proto=17, udp_srcport=53, udp_dstport=5000, udp_stream=0),
        ]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual((flow['proto'], flow['app_proto'], flow['src_port'], flow['dest_port']), ('UDP', 'dns', 5000, 53))
        self.assertEqual(flow['shark']['protocols'], {'dns': 2})

    def test_icmp_flows_have_no_ports_and_pair_both_directions(self):
        lines = [
            _line(frame_time_epoch=1, frame_len=98, frame_protocols='eth:ethertype:ip:icmp:data', ip_src='10.0.0.1',
                  ip_dst='10.0.0.2', ip_proto=1),
            _line(frame_time_epoch=2, frame_len=98, frame_protocols='eth:ethertype:ip:icmp:data', ip_src='10.0.0.2',
                  ip_dst='10.0.0.1', ip_proto=1),
        ]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual((flow['proto'], flow['app_proto']), ('ICMP', 'icmp'))
        self.assertNotIn('src_port', flow)
        self.assertNotIn('stream', flow['shark'])
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (1, 1))

    def test_ipv6_flow(self):
        line = _line(frame_time_epoch=1, frame_len=90, frame_protocols='eth:ethertype:ipv6:tcp:http',
                     ipv6_src='2001:db8::1', ipv6_dst='2001:db8::2', ipv6_nxt=6, tcp_srcport=40001,
                     tcp_dstport=8080, tcp_stream=0)
        [flow] = shark_analyzer.build_flows([line])
        self.assertEqual((flow['src_ip'], flow['ip_v'], flow['proto']),
                         ('2001:0db8:0000:0000:0000:0000:0000:0001', 6, 'TCP'), 'written out in full, like Suricata')

    def test_non_ip_traffic_is_grouped_by_mac_addresses_and_protocol(self):
        arp = dict(frame_len=42, frame_protocols='eth:ethertype:arp', eth_src='00:00:00:00:00:01', eth_dst='ff:ff:ff:ff:ff:ff')
        [flow] = shark_analyzer.build_flows([_line(frame_time_epoch=1, **arp), _line(frame_time_epoch=2, **arp)])
        self.assertEqual((flow['proto'], flow['app_proto'], flow['src_ip']), ('ARP', 'arp', '00:00:00:00:00:01'))
        self.assertNotIn('ip_v', flow)
        self.assertEqual(flow['flow']['pkts_toserver'], 2)

    def test_malformed_lines_are_skipped(self):
        good = _tcp(1.0, '10.0.0.1', 1, '10.0.0.2', 2, 0)
        self.assertEqual(len(shark_analyzer.build_flows(['', 'garbage\n', 'x\t' * 30 + '\n', good])), 1)

    def test_protocols_count_every_layer_seen_most_first(self):
        lines = [_tcp(1.0, '10.0.0.1', 1, '10.0.0.2', 21, 0, protos='eth:ethertype:ip:tcp:ftp')] + \
                [_tcp(2.0 + i, '10.0.0.1', 1, '10.0.0.2', 21, 0, protos='eth:ethertype:ip:tcp:tls') for i in range(3)]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual(flow['app_proto'], 'ftp', "the flow's first application protocol names it")
        self.assertEqual(list(flow['shark']['protocols'].items()), [('tls', 3), ('ftp', 1)])


class TestTsharkCommand(unittest.TestCase):
    def test_plain_fields_with_community_id(self):
        cmd = shark_analyzer.tshark_command('/x.pcap')
        self.assertEqual(cmd[:4], ['tshark', '-n', '-r', '/x.pcap'])
        self.assertIn('--enable-protocol', cmd)
        self.assertEqual(cmd[cmd.index('--enable-protocol') + 1], 'communityid')
        self.assertEqual(cmd[cmd.index('-T') + 1], 'fields')
        self.assertEqual([cmd[i + 1] for i, a in enumerate(cmd) if a == '-e'], list(shark_analyzer._ALL_FIELDS))

    def test_shark_artifacts_are_removed_on_reanalyze(self):
        for name in shark_analyzer.SHARK_ARTIFACTS:
            self.assertIn(name, storage.PCAP_ANALYSIS_ARTIFACTS)


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestAgainstSuricata(unittest.TestCase):
    """The built-in Sample PCAP file's flows, with the values Suricata
    8.0.6 itself logged for the same capture (its eve.json flow events) -
    every field the two views share agrees."""

    SURICATA_FLOWS = {
        '1:EpYHmrPJXlZhxCKCpAtvF5gS/54=': ('10.20.4.12', 51733, '203.0.113.66', 80, 'http', 6, 4, 490, 1034),
        '1:2NztZopomhYFALQ23BcQ7v3z3E8=': ('10.20.4.12', 51791, '203.0.113.66', 50000, 'ftp-data', 5, 3, 667, 162),
    }

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'sample.pcap')
        with open(cls.pcap, 'wb') as f:
            f.write(build_pcap_sample())
        cls.flows = {f['community_id']: f for f in shark_analyzer.run_tshark(cls.pcap) if f['event_type'] == 'flow'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_the_same_three_flows(self):
        self.assertEqual(sorted(f['app_proto'] for f in self.flows.values()), ['ftp', 'ftp-data', 'http'])
        for cid in self.SURICATA_FLOWS:
            self.assertIn(cid, self.flows, 'Community IDs must match Suricata\'s')

    def test_every_shared_field_matches_suricata(self):
        for cid, expected in self.SURICATA_FLOWS.items():
            f = self.flows[cid]
            got = (f['src_ip'], f['src_port'], f['dest_ip'], f['dest_port'], f['app_proto'],
                   f['flow']['pkts_toserver'], f['flow']['pkts_toclient'],
                   f['flow']['bytes_toserver'], f['flow']['bytes_toclient'])
            self.assertEqual(got, expected, cid)


class TestFieldParsing(unittest.TestCase):
    def test_unescape_undoes_tsharks_escapes(self):
        self.assertEqual(shark_analyzer._unescape(r'v=spf1 a\tb\\c'), 'v=spf1 a\tb\\c')
        self.assertEqual(shark_analyzer._unescape(r'line\nnext\r'), 'line\nnext\r')
        self.assertEqual(shark_analyzer._unescape(r'\x41\x1f'), 'A\x1f')
        self.assertEqual(shark_analyzer._unescape('plain'), 'plain')

    def test_ipv6_is_written_out_in_full_like_suricata(self):
        self.assertEqual(shark_analyzer.ipv6_exploded('2001:db8::7'), '2001:0db8:0000:0000:0000:0000:0000:0007')
        self.assertEqual(shark_analyzer.ipv6_exploded('not an address'), 'not an address')

    def test_app_proto_uses_suricatas_names(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:mbtcp:modbus'), 'modbus')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:nbss:smb2'), 'smb')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:udp:kerberos'), 'krb5')

    def test_rpc_is_the_protocol_only_when_nothing_follows_it(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:rpc:nfs'), 'nfs')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:udp:rpc:portmap'), 'portmap')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:rpc'), 'rpc')

    def test_command_outputs_every_occurrence_joined_by_the_aggregator(self):
        cmd = shark_analyzer.tshark_command('/x.pcap')
        self.assertIn('occurrence=a', cmd)
        self.assertIn('aggregator=\x1f', cmd)
        fields = [cmd[i + 1] for i, a in enumerate(cmd) if a == '-e']
        self.assertEqual(fields[:len(shark_analyzer._FIELDS)], list(shark_analyzer._FIELDS))
        self.assertIn('dns.response_to', fields)
        self.assertIn('tls.handshake.ja4', fields)


def _load_eve(name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', name)
    with open(path) as f:
        return [json.loads(line) for line in f]


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestProtocolRecordsAgainstSuricata(unittest.TestCase):
    """SHAR-CRATES's records for tests/protocol_fixtures.py's capture,
    compared with what Suricata 8.0.6 logged for the same packets
    (tests/data/protocol_fixture.eve.json - regenerate it with Suricata
    if the fixture ever changes). Every flow, DNS, HTTP, TLS and Modbus
    record must agree on every shared field."""

    @classmethod
    def setUpClass(cls):
        from scripts.compare_shark_suricata import compare
        from tests.protocol_fixtures import write_protocol_pcap
        cls.tmpdir = tempfile.mkdtemp()
        pcap = os.path.join(cls.tmpdir, 'protocols.pcap')
        write_protocol_pcap(pcap)
        cls.records = shark_analyzer.run_tshark(pcap)
        cls.report = compare(_load_eve('protocol_fixture.eve.json'), cls.records)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _of(self, event_type):
        return [r for r in self.records if r['event_type'] == event_type]

    def test_every_record_matches_suricata(self):
        for event_type, result in self.report.items():
            with self.subTest(event_type=event_type):
                self.assertEqual(result['differences'], [])
                self.assertEqual(result['matched'], result['suricata'])
        self.assertEqual({t: r['matched'] for t, r in self.report.items()},
                         {'flow': 10, 'dns': 8, 'http': 3, 'tls': 1, 'modbus': 3})

    def test_dns_pairs_queries_with_responses_and_keeps_the_unanswered(self):
        by_name = {r['dns']['queries'][0]['rrname']: r for r in self._of('dns')}
        self.assertEqual(by_name['lost.example.com']['dns']['type'], 'request')
        self.assertNotIn('rcode', by_name['lost.example.com']['dns'])
        self.assertEqual(by_name['missing.example.com']['dns']['rcode'], 'NXDOMAIN')
        self.assertEqual([a['rdata'] for a in by_name['cdn.example.net']['dns']['answers']],
                         ['edge.example.net', '198.51.100.7'])
        self.assertEqual(by_name['txt.example.com']['dns']['answers'][0]['rdata'], 'v=spf1 a\tb\\c')
        www = by_name['www.example.com']
        self.assertEqual((www['src_ip'], www['src_port'], www['dest_port']), ('10.1.0.10', 53001, 53))
        self.assertEqual(www['timestamp'], '2023-11-14T22:13:20.000000+0000', "the query's time")

    def test_http_pairs_each_request_on_a_keep_alive_connection(self):
        self.assertEqual([(r['http']['http_method'], r['http']['url'], r['http']['status']) for r in self._of('http')],
                         [('GET', '/index.html', 200), ('GET', '/missing', 404), ('POST', '/upload', 201)])

    def test_tls_session(self):
        [tls] = self._of('tls')
        self.assertEqual(tls['tls']['ja4'], 't13d0407h2_358020e8f41d_078775ef5e04')
        self.assertEqual(tls['tls']['version'], 'TLS 1.3')

    def test_modbus_exception_response(self):
        third = [r for r in self._of('modbus') if r['modbus']['id'] == 3][0]['modbus']
        self.assertEqual(third['request']['read'], {'address': 0, 'quantity': 8})
        self.assertEqual(third['response']['function_raw'], 0x81)
        self.assertEqual(third['response']['exception'], {'raw': 2, 'code': 'IllegalDataAddr'})

    def test_records_land_in_shark_db_and_its_summary(self):
        from db import create_shark_db, get_event_types_sqlite, get_shark_summary_sqlite
        db_path = os.path.join(self.tmpdir, 'shark.db')
        create_shark_db(db_path, self.records)
        self.assertEqual(get_event_types_sqlite(db_path), {'flow': 10, 'dns': 8, 'http': 3, 'tls': 1, 'modbus': 3})
        self.assertEqual(get_shark_summary_sqlite(db_path)['app_protos'],
                         {'dns': 7, 'http': 1, 'modbus': 1, 'tls': 1})


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestKnownDifferencesFromSuricata(unittest.TestCase):
    """tests/pcap_fixtures.write_http_pcap's IPv6, VLAN and retransmission
    flows all match Suricata's (tests/data/http_fixture.eve.json). The one
    expected difference: Suricata counts a response body's bytes itself
    when there's no Content-Length header; SHAR-CRATES reports the header
    (counting the body would mean tshark printing every body in full)."""

    def test_only_body_length_without_a_content_length_header_differs(self):
        from scripts.compare_shark_suricata import compare
        from tests.pcap_fixtures import write_http_pcap
        tmpdir = tempfile.mkdtemp()
        try:
            pcap = os.path.join(tmpdir, 'http.pcap')
            write_http_pcap(pcap)
            report = compare(_load_eve('http_fixture.eve.json'), shark_analyzer.run_tshark(pcap))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        self.assertEqual(report['flow']['differences'], [])
        self.assertEqual(report['flow']['matched'], 4, 'IPv6, VLAN and retransmitted flows included')
        self.assertEqual(len(report['http']['differences']), 3)
        for d in report['http']['differences']:
            self.assertEqual(d['fields'], {'length': (519, None)})


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestAnalyze(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.pcap = os.path.join(self.dir, 'sample.pcap')
        with open(self.pcap, 'wb') as f:
            f.write(build_pcap_sample())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_writes_a_queryable_shark_db_and_nothing_else(self):
        shark_analyzer.analyze(self.dir, self.pcap)
        events = query_events_sqlite(shark_analyzer.shark_db_path(self.dir), 'flow')
        self.assertEqual(len(events), 3)
        self.assertFalse(os.path.exists(os.path.join(self.dir, 'shark.db.tmp')))
        self.assertFalse(os.path.exists(os.path.join(self.dir, shark_analyzer.SHARK_ERROR)))
        self.assertEqual(shark_analyzer.status(self.dir, self.pcap), {'status': 'ready'})

    def test_shark_db_is_stamped_and_an_older_format_is_rebuilt(self):
        """REGRESSION: shark.db existing meant 'ready' forever, so an
        analysis built before a SHAR-CRATES change never got it - its
        flows-only shark.db hid the protocol records added since."""
        import sqlite3
        shark_analyzer.analyze(self.dir, self.pcap)
        db_path = shark_analyzer.shark_db_path(self.dir)
        self.assertEqual(shark_analyzer.format_version(db_path), shark_analyzer.SHARK_FORMAT_VERSION)
        conn = sqlite3.connect(db_path)
        conn.execute('PRAGMA user_version = 1')
        conn.commit()
        conn.close()
        self.assertEqual(shark_analyzer.status(self.dir, self.pcap), {'status': 'not_started'})
        self.assertFalse(os.path.exists(db_path), 'the stale database is removed so it gets rebuilt')

    def test_a_failed_run_records_why_and_leaves_no_database(self):
        with open(self.pcap, 'wb') as f:
            f.write(b'not a pcap at all')
        shark_analyzer.analyze(self.dir, self.pcap)
        self.assertFalse(os.path.exists(shark_analyzer.shark_db_path(self.dir)))
        status = shark_analyzer.status(self.dir, self.pcap)
        self.assertEqual(status['status'], 'error')
        self.assertIn('tshark failed', status['message'])

    def test_timeout(self):
        with mock.patch.object(shark_analyzer, 'tshark_command', return_value=['sleep', '30']):
            start = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, 'timed out after 0.3s'):
                shark_analyzer.run_tshark(self.pcap, timeout=0.3)
        self.assertLess(time.monotonic() - start, 10)

    def test_background_size_limit(self):
        self.assertTrue(shark_analyzer.background_eligible(self.pcap))
        with mock.patch.object(config, 'SHARK_BACKGROUND_MAX_BYTES', 10):
            self.assertFalse(shark_analyzer.background_eligible(self.pcap))
            self.assertEqual(shark_analyzer.status(self.dir, self.pcap), {'status': 'too_large'})
        self.assertFalse(shark_analyzer.background_eligible(os.path.join(self.dir, 'missing.pcap')))


class TestQueue(unittest.TestCase):
    def setUp(self):
        self.dirs = [tempfile.mkdtemp() for _ in range(2)]
        self.pcaps = []
        for d in self.dirs:
            p = os.path.join(d, 'x.pcap')
            open(p, 'wb').close()
            self.pcaps.append(p)

    def tearDown(self):
        for d in self.dirs:
            shark_analyzer.cancel(d)
        self.assertTrue(shark_analyzer.wait_idle(15))
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def test_one_run_at_a_time_in_order_and_no_duplicates(self):
        gate, order = threading.Event(), []

        def fake(dir_path, pcap_path, on_start=None):
            order.append(dir_path)
            gate.wait(10)
        with mock.patch.object(shark_analyzer, 'analyze', side_effect=fake):
            self.assertTrue(shark_analyzer.enqueue(self.dirs[0], self.pcaps[0]))
            self.assertTrue(shark_analyzer.enqueue(self.dirs[1], self.pcaps[1]))
            self.assertFalse(shark_analyzer.enqueue(self.dirs[1], self.pcaps[1]), 'already queued')
            deadline = time.monotonic() + 5
            while shark_analyzer.status(self.dirs[0])['status'] != 'running' and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'running'})
            self.assertFalse(shark_analyzer.enqueue(self.dirs[0], self.pcaps[0]), 'already running')
            self.assertEqual(shark_analyzer.status(self.dirs[1]), {'status': 'queued', 'position': 1})
            gate.set()
            self.assertTrue(shark_analyzer.wait_idle(10))
        self.assertEqual(order, self.dirs)

    def test_cancel_drops_a_queued_run(self):
        gate, ran = threading.Event(), []

        def fake(dir_path, pcap_path, on_start=None):
            ran.append(dir_path)
            gate.wait(10)
        with mock.patch.object(shark_analyzer, 'analyze', side_effect=fake):
            shark_analyzer.enqueue(self.dirs[0], self.pcaps[0])
            shark_analyzer.enqueue(self.dirs[1], self.pcaps[1])
            shark_analyzer.cancel(self.dirs[1])
            self.assertEqual(shark_analyzer.status(self.dirs[1]), {'status': 'not_started'})
            gate.set()
            self.assertTrue(shark_analyzer.wait_idle(10))
        self.assertEqual(ran, [self.dirs[0]])

    def test_cancel_kills_a_running_tshark_without_recording_an_error(self):
        with mock.patch.object(shark_analyzer, 'tshark_command', return_value=['sleep', '30']):
            shark_analyzer.enqueue(self.dirs[0], self.pcaps[0])
            deadline = time.monotonic() + 5
            while shark_analyzer._running_proc is None and time.monotonic() < deadline:
                time.sleep(0.02)
            start = time.monotonic()
            shark_analyzer.cancel(self.dirs[0])
            self.assertTrue(shark_analyzer.wait_idle(10))
        self.assertLess(time.monotonic() - start, 5)
        self.assertFalse(os.path.exists(os.path.join(self.dirs[0], shark_analyzer.SHARK_ERROR)))
        self.assertFalse(os.path.exists(shark_analyzer.shark_db_path(self.dirs[0])))


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestSharkAPI(unittest.TestCase):
    """GET /api/shark-status, POST /api/shark-start, and view=shark on the
    read-only data endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.original_base = server.DATA_DIR
        server.DATA_DIR = cls.tmpdir
        cls.server = server.ThreadedTCPServer(('127.0.0.1', 0), server.Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        server.DATA_DIR = cls.original_base
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.md5 = os.urandom(16).hex()
        self.dir = os.path.join(self.tmpdir, self.md5)
        os.makedirs(self.dir)
        with open(os.path.join(self.dir, 'sample.pcap'), 'wb') as f:
            f.write(build_pcap_sample())
        init_empty_db(os.path.join(self.dir, 'events.db'))   # Suricata's view, done

    def tearDown(self):
        shark_analyzer.cancel(self.dir)
        shark_analyzer.wait_idle(15)

    def _get(self, path):
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{self.port}{path}', timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b'{}')

    def _post(self, path, body):
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}', data=json.dumps(body).encode(),
                                     headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b'{}')

    def _wait_ready(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            _, body = self._get(f'/api/shark-status?md5={self.md5}')
            if body['status'] not in ('queued', 'running'):
                return body
            time.sleep(0.1)
        self.fail('SHAR-CRATES never finished')

    def test_first_status_request_queues_it_and_it_becomes_ready_with_a_summary(self):
        status, body = self._get(f'/api/shark-status?md5={self.md5}')
        self.assertEqual(status, 200)
        self.assertIn(body['status'], ('queued', 'running', 'ready'))
        body = self._wait_ready()
        self.assertEqual(body, {'status': 'ready', 'flows': 3, 'app_protos': {'ftp': 1, 'ftp-data': 1, 'http': 1}})

    def test_view_shark_reads_shark_db_and_the_default_reads_events_db(self):
        self._get(f'/api/shark-status?md5={self.md5}')
        self._wait_ready()
        _, flows = self._get(f'/api/events?md5={self.md5}&view=shark&type=flow')
        self.assertEqual(len(flows), 3)
        _, stats = self._get(f'/api/stats?md5={self.md5}&view=shark')
        self.assertEqual(stats['counts'], {'flow': 3, 'http': 1})
        _, count = self._get(f'/api/count?md5={self.md5}&view=shark&type=flow')
        self.assertEqual(count, {'count': 3})
        _, suricata = self._get(f'/api/events?md5={self.md5}&type=flow')
        self.assertEqual(suricata, [], 'without view=shark, events.db (empty here) is read')
        status, _ = self._get(f'/api/events?md5={self.md5}&view=wireshark')
        self.assertEqual(status, 400)

    def test_view_shark_aggregation_cache_is_kept_apart_from_suricatas(self):
        self._get(f'/api/shark-status?md5={self.md5}')
        self._wait_ready()
        _, shark = self._get(f'/api/aggregation-totals?md5={self.md5}&view=shark&type=flow')
        _, suricata = self._get(f'/api/aggregation-totals?md5={self.md5}&type=flow')
        self.assertNotEqual(shark, suricata)
        self.assertIn((self.md5, 'shark', 'flow'), server.AGGREGATION_TOTALS_CACHE)
        server.evict_analysis_cache(self.md5)
        self.assertNotIn((self.md5, 'shark', 'flow'), server.AGGREGATION_TOTALS_CACHE)

    def test_waits_for_suricata(self):
        with open(os.path.join(self.dir, '.phase'), 'w') as f:
            f.write('network')
        _, body = self._get(f'/api/shark-status?md5={self.md5}')
        self.assertEqual(body, {'status': 'waiting'})

    def test_too_large_waits_to_be_asked_then_shark_start_runs_it(self):
        with mock.patch.object(config, 'SHARK_BACKGROUND_MAX_BYTES', 10):
            _, body = self._get(f'/api/shark-status?md5={self.md5}')
            self.assertEqual(body, {'status': 'too_large'})
            status, body = self._post('/api/shark-start', {'md5': self.md5})
            self.assertEqual(status, 200)
            self.assertIn(body['status'], ('queued', 'running', 'ready'))
            self.assertEqual(self._wait_ready()['status'], 'ready')

    def test_not_a_pcap_analysis(self):
        os.unlink(os.path.join(self.dir, 'sample.pcap'))
        with open(os.path.join(self.dir, 'notes.txt'), 'w') as f:
            f.write('hi')
        _, body = self._get(f'/api/shark-status?md5={self.md5}')
        self.assertEqual(body, {'status': 'unavailable'})

    def test_unknown_or_invalid_analysis(self):
        self.assertEqual(self._get('/api/shark-status?md5=' + 'a' * 32)[0], 404)
        self.assertEqual(self._get('/api/shark-status?md5=nope')[0], 400)
        self.assertEqual(self._post('/api/shark-start', {'md5': 'a' * 32})[0], 404)

    def test_delete_cancels_a_queued_run(self):
        with mock.patch.object(shark_analyzer, 'cancel', wraps=shark_analyzer.cancel) as cancel:
            status, _ = self._post('/api/delete-analysis', {'md5': self.md5})
        self.assertEqual(status, 200)
        cancel.assert_called_once_with(self.dir)


if __name__ == '__main__':
    unittest.main()
