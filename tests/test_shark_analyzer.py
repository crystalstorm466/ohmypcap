"""Tests for shark_analyzer.py - SHAR-CRATES, the tshark view of a PCAP:
grouping tshark's per-packet fields into Suricata-shaped flow records,
the background queue, and the API that serves shark.db. Tests that need
real tshark output skip when tshark isn't installed."""

import json
import os
import shutil
import subprocess
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
        """Everything but FTP's two known differences (next test)."""
        for event_type in ('dns', 'http', 'tls', 'modbus'):
            with self.subTest(event_type=event_type):
                self.assertEqual(self.report[event_type]['differences'], [])
                self.assertEqual(self.report[event_type]['matched'], self.report[event_type]['suricata'])
        self.assertEqual({t: r['matched'] for t, r in self.report.items()},
                         {'flow': 13, 'dns': 8, 'http': 3, 'tls': 1, 'modbus': 3, 'ftp': 7, 'ftp_data': 2,
                          'quic': 0, 'mdns': 0})

    def test_ftp_differs_from_suricata_only_in_two_known_ways(self):
        """Documented in docs/usage/exploring-results.md. (1) A multi-line
        reply: SHAR-CRATES has every reply code but only the first line's
        text - tshark doesn't expose the rest as fields. (2) A command
        Suricata doesn't recognize (OPTS): it logs the reply on its own;
        SHAR-CRATES pairs it with its command."""
        ftp = self.report['ftp']['differences']
        greeting = [d for d in ftp if d['key'][1] == (None, None) and 'fields' in d]
        self.assertEqual(len(greeting), 1)
        self.assertEqual(greeting[0]['fields'], {'reply': (['220-Welcome to the test FTP server', '220-Second greeting line', 'Ready.'],
                                                           ['Welcome to the test FTP server'])})
        self.assertIn('OPTS', [d['key'][1][0] for d in ftp if d.get('only') == 'shark'])
        self.assertTrue(any(d.get('only') == 'suricata' and d['record']['completion_code'] == ['504'] for d in ftp))
        self.assertEqual(len(ftp), 3, 'the greeting, and OPTS on each side')
        self.assertEqual(self.report['ftp_data']['differences'], [], 'passive and active data connections both match')
        self.assertEqual(self.report['flow']['differences'], [])

    def test_ftp_records(self):
        ftp = [r['ftp'] for r in self._of('ftp')]
        self.assertEqual(ftp[0], {'completion_code': ['220'], 'reply': ['Welcome to the test FTP server'], 'reply_received': 'yes'})
        retr = next(f for f in ftp if f.get('command') == 'RETR')
        self.assertEqual(retr['completion_code'], ['150', '226'], 'every reply to the command')
        pasv = next(f for f in ftp if f.get('command') == 'PASV')
        self.assertEqual((pasv['dynamic_port'], pasv['mode']), (50001, 'passive'))
        port = next(f for f in ftp if f.get('command') == 'PORT')
        self.assertEqual((port['dynamic_port'], port['mode']), (40965, 'active'))
        self.assertEqual(sorted((r['ftp_data']['command'], r['ftp_data']['filename']) for r in self._of('ftp_data')),
                         [('RETR', 'report.pdf'), ('STOR', 'upload.txt')])

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
        self.assertEqual(get_event_types_sqlite(db_path),
                         {'flow': 13, 'dns': 8, 'http': 3, 'tls': 1, 'modbus': 3, 'ftp': 9, 'ftp_data': 2})
        self.assertEqual(get_shark_summary_sqlite(db_path)['app_protos'],
                         {'dns': 7, 'ftp-data': 2, 'ftp': 1, 'http': 1, 'modbus': 1, 'tls': 1})


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestExtraCaptureAgainstSuricata(unittest.TestCase):
    """tests/protocol_fixtures.write_extra_pcap: the protocols only SHAR-CRATES
    records (NBNS, LLMNR, SSDP, S7comm), and the cases real captures turned
    up - each checked against what Suricata 8.0.6 logged for the same
    packets (tests/data/extra_fixture.eve.json) where Suricata parses it."""

    @classmethod
    def setUpClass(cls):
        from scripts.compare_shark_suricata import compare
        from tests.protocol_fixtures import write_extra_pcap
        cls.tmpdir = tempfile.mkdtemp()
        pcap = os.path.join(cls.tmpdir, 'extra.pcap')
        write_extra_pcap(pcap)
        cls.records = shark_analyzer.run_tshark(pcap)
        cls.report = compare(_load_eve('extra_fixture.eve.json'), cls.records)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _of(self, event_type):
        return [r[event_type] for r in self.records if r['event_type'] == event_type]

    def test_dns_http_ftp_and_mdns_match_suricata(self):
        for event_type in ('http', 'ftp', 'mdns'):
            with self.subTest(event_type=event_type):
                self.assertEqual(self.report[event_type]['differences'], [])
                self.assertEqual(self.report[event_type]['matched'], self.report[event_type]['suricata'])
        dns = self.report['dns']
        self.assertEqual(dns['matched'], dns['suricata'])
        self.assertEqual([(d.get('only'), d['record']['queries']) for d in dns['differences']],
                         [('shark', [('time.example.com', 'A')])] * 2,
                         'the only difference: the DNS Suricata never parsed on the flow caught mid-conversation')

    def test_flows_match_suricata_except_for_protocols_it_cannot_name(self):
        """Every flow's counts and times match - including the one an ICMP
        error belongs to - and the only differences are app_proto on flows
        of protocols Suricata doesn't parse (it even calls SSDP 'sip')."""
        diffs = self.report['flow']['differences']
        self.assertTrue(diffs)
        for d in diffs:
            self.assertEqual(set(d['fields']), {'app_proto'}, d)
            self.assertIn(d['fields']['app_proto'][0], (None, 'sip'))
            self.assertIn(d['fields']['app_proto'][1], ('llmnr', 'nbns', 'ssdp', 's7comm', 'dns'))
        self.assertEqual(self.report['flow']['reoriented'], 4,
                         'the flow caught mid-conversation, and the LLMNR, NBNS and SSDP answers on flows of their own')

    def _flow(self, port):
        [flow] = [r for r in self.records if r['event_type'] == 'flow' and port in (r.get('src_port'), r.get('dest_port'))]
        return flow

    def test_a_flow_caught_mid_conversation_is_addressed_from_whoever_asked(self):
        """REGRESSION (4SICS GeekLounge): the capture opened on a DNS server's
        answer, so the server was taken for the client and all 43,000 of
        the flow's queries were addressed from the server to the asker."""
        flow = self._flow(949)
        self.assertEqual((flow['src_ip'], flow['src_port'], flow['dest_ip'], flow['dest_port']),
                         ('10.1.0.10', 949, '10.1.0.53', 53))
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (1, 2))
        records = [r for r in self.records if r['event_type'] == 'dns' and r['dns']['queries'][0]['rrname'] == 'time.example.com']
        self.assertEqual([(r['src_ip'], r['dest_ip'], r['dns']['rcode']) for r in records],
                         [('10.1.0.10', '10.1.0.53', 'REFUSED')] * 2)

    def test_an_answer_on_a_flow_of_its_own_is_addressed_from_the_asker(self):
        """A multicast or broadcast question's unicast answer is a flow of
        one packet - from the answerer, but to the client that asked."""
        [flow] = [r for r in self.records if r['event_type'] == 'flow' and '10.1.0.70' in (r['src_ip'], r['dest_ip'])]
        self.assertEqual((flow['src_ip'], flow['dest_ip'], flow['dest_port']), ('10.1.0.10', '10.1.0.70', 5355))
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (0, 1))

    def test_an_announcement_to_a_group_keeps_its_sender_as_the_client(self):
        """An mDNS response to the multicast group answers nobody - the
        group can't be a client."""
        [flow] = [r for r in self.records if r['event_type'] == 'flow' and r['src_ip'] == '10.1.0.60' and r.get('src_port') == 5353]
        self.assertEqual(flow['dest_ip'], '224.0.0.251')

    def test_icmp_error_counts_in_its_flow_in_its_own_direction(self):
        """REGRESSION: the client's port unreachable carries a copy of the
        server's response - it was counted server-to-client, and its copy
        parsed as another DNS response."""
        [flow] = [r for r in self.records if r['event_type'] == 'flow' and r.get('src_port') == 53011]
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (2, 3))

    def test_dns_retransmissions_and_repeated_responses_are_one_transaction(self):
        """REGRESSION: each resent query, and each repeat of a response
        (tshark links only the first to its query), was its own record."""
        slow, echo = [d for d in self._of('dns') if d['queries'][0]['rrname'] in ('slow.example.com', 'echo.example.com')]
        self.assertEqual((slow['queries'][0]['rrname'], slow['type'], slow['transmissions']), ('slow.example.com', 'response', 2))
        self.assertEqual((echo['queries'][0]['rrname'], echo['type'], echo['responses']), ('echo.example.com', 'response', 3),
                         'the answer sent three times: one record that says so - repeated answers can be spoofing')
        self.assertNotIn('transmissions', echo)
        self.assertNotIn('responses', slow)

    def test_mdns_and_llmnr_are_not_dns(self):
        """REGRESSION: tshark decodes both with its DNS dissector, so their
        packets carry dns.* fields - they were recorded as DNS."""
        self.assertFalse([d for d in self._of('dns') if d['queries'][0]['rrname'].endswith('.local') or d['queries'][0]['rrname'] == 'wpad'])
        query, answer = self._of('mdns')
        self.assertEqual(answer['answers'], [{'rrname': '_ipp._tcp.local', 'ptr': 'printer._ipp._tcp.local'}],
                         "Suricata's mDNS answer layout")
        self.assertEqual(query['queries'], [{'rrname': '_ipp._tcp.local', 'rrtype': 'ptr'}])
        [llmnr] = self._of('llmnr')
        self.assertEqual((llmnr['type'], llmnr['answers'][0]['rdata']), ('response', '10.1.0.70'),
                         "a multicast query and its unicast answer, paired")

    def test_ssdp_is_not_http(self):
        """REGRESSION: SSDP's packets carry http.* fields."""
        [http] = self._of('http')
        self.assertEqual(http['hostname'], 'www.example.com', 'without its port, as Suricata logs it')
        self.assertEqual(http['http_content_type'], 'text/plain', 'without its parameters')
        search, answer, notify = self._of('ssdp')
        self.assertEqual((search['method'], search['search_target']),
                         ('M-SEARCH', 'urn:schemas-upnp-org:device:InternetGatewayDevice:1'))
        self.assertEqual((answer['status'], answer['location'], answer['server']),
                         (200, 'http://10.1.0.60:49152/gateway.xml', 'Linux/5.4 UPnP/1.0 TestGateway/1.0'))
        self.assertEqual((notify['method'], notify['notification_type'], notify['notification_sub_type'], notify['usn']),
                         ('NOTIFY', 'upnp:rootdevice', 'ssdp:alive', 'uuid:0b1d-test::upnp:rootdevice'))

    def test_nbns(self):
        registration, query = self._of('nbns')
        self.assertEqual({k: registration[k] for k in ('opcode', 'name', 'suffix', 'service', 'address', 'transmissions')},
                         {'opcode': 'registration', 'name': 'DESKTOP-TEST01', 'suffix': '20', 'service': 'Server service',
                          'address': '10.1.0.10', 'transmissions': 3}, 'three broadcasts, one record')
        self.assertEqual((query['opcode'], query['name'], query['type'], query['address']),
                         ('query', 'FILESERVER', 'response', '10.1.0.30'), 'the broadcast query and its direct answer, paired')

    def test_s7comm(self):
        setup, read, write, userdata = self._of('s7comm')
        self.assertEqual((setup['function'], setup['response']['function']), ('Setup communication', 'Setup communication'))
        self.assertEqual(read['items'], [{'area': 'Data blocks', 'db': 1, 'address': '10.0'}])
        self.assertEqual(write['response']['error_class'], 'Error on supplies')
        self.assertEqual((userdata['type'], userdata['function_group'], userdata['subfunction']), ('userdata', 'CPU functions', 1))

    def test_ftp_reply_after_a_final_reply_is_its_own_record(self):
        ftp = self._of('ftp')
        password = next(f for f in ftp if f.get('command') == 'PASS')
        self.assertEqual(password['completion_code'], ['530'])
        self.assertEqual(ftp[-1], {'completion_code': ['221'], 'reply': ['Goodbye.'], 'reply_received': 'yes'})


class TestFlowOrientation(unittest.TestCase):
    def _flow(self):
        return shark_analyzer._Flow(('udp', 0), 'UDP', 4, '10.0.0.53', '10.0.0.9', 53, 40000, 1.0, 0)

    def test_a_reply_first_turns_the_flow_round(self):
        flow = self._flow()
        flow.add('10.0.0.53', 53, 80, 1.0, 'dns', '', False)
        flow.orient('10.0.0.53', 53, True)
        self.assertEqual((flow.client, flow.cport, flow.server, flow.pkts_ts, flow.pkts_tc), ('10.0.0.9', 40000, '10.0.0.53', 0, 1))

    def test_only_the_first_request_or_reply_decides(self):
        flow = self._flow()
        flow.orient('10.0.0.53', 53, False)    # the first sender's request: it is the client
        flow.orient('10.0.0.53', 53, True)
        self.assertEqual(flow.client, '10.0.0.53')

    def test_a_stream_that_opens_on_a_syn_ack_is_the_other_sides(self):
        """Found in the 4SICS GeekLounge capture: a server re-sends its
        SYN-ACK after the client reset the connection, and tshark starts a
        new stream there - whose first sender is the server."""
        from tests.pcap_fixtures import _tcp_packet, write_pcap
        with tempfile.TemporaryDirectory() as tmp:
            pcap = os.path.join(tmp, 'synack.pcap')
            write_pcap(pcap, [_tcp_packet('10.0.0.80', '10.0.0.9', 80, 40000, 5000, 1001, 0x12),
                              _tcp_packet('10.0.0.9', '10.0.0.80', 40000, 80, 1001, 0, 0x04)])
            [flow] = [e for e in shark_analyzer.run_tshark(pcap) if e['event_type'] == 'flow']
        self.assertEqual((flow['src_ip'], flow['src_port'], flow['dest_port']), ('10.0.0.9', 40000, 80))
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (1, 1))

    def test_a_syn_outranks_a_message(self):
        flow = shark_analyzer._Flow(('tcp', 0), 'TCP', 4, '10.0.0.9', '10.0.0.80', 40000, 80, 1.0, 0)
        flow.add('10.0.0.9', 40000, 60, 1.0, '', '', True)
        flow.orient('10.0.0.9', 40000, True)
        self.assertEqual(flow.client, '10.0.0.9')

    def test_what_marks_a_reply(self):
        def cols(**values):
            out = [''] * len(shark_analyzer._ALL_FIELDS)
            for name, value in values.items():
                out[shark_analyzer._COLUMN[name.replace('__', '.')]] = value
            return out
        cases = [({'dns__flags__response': 'True'}, True), ({'dns__flags__response': 'False'}, False),
                 ({'nbns__flags__response': '1'}, True), ({'http__response__code': '200'}, True),
                 ({'http__request__method': 'GET'}, False), ({'ftp__response__code': '220'}, True),
                 ({'ftp__request__command': 'USER'}, False), ({'s7comm__header__rosctr': '3'}, True),
                 ({'s7comm__header__rosctr': '1'}, False), ({'s7comm__header__rosctr': '7'}, None),
                 ({'tls__handshake__type': '2'}, True), ({'tls__handshake__type': '1\x1f16'}, False),   # the first of a packet's handshakes
                 ({'tls__handshake__type': '11'}, None), ({'mbtcp__trans_id': '1'}, None), ({}, None)]
        for values, expected in cases:
            with self.subTest(values=values):
                self.assertIs(shark_analyzer._is_reply(cols(**values)), expected)

    def test_group_addresses(self):
        self.assertEqual([shark_analyzer._is_group_address(a) for a in
                          ('224.0.0.251', '239.255.255.250', '255.255.255.255', '10.1.0.255', 'ff02::fb', '10.1.0.10', '2001:db8::1', 'aa:bb:cc:dd:ee:ff')],
                         [True, True, True, True, True, False, False, False])


class TestProtocolDetails(unittest.TestCase):
    def test_each_field_is_asked_of_tshark_once(self):
        """REGRESSION: SSDP reads HTTP's fields, and tshark fills only one
        column of a field asked for twice - HTTP's came back empty."""
        self.assertEqual(len(shark_analyzer._ALL_FIELDS), len(set(shark_analyzer._ALL_FIELDS)))
        from shark_protocols import HTTP, SSDP
        self.assertTrue(set(HTTP.fields) & set(SSDP.fields), 'the case this guards')

    def test_host_without_port(self):
        from shark_protocols import _host_without_port as h
        self.assertEqual([h(x) for x in ('a.example', 'a.example:8080', '[2001:db8::1]:80', '2001:db8::1', '10.0.0.1:81')],
                         ['a.example', 'a.example', '2001:db8::1', '2001:db8::1', '10.0.0.1'])

    def test_tls_versions_use_suricatas_names(self):
        from shark_protocols import _tls_version
        self.assertEqual([_tls_version(v) for v in ('0x0300', '0x0301', '0x0303', '0x0304')],
                         ['SSLv3', 'TLSv1', 'TLS 1.2', 'TLS 1.3'])

    def _fields(self, cls, **values):
        return {f: values.get(f.replace('.', '_'), []) for f in cls.fields}

    def test_quic_handshakes_are_quic_records(self):
        """REGRESSION: QUIC's TLS handshake was recorded as TLS."""
        from shark_protocols import TLS, Packet
        tls = TLS()
        flow = mock.Mock(key=('udp', 1))
        tls.feed(Packet(1, 1.0, flow, 50000, 443, 'quic'), self._fields(
            TLS, quic_version=['0x00000001'], tls_handshake_type=['1'], tls_handshake_extensions_server_name=['q.example'],
            tls_handshake_ja4=['q13d0311h3_55b375c5d22e_f2a83c8e78ae']))
        flow2 = mock.Mock(key=('udp', 2))
        tls.feed(Packet(2, 2.0, flow2, 50001, 443, 'quic'), self._fields(TLS, quic_version=['0x6b3343cf']))
        (_, _, kind, body), (_, _, _, other) = tls.finish()
        self.assertEqual((kind, body['version'], body['sni']), ('quic', '1', 'q.example'))
        self.assertEqual(other['version'], '6b3343cf', 'any other version in hex, as Suricata writes it')

    def test_modbus_function_with_no_data_access(self):
        from shark_protocols import Modbus, Packet
        m = Modbus()
        m.feed(Packet(1, 1.0, mock.Mock(key=('tcp', 1)), 40000, 502), self._fields(
            Modbus, mbtcp_trans_id=['1'], mbtcp_prot_id=['0'], mbtcp_unit_id=['1'], modbus_func_code=['43']))
        [(_, _, _, body)] = m.finish()
        self.assertEqual((body['request']['function_code'], body['request']['access_type']), ('MEI', 'NONE'))

    def test_empty_mdns_message_is_skipped(self):
        from shark_protocols import DNS, Packet
        d = DNS()
        d.feed(Packet(1, 1.0, mock.Mock(key=('udp', 1)), 5353, 5353, 'mdns'), self._fields(DNS, dns_id=['0x0000']))
        self.assertEqual(d.finish(), [])


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestConnectionTypes(unittest.TestCase):
    """conn_<app proto>: a tab per protocol with no records of its own, as
    a view on the flow rows (db.CONNECTION_TYPE_PREFIX). In
    tests/pcap_fixtures.write_http_pcap's capture, the Telnet session gets
    one; the three HTTP flows don't - HTTP has records."""

    @classmethod
    def setUpClass(cls):
        from tests.pcap_fixtures import write_http_pcap
        cls.dir = tempfile.mkdtemp()
        pcap = os.path.join(cls.dir, 'http.pcap')
        write_http_pcap(pcap)
        shark_analyzer.analyze(cls.dir, pcap)
        cls.db = shark_analyzer.shark_db_path(cls.dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_counts_one_type_per_unrecorded_protocol(self):
        import db
        from shark_protocols import RECORDED_APP_PROTOS
        self.assertIn('http', RECORDED_APP_PROTOS)
        self.assertIn('ftp-data', RECORDED_APP_PROTOS, 'FTP records cover its data connections too')
        self.assertEqual(db.get_connection_type_counts_sqlite(self.db, None, RECORDED_APP_PROTOS), {'conn_telnet': 1})
        self.assertEqual(db.get_connection_type_counts_sqlite(self.db, ['10.0.0.1'], RECORDED_APP_PROTOS), {},
                         'a search narrows them like any count')

    def test_every_query_reads_a_connection_type_as_its_flows(self):
        import db
        [flow] = db.query_events_sqlite(self.db, 'conn_telnet')
        self.assertEqual((flow['event_type'], flow['app_proto'], flow['dest_port']), ('flow', 'telnet', 23))
        self.assertEqual(db.get_event_count_sqlite(self.db, 'conn_telnet'), 1)
        agg = db.get_aggregation_data_sqlite(self.db, 'conn_telnet')
        self.assertEqual(agg['App Proto'], [{'value': 'telnet', 'count': 1}], "flow's columns")
        self.assertEqual(db.get_aggregation_totals_sqlite(self.db, 'conn_telnet')['Dest Port'], 1)
        self.assertEqual(len(db.query_events_sqlite(self.db, 'conn_telnet', order_by='Bytes →', sort_dir='desc')), 1)
        self.assertTrue(db.get_sankey_data_sqlite(self.db, 'conn_telnet')['links'])
        self.assertEqual(db.query_events_sqlite(self.db, 'conn_nope'), [])

    def test_connection_types_are_never_cached(self):
        """Their names are whatever the client sends."""
        from analysis_cache import cacheable_aggregation_key
        self.assertFalse(cacheable_aggregation_key('conn_telnet'))
        self.assertFalse(cacheable_aggregation_key('conn_telnet', 'Dest Port'))


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
        status = shark_analyzer.status(self.dir, self.pcap)
        self.assertIsInstance(status.pop('seconds'), int, 'how long the run took')
        self.assertEqual(status, {'status': 'ready'})

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
            self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'running', 'elapsed': 0})
            self.assertFalse(shark_analyzer.enqueue(self.dirs[0], self.pcaps[0]), 'already running')
            self.assertEqual(shark_analyzer.status(self.dirs[1]), {'status': 'queued', 'position': 1})
            gate.set()
            self.assertTrue(shark_analyzer.wait_idle(10))
        self.assertEqual(order, self.dirs)

    def test_a_run_reports_its_seconds_while_running_and_once_ready(self):
        gate = threading.Event()

        def fake(dir_path, pcap_path, on_start=None):
            gate.wait(10)
        with mock.patch.object(shark_analyzer, 'analyze', side_effect=fake):
            shark_analyzer.enqueue(self.dirs[0], self.pcaps[0])
            deadline = time.monotonic() + 5
            while shark_analyzer.status(self.dirs[0])['status'] != 'running' and time.monotonic() < deadline:
                time.sleep(0.02)
            with mock.patch.object(shark_analyzer.time, 'time', return_value=shark_analyzer._running_since + 42.7):
                self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'running', 'elapsed': 42})
            gate.set()
            self.assertTrue(shark_analyzer.wait_idle(10))

    @unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
    def test_a_built_shark_db_records_how_long_its_run_took(self):
        from tests.protocol_fixtures import write_protocol_pcap
        write_protocol_pcap(self.pcaps[0])
        with mock.patch.object(shark_analyzer.time, 'monotonic', side_effect=[100.0, 117.4] + [200.0] * 50):
            self.assertTrue(shark_analyzer.build(self.dirs[0], self.pcaps[0]))
        self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'ready', 'seconds': 17})

    def test_a_shark_db_without_its_run_time_is_still_ready(self):
        """Built before runs recorded their time: no 'seconds', no error."""
        import sqlite3
        conn = sqlite3.connect(shark_analyzer.shark_db_path(self.dirs[0]))
        conn.execute(f'PRAGMA user_version = {shark_analyzer.SHARK_FORMAT_VERSION}')
        conn.close()
        self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'ready'})

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

    def test_cancel_kills_a_running_build_and_its_tshark_without_recording_an_error(self):
        """The build runs in a child process with tshark as its own child:
        cancelling kills the whole process group, so neither outlives it."""
        marker = os.path.join(self.dirs[0], 'grandchild.pid')
        with mock.patch.object(shark_analyzer, '_child_command',
                               return_value=['sh', '-c', f'sleep 30 & echo $! > {marker}; wait']):
            shark_analyzer.enqueue(self.dirs[0], self.pcaps[0])
            deadline = time.monotonic() + 5
            while not (os.path.exists(marker) and os.path.getsize(marker)) and time.monotonic() < deadline:
                time.sleep(0.02)
            grandchild = int(open(marker).read())
            start = time.monotonic()
            shark_analyzer.cancel(self.dirs[0])
            self.assertTrue(shark_analyzer.wait_idle(10))
        self.assertLess(time.monotonic() - start, 5)
        deadline = time.monotonic() + 5
        while os.path.exists(f'/proc/{grandchild}') and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(os.path.exists(f'/proc/{grandchild}'), "the build's own child (tshark) was killed too")
        self.assertFalse(os.path.exists(os.path.join(self.dirs[0], shark_analyzer.SHARK_ERROR)))
        self.assertFalse(os.path.exists(shark_analyzer.shark_db_path(self.dirs[0])))

    def test_a_build_that_dies_without_saying_why_is_recorded_as_an_error(self):
        """Killed (out of memory, most often) or crashed: the build never
        got to write .shark_error, so analyze does."""
        for command, expected in ((['sh', '-c', 'kill -9 $$'], 'tshark analysis stopped: killed - out of memory?'),
                                  (['sh', '-c', 'echo "MemoryError: boom" >&2; exit 1'], 'tshark analysis stopped: MemoryError: boom')):
            with self.subTest(command=command), mock.patch.object(shark_analyzer, '_child_command', return_value=command):
                shark_analyzer.analyze(self.dirs[0], self.pcaps[0])
                self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'error', 'message': expected})

    @unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
    def test_the_build_runs_in_its_own_lower_priority_process(self):
        from tests.protocol_fixtures import write_protocol_pcap
        write_protocol_pcap(self.pcaps[0])
        seen = {}
        real_popen = subprocess.Popen

        def spy(cmd, **kwargs):
            seen.update(cmd=cmd, kwargs=kwargs)
            return real_popen(cmd, **kwargs)
        with mock.patch.object(shark_analyzer.subprocess, 'Popen', side_effect=spy):
            shark_analyzer.analyze(self.dirs[0], self.pcaps[0])
        self.assertEqual(seen['cmd'][-4:], ['shark_analyzer', 'build', self.dirs[0], self.pcaps[0]])
        self.assertTrue(seen['kwargs']['start_new_session'])
        self.assertIs(seen['kwargs']['preexec_fn'], shark_analyzer._low_priority)
        self.assertEqual(shark_analyzer.status(self.dirs[0])['status'], 'ready')


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
        self.assertIsInstance(body.pop('seconds'), int)
        self.assertEqual(body, {'status': 'ready', 'flows': 3, 'app_protos': {'ftp': 1, 'ftp-data': 1, 'http': 1}})

    def test_view_shark_reads_shark_db_and_the_default_reads_events_db(self):
        self._get(f'/api/shark-status?md5={self.md5}')
        self._wait_ready()
        _, flows = self._get(f'/api/events?md5={self.md5}&view=shark&type=flow')
        self.assertEqual(len(flows), 3)
        _, stats = self._get(f'/api/stats?md5={self.md5}&view=shark')
        self.assertEqual(stats['counts'], {'flow': 3, 'http': 1, 'ftp': 7, 'ftp_data': 1})
        _, count = self._get(f'/api/count?md5={self.md5}&view=shark&type=flow')
        self.assertEqual(count, {'count': 3})
        _, suricata = self._get(f'/api/events?md5={self.md5}&type=flow')
        self.assertEqual(suricata, [], 'without view=shark, events.db (empty here) is read')
        status, _ = self._get(f'/api/events?md5={self.md5}&view=wireshark')
        self.assertEqual(status, 400)

    def test_shark_stats_add_a_tab_per_unrecorded_protocol(self):
        from tests.pcap_fixtures import write_http_pcap
        write_http_pcap(os.path.join(self.dir, 'sample.pcap'))   # its Telnet session has no records
        self._get(f'/api/shark-status?md5={self.md5}')
        self._wait_ready()
        _, shark = self._get(f'/api/stats?md5={self.md5}&view=shark')
        self.assertEqual(shark['counts'], {'flow': 4, 'http': 3, 'conn_telnet': 1})
        _, suricata = self._get(f'/api/stats?md5={self.md5}')
        self.assertEqual(suricata['counts'], {}, 'SURI-CRATES never gets them')

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
