"""Tests for shark_analyzer.py - tshark's part of a PCAP analysis:
grouping tshark's per-packet fields into Suricata-shaped flows and
records, the merge into events.db, the background queue and the status
API. Tests that need
real tshark output skip when tshark isn't installed."""

import json
import os
import shutil
import struct
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
import db
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
        self.assertEqual([cmd[i + 1] for i, a in enumerate(cmd) if a == '-e'], list(shark_analyzer._FIRST_PASS_FIELDS))

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
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:udp:cldap'), 'ldap')

    def test_rpc_is_the_protocol_only_when_nothing_follows_it(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:rpc:nfs'), 'nfs')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:udp:rpc:portmap'), 'portmap')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:rpc'), 'rpc')

    def test_the_osi_layers_carry_mms(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:tpkt:cotp:ses:pres:mms'), 'mms')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:tpkt:cotp:ses:pres:acse:mms'), 'mms')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:tpkt:cotp:ses'), 'ses')

    def test_command_outputs_every_occurrence_joined_by_the_aggregator(self):
        cmd = shark_analyzer.tshark_command('/x.pcap')
        self.assertIn('occurrence=a', cmd)
        self.assertIn('aggregator=\x1f', cmd)
        fields = [cmd[i + 1] for i, a in enumerate(cmd) if a == '-e']
        self.assertEqual(fields[:len(shark_analyzer._FIELDS)], list(shark_analyzer._FIELDS))
        self.assertIn('tls.handshake.type', fields, 'flow orientation reads it, though no records here do')
        self.assertNotIn('dns.response_to', fields, "a protocol's fields are the protocol pass's")
        from shark_protocols import PROTOCOLS
        cmd = shark_analyzer.tshark_command('/x.pcap', shark_analyzer._protocol_pass_fields(PROTOCOLS))
        fields = [cmd[i + 1] for i, a in enumerate(cmd) if a == '-e']
        self.assertEqual(fields[:len(shark_analyzer._FIELDS)], list(shark_analyzer._FIELDS))
        self.assertIn('dns.response_to', fields)


def _load_eve(name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', name)
    with open(path) as f:
        return [json.loads(line) for line in f]


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestFlowsAgainstSuricata(unittest.TestCase):
    """tests/protocol_fixtures.py's capture (DNS, HTTP, TLS, Modbus, FTP):
    tshark's flows compared with what Suricata 8.0.6 logged for the same
    packets (tests/data/protocol_fixture.eve.json - regenerate it with
    Suricata if the fixture ever changes). Suricata's own records for
    these protocols are the analysis's; tshark adds none of them."""

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

    def test_every_flow_matches_suricata(self):
        self.assertEqual(self.report['flow']['differences'], [])
        self.assertEqual(self.report['flow']['matched'], 13)

    def test_no_records_for_protocols_suricata_parses(self):
        self.assertEqual({r['event_type'] for r in self.records}, {'flow'})

@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestExtraCaptureAgainstSuricata(unittest.TestCase):
    """tests/protocol_fixtures.write_extra_pcap: the protocols tshark adds
    (NBNS, LLMNR, SSDP, S7comm), and the flow cases real captures turned
    up - checked against what Suricata 8.0.6 logged for the same packets
    (tests/data/extra_fixture.eve.json)."""

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
        answer, so the server was taken for the client of the flow."""
        flow = self._flow(949)
        self.assertEqual((flow['src_ip'], flow['src_port'], flow['dest_ip'], flow['dest_port']),
                         ('10.1.0.10', 949, '10.1.0.53', 53))
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (1, 2))

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

    def test_llmnr_and_only_the_protocols_suricata_lacks(self):
        """tshark decodes LLMNR (and mDNS) with its DNS dissector, and SSDP
        with its HTTP one: only LLMNR, NBNS, SSDP and S7comm become records."""
        self.assertEqual({r['event_type'] for r in self.records} - {'flow'}, {'llmnr', 'nbns', 'ssdp', 's7comm'})
        [llmnr] = self._of('llmnr')
        self.assertEqual((llmnr['type'], llmnr['answers'][0]['rdata']), ('response', '10.1.0.70'),
                         "a multicast query and its unicast answer, paired")
        self.assertEqual(llmnr['queries'], [{'rrname': 'wpad', 'rrtype': 'A'}])

    def test_ssdp(self):
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

@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestTelnet(unittest.TestCase):
    """tests/protocol_fixtures.write_telnet_pcap: a login, a failed login and
    a scanner's HTTP request to the Telnet port - with what Suricata 8.0.7
    logged for them (tests/data/telnet_fixture.eve.json): a 'telnet' label
    and nothing else for the two sessions, HTTP for the probe."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_telnet_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'telnet.pcap')
        write_telnet_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.by_port = {r['src_port']: r['telnet'] for r in cls.records if r['event_type'] == 'telnet'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_login_rebuilt_from_its_keystrokes(self):
        """Each key its own segment, the server's echo ignored, a
        backspace applied, an arrow key no command."""
        self.assertEqual(self.by_port[41023], {'banner': 'Ubuntu 22.04.3 LTS', 'username': 'admin', 'password': 's3cret',
                                               'commands': ['ls -la', 'exit']})

    def test_a_failed_login(self):
        self.assertEqual(self.by_port[41024], {'banner': 'MOXA EtherDevice Switch EDS-508A', 'username': 'admin',
                                               'password': 'admin', 'login': 'failed'})

    def test_flows_match_suricata(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('telnet_fixture.eve.json'), self.records)['flow']
        self.assertEqual(report['matched'], 2)
        self.assertEqual([d['fields'] for d in report['differences']], [{'app_proto': ('http', 'telnet')}],
                         'only the probe: HTTP by its content to Suricata, Telnet by its port to tshark')

    def test_the_merge_adds_the_sessions_suricata_only_labelled(self):
        """Suricata recognizes Telnet but logs nothing about it: a 'telnet'
        label alone keeps nothing out. The probe it logged as HTTP stays
        Suricata's."""
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'telnet_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'telnet.pcap')))
        shark_analyzer.merge(d)
        merged = db.query_events_sqlite(events_db, 'telnet')
        self.assertEqual(sorted(e['src_port'] for e in merged), [41023, 41024])
        self.assertNotIn('conn_telnet', db.get_event_types_sqlite(events_db))


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestIEC104(unittest.TestCase):
    """tests/protocol_fixtures.write_iec104_pcap: control actions paired with
    their replies, and monitored points summarized - with what Suricata
    8.0.7 logged for the capture (tests/data/iec104_fixture.eve.json): a
    flow it gives no protocol, since it doesn't parse IEC 104."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_iec104_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'iec104.pcap')
        write_iec104_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.actions = [r['iec104'] for r in cls.records if r['event_type'] == 'iec104']
        cls.points = {p['ioa']: p for p in (r['iec104_point'] for r in cls.records if r['event_type'] == 'iec104_point')}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_control_actions_with_their_replies(self):
        self.assertEqual([(a['action'], a.get('value'), a['result']) for a in self.actions], [
            ('Interrogation', 'station', 'confirmed, terminated'),
            ('Single command', 'on', 'confirmed, terminated'),
            ('Set point (float)', 3.25, 'negative'),
            ('Interrogation', 'station', 'confirmed, terminated'),
            ('Interrogation', 'station', 'confirmed, terminated'),
            ('Clock synchronization', None, 'confirmed (request not seen)'),
        ], 'two interrogations sent before either was answered each get their own replies, in order')
        command = self.actions[1]
        self.assertEqual((command['type'], command['station'], command['ioa'], command['response']),
                         ('C_SC_NA_1', 7, 2001, {'cause': 'actcon', 'negative': False}))

    def test_points_summarize_their_updates(self):
        """Including a packet that carries two messages, split by their
        object counts."""
        self.assertEqual(sorted(self.points), [1001, 1002, 1003])
        p = self.points[1001]
        self.assertEqual((p['type'], p['updates'], p['causes'], p['last_value']),
                         ('M_ME_NC_1', 2, {'inrogen': 1, 'spont': 1}, 231.0))
        self.assertEqual((self.points[1003]['type'], self.points[1003]['last_value']), ('M_SP_NA_1', 1))

    def test_the_flow_matches_suricatas_and_the_merge_adds_both_kinds(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('iec104_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (1, 1, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'iec104_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'iec104.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual((counts.get('iec104'), counts.get('iec104_point')), (6, 3))
        self.assertNotIn('conn_iec60870_104', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestBACnet(unittest.TestCase):
    """tests/protocol_fixtures.write_bacnet_pcap: actions paired with their
    replies, reads and value notifications summarized per object and
    property, devices from their I-Ams - with what Suricata 8.0.7 logged
    for the capture (tests/data/bacnet_fixture.eve.json): flows it gives
    no protocol, since it doesn't parse BACnet."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_bacnet_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'bacnet.pcap')
        write_bacnet_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.actions = [r['bacnet'] for r in cls.records if r['event_type'] == 'bacnet']
        cls.properties = {p['object']: p for p in (r['bacnet_property'] for r in cls.records
                                                   if r['event_type'] == 'bacnet_property')}
        cls.devices = [r['bacnet_device'] for r in cls.records if r['event_type'] == 'bacnet_device']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_actions_with_their_replies(self):
        self.assertEqual([(a['service'], a.get('object'), a.get('value'), a.get('result')) for a in self.actions], [
            ('who-Is', None, None, None),
            ('who-Is', None, None, None),
            ('writeProperty', 'binary-output,3', 'active', 'ok'),
            ('writeProperty', 'analog-value,2', 50.0, 'ok'),
            ('reinitializeDevice', None, None, 'error: services: password-failure'),
            ('deviceCommunicationControl', None, None, 'ok'),
        ], 'a write and a read sent with the same invoke id each get their own reply, though they came in the other order')
        self.assertEqual(self.actions[1]['range'], '100-200')

    def test_the_same_discovery_question_is_one_record_counted(self):
        from tests.protocol_fixtures import bacnet_packets, _bacnet_ip, _BACNET_BROADCAST, CLIENT
        from tests.pcap_fixtures import write_pcap
        who_is = _bacnet_ip(CLIENT, _BACNET_BROADCAST, b'\x10\x08', broadcast=True)
        path = os.path.join(self.tmpdir, 'who_is.pcap')
        write_pcap(path, bacnet_packets() + [who_is] * 3)
        asked = [r['bacnet'] for r in shark_analyzer.run_tshark(path)
                 if r['event_type'] == 'bacnet' and r['bacnet']['service'] == 'who-Is']
        self.assertEqual([(a.get('range'), a['count']) for a in asked], [(None, 4), ('100-200', 1)])
        self.assertEqual(asked[0]['last_seen'][:19], '2023-11-14T22:13:41')

    def test_passwords_and_states_come_from_the_requests_bytes(self):
        """tshark shows them only as text."""
        reinit, control = self.actions[4], self.actions[5]
        self.assertEqual((reinit['state'], reinit['password']), ('warmstart', 'filister'))
        self.assertEqual((control['state'], control['duration'], control['password']), ('disable', 5, 'secret'))

    def test_reads_and_notifications_are_summarized(self):
        read = self.properties['analog-value,1']
        self.assertEqual((read['service'], read['property'], read['count'], read['errors'], read['last_value'],
                          read['last_error']),
                         ('readProperty', 'present-value', 2, 1, 72.5, 'error: property: unknown-property'))
        self.assertEqual(self.properties['analog-value,2']['last_value'], 49.0)
        cov = self.properties['analog-input,2']
        self.assertEqual((cov['service'], cov['device'], cov['last_value']),
                         ('unconfirmedCOVNotification', 'device,1047', 21.5))

    def test_devices_from_their_i_ams_with_tsharks_vendor_name(self):
        self.assertEqual([(d['device'], d['vendor_id'], d['vendor'], d['announcements']) for d in self.devices],
                         [(1047, 42, 'Acuity Brands Lighting, Inc.', 2)])

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('bacnet_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (3, 3, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'bacnet_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'bacnet.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual((counts.get('bacnet'), counts.get('bacnet_property'), counts.get('bacnet_device')), (6, 3, 1))
        self.assertNotIn('conn_bvlc', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestOPCUA(unittest.TestCase):
    """tests/protocol_fixtures.write_opcua_pcap, read by the structured
    pass: the connection's session, and its changes with their own
    statuses - with what Suricata 8.0.7 logged for the capture
    (tests/data/opcua_fixture.eve.json): a flow it gives no protocol,
    since it doesn't parse OPC UA."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_opcua_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'opcua.pcap')
        write_opcua_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.sessions = [r['opcua'] for r in cls.records if r['event_type'] == 'opcua']
        cls.actions = [r['opcua_action'] for r in cls.records if r['event_type'] == 'opcua_action']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_the_session(self):
        self.assertEqual(len(self.sessions), 1)
        s = self.sessions[0]
        self.assertEqual({k: s.get(k) for k in ('endpoint', 'security_policy', 'security_mode', 'client_application',
                                                'session_name', 'user_token', 'username', 'activation')},
                         {'endpoint': 'opc.tcp://10.1.0.48:4840/fixture', 'security_policy': 'None', 'security_mode': 'None',
                          'client_application': 'Fixture Client', 'session_name': 'Fixture Session',
                          'user_token': 'username', 'username': 'user1', 'activation': 'Good'})
        self.assertEqual(s['password'], 's3cret', 'a UserName token with no encryption algorithm carries it in the clear')
        self.assertEqual((s['services']['Read'], s['services']['Publish'], s['errors'], s['last_error']),
                         (1, 1, 1, 'Publish: BadNoSubscription'))

    def test_changes_with_their_own_statuses(self):
        self.assertEqual(self.actions, [
            {'service': 'Write', 'node': 'ns=1;s=the.answer', 'attribute': 'Value', 'value': '42', 'result': 'Good'},
            {'service': 'Call', 'node': 'ns=1;i=62541', 'object': 'i=85', 'arguments': ['Hello'],
             'result': 'BadNodeIdUnknown'},
        ], 'the call was refused for its one operation though the response itself was Good')

    def test_status_names_are_tsharks(self):
        from shark_protocols import _opcua_status
        self.assertEqual([_opcua_status(c) for c in ('0x00000000', '0x80340000', '0x801f0000', '0x80ff0000')],
                         ['Good', 'BadNodeIdUnknown', 'BadUserAccessDenied', '0x80ff0000'])

    def test_the_flow_matches_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('opcua_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (1, 1, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'opcua_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'opcua.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual((counts.get('opcua'), counts.get('opcua_action')), (1, 2))
        self.assertNotIn('conn_opcua', counts, 'records, not a connection card')

    def test_a_loopback_capture_is_decoded_too(self):
        """The structured pass decodes only the link layers it enables;
        OPC UA test servers are often captured on loopback."""
        from tests.protocol_fixtures import opcua_packets
        path = os.path.join(self.tmpdir, 'loopback.pcap')
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 0))          # DLT_NULL
            for i, p in enumerate(opcua_packets()):
                p = struct.pack('<I', 2) + p[14:]                                      # AF_INET, not Ethernet
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)
        records = shark_analyzer.run_tshark(path)
        self.assertEqual(sum(r['event_type'] == 'opcua_action' for r in records), 2)


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestGOOSE(unittest.TestCase):
    """tests/protocol_fixtures.write_goose_pcap: one record per state
    change, repeats counted, with what Suricata 8.0.7 logged for the
    capture (tests/data/goose_fixture.eve.json) - only 'Ethertype unknown'
    decoder alerts, since it doesn't decode GOOSE."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_goose_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'goose.pcap')
        write_goose_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.states = [r['goose'] for r in cls.records if r['event_type'] == 'goose']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_one_record_per_state_change(self):
        self.assertEqual([(s['stnum'], s['repeats'], s['values']) for s in self.states],
                         [(1, 2, [False, '40', 7]), (2, 0, [True, '40', 7]), (10, 0, [True, '40', 7]),
                          (1, 0, [False, '40', 7])])
        self.assertEqual((self.states[0]['gocb_ref'], self.states[0]['dataset'], self.states[0]['go_id']),
                         ('IED1LD0/LLN0$GO$gcb1', 'IED1LD0/LLN0$Trips', 'Trips'))
        self.assertEqual(self.states[1]['changed'], [0], 'the trip value turned true')

    def test_a_jump_or_reset_in_stnum_is_marked(self):
        self.assertNotIn('anomaly', self.states[1])
        self.assertEqual((self.states[2]['stnum_gap'], self.states[2]['anomaly']), (7, 'stNum skipped 7'))
        self.assertEqual((self.states[3]['stnum_reset_from'], self.states[3]['anomaly']), (10, 'stNum reset from 10'))

    def test_the_merge_adds_the_records(self):
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'goose_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'goose.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('goose'), 4)
        self.assertNotIn('conn_goose', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestNeighbors(unittest.TestCase):
    """tests/protocol_fixtures.write_neighbor_pcap: LLDP and CDP
    announcements, one record per sending MAC, device and port - with
    what Suricata 8.0.7 logged for the capture
    (tests/data/neighbor_fixture.eve.json): only 'Ethertype unknown'
    decoder alerts, since it doesn't decode either."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_neighbor_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'neighbor.pcap')
        write_neighbor_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.lldp = {r['src_ip']: r['lldp'] for r in cls.records if r['event_type'] == 'lldp'}
        cls.cdp = [r['cdp'] for r in cls.records if r['event_type'] == 'cdp']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_an_lldp_switch_says_what_it_is(self):
        from tests.protocol_fixtures import NEIGHBOR_SWITCH
        switch = self.lldp[NEIGHBOR_SWITCH]
        self.assertEqual((switch['count'], switch['chassis_id'], switch['port_id'], switch['system_name']),
                         (2, NEIGHBOR_SWITCH, 'Gi1/0/1', 'sw1.example'), 'the repeated announcement counted')
        self.assertEqual(switch['system_description'], 'Fixture Switch OS 1.0\nBuilt 2026-01-01')
        self.assertEqual((switch['capabilities'], switch['management_addresses'], switch['vlan']),
                         (['bridge', 'router'], ['10.1.0.1'], 10))

    def test_a_local_chassis_id_is_text_and_lldp_med_inventory_is_kept(self):
        from tests.protocol_fixtures import NEIGHBOR_PLC
        plc = self.lldp[NEIGHBOR_PLC]
        self.assertEqual((plc['chassis_id'], plc['port_id']), ('plc-1 line 2', 'port-001'))
        self.assertEqual((plc['manufacturer'], plc['model'], plc['serial_number'], plc['hardware_revision'],
                          plc['firmware_revision']), ('Fixture Automation', 'PLC-100', 'SN-0042', 'HW 3', 'FW 2.1'))
        self.assertEqual((plc['ttl'], plc['shutdowns']), (0, 1), 'its port shut down')

    def test_cdp(self):
        self.assertEqual(len(self.cdp), 1)
        sw = self.cdp[0]
        self.assertEqual((sw['device_id'], sw['port_id'], sw['platform'], sw['software_version'], sw['capabilities']),
                         ('sw1', 'GigabitEthernet1/0/1', 'cisco WS-C2960-24TT', 'Fixture IOS 15.2', ['switch', 'IGMP']))
        self.assertEqual((sw['addresses'], sw['native_vlan'], sw['vtp_domain'], sw['duplex']),
                         (['10.1.0.1'], 10, 'PLANT', 'full'))

    def test_the_merge_adds_the_records(self):
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'neighbor_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'neighbor.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual((counts.get('lldp'), counts.get('cdp')), (2, 1))
        self.assertNotIn('conn_lldp', counts, 'records, not a connection card')
        self.assertNotIn('conn_cdp', counts)


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestBrowser(unittest.TestCase):
    """tests/protocol_fixtures.write_browser_pcap: Windows Browser messages,
    one record per host, name and kind of message - with what Suricata
    8.0.7 logged for the capture (tests/data/browser_fixture.eve.json):
    flows it gives no protocol, since it doesn't parse NetBIOS datagrams."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_browser_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'browser.pcap')
        write_browser_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.messages = {(b['source_name'], b['message']): b for b in
                        (r['browser'] for r in cls.records if r['event_type'] == 'browser')}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_one_record_per_host_and_message(self):
        self.assertEqual(sorted(self.messages), [('DC1', 'Local Master Announcement'), ('WS1', 'Browser Election Request'),
                                                 ('WS1', 'Host Announcement'), ('WS1', 'Request Announcement')])
        self.assertEqual(self.messages[('WS1', 'Host Announcement')]['count'], 2, 'the repeated announcement counted')

    def test_announcements_say_what_the_host_is(self):
        workstation = self.messages[('WS1', 'Host Announcement')]
        self.assertEqual((workstation['destination_name'], workstation['os_version'], workstation['roles'],
                          workstation['comment']),
                         ('FIXTUREDOM', '10.0', ['workstation', 'server', 'NT workstation'], 'Accounting PC'))
        self.assertIn('domain controller', self.messages[('DC1', 'Local Master Announcement')]['roles'])
        self.assertIn('master browser', self.messages[('DC1', 'Local Master Announcement')]['roles'])

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('browser_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (2, 2, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'browser_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'browser.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('browser'), 4)
        self.assertNotIn('conn_nbdgm', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestOnePassOrTwo(unittest.TestCase):
    """A capture mostly of protocols with records here gets one pass
    asking for every field (_mostly_recorded, _combined_fields); any other,
    a first pass for flows and a protocol pass over just the packets that
    need it. The records are the same either way."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import (write_bacnet_pcap, write_browser_pcap, write_extra_pcap,
                                             write_iec104_pcap, write_protocol_pcap, write_telnet_pcap)
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcaps = {}
        for name, write in (('iec104', write_iec104_pcap), ('bacnet', write_bacnet_pcap), ('telnet', write_telnet_pcap),
                            ('extra', write_extra_pcap), ('browser', write_browser_pcap), ('protocols', write_protocol_pcap)):
            cls.pcaps[name] = os.path.join(cls.tmpdir, name + '.pcap')
            write(cls.pcaps[name])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    @staticmethod
    def _records(pcap, combined):
        with mock.patch.object(shark_analyzer, '_mostly_recorded', return_value=combined):
            return sorted(json.dumps(r, sort_keys=True) for r in shark_analyzer.run_tshark(pcap))

    def test_the_same_records_either_way(self):
        for name, pcap in self.pcaps.items():
            with self.subTest(capture=name):
                two = self._records(pcap, False)
                self.assertEqual(self._records(pcap, True), two)
                self.assertTrue(any('"event_type": "flow"' not in r for r in two) or name == 'protocols')

    def test_the_probe_tells_one_protocols_capture_from_a_mixed_one(self):
        with mock.patch.object(shark_analyzer, '_PROBE_MIN_PACKETS', 1):
            self.assertTrue(shark_analyzer._mostly_recorded(self.pcaps['iec104']))
            self.assertFalse(shark_analyzer._mostly_recorded(self.pcaps['protocols']), 'DNS, HTTP, TLS, Modbus, FTP')

    def test_a_small_capture_is_never_probed(self):
        with mock.patch.object(shark_analyzer.pcap_subset, 'copy_frames', side_effect=AssertionError('probed')):
            self.assertFalse(shark_analyzer._mostly_recorded(self.pcaps['iec104']))


class _NbnsFromJson:
    """A structured protocol for testing the structured pass on its own:
    NBNS names, read from each packet's JSON tree."""
    app_protos = ('nbns',)
    tshark_protocols = ('nbns',)
    layers = ('nbns',)
    display_filter = 'nbns'

    def __init__(self):
        self.seen = []

    def feed_json(self, pkt, layers):
        from shark_protocols import _flatten, _pdus
        for pdu in _pdus(layers.get('nbns')):
            self.seen.append((pkt.flow.cport, _flatten(pdu).get('nbns.name', [''])[0]))

    def finish(self):
        return []


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestStructuredPass(unittest.TestCase):
    """shark_analyzer._structured_pass: a second tshark run writing JSON
    trees, over just the flows of the protocols that need it."""

    def test_reads_only_the_flows_that_need_it_from_a_copy_of_their_packets(self):
        from tests.protocol_fixtures import extra_packets, dns_packets
        from tests.pcap_fixtures import write_pcap
        with tempfile.TemporaryDirectory() as tmp:
            pcap = os.path.join(tmp, 'padded.pcap')
            write_pcap(pcap, dns_packets() * 40 + extra_packets())     # mostly DNS, then the NBNS
            proto = _NbnsFromJson()
            calls = []
            real_copy = shark_analyzer.pcap_subset.copy_frames

            def spy(src, dst, ranges):
                calls.append(ranges)
                return real_copy(src, dst, ranges)
            # (no field protocols, so the protocol pass cuts no copy of its own)
            with mock.patch.object(shark_analyzer, 'STRUCTURED_PROTOCOLS', (lambda: proto,)), \
                    mock.patch.object(shark_analyzer, 'PROTOCOLS', ()), \
                    mock.patch.object(shark_analyzer.pcap_subset, 'copy_frames', side_effect=spy):
                shark_analyzer.run_tshark(pcap)
        [ranges] = calls
        self.assertLess(len(ranges), 5, 'a few frame ranges, not the whole capture')
        self.assertEqual(sorted({(port, name.split('<')[0]) for port, name in proto.seen}),
                         [(137, 'DESKTOP-TEST01'), (137, 'FILESERVER')], 'each packet matched to its first-pass flow')

    def test_no_flows_that_need_it_no_second_pass(self):
        from tests.protocol_fixtures import write_protocol_pcap
        with tempfile.TemporaryDirectory() as tmp:
            pcap = os.path.join(tmp, 'protocols.pcap')
            write_protocol_pcap(pcap)
            with mock.patch.object(shark_analyzer, 'STRUCTURED_PROTOCOLS', (_NbnsFromJson,)), \
                    mock.patch.object(shark_analyzer, '_structured_command', side_effect=AssertionError('ran')):
                shark_analyzer.run_tshark(pcap)

    def test_frame_ranges(self):
        flows = [mock.Mock(first_frame=a, last_frame=b) for a, b in ((10, 20), (15, 30), (40, 41), (100, 200), (0, 0))]
        self.assertEqual(shark_analyzer._frame_ranges(flows), [(10, 30), (40, 41), (100, 200)])
        self.assertEqual(shark_analyzer._merge_ranges([(10, 30), (40, 41), (100, 200)], max_ranges=2),
                         [(10, 41), (100, 200)], 'closing the smallest gap')

    def test_json_packets_one_at_a_time(self):
        lines = ['[\n', '  {\n', '    "_source": {"layers": {"nbns": {"nbns.id": "5"}}}\n', '  },\n',
                 '  {\n', '    "_source": {"layers": {"nbns": {"nbns.id": "6"}}}\n', '  }\n', ']\n']
        self.assertEqual([p['nbns']['nbns.id'] for p in shark_analyzer._json_packets(lines)], ['5', '6'])

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
            out = [''] * len(shark_analyzer._FIRST_PASS_FIELDS)
            for name, value in values.items():
                out[shark_analyzer._COLUMN[name.replace('__', '.')]] = value
            return out
        cases = [({'dns__flags__response': 'True'}, True), ({'dns__flags__response': 'False'}, False),
                 ({'nbns__flags__response': '1'}, True), ({'http__response__code': '200'}, True),
                 ({'http__request__method': 'GET'}, False), ({'ftp__response__code': '220'}, True),
                 ({'ftp__request__command': 'USER'}, False), ({'s7comm__header__rosctr': '3'}, True),
                 ({'s7comm__header__rosctr': '1'}, False), ({'s7comm__header__rosctr': '7'}, None),
                 ({'tls__handshake__type': '2'}, True), ({'tls__handshake__type': '1\x1f16'}, False),   # the first of a packet's handshakes
                 ({'tls__handshake__type': '11'}, None), ({'ip__src': '10.0.0.1'}, None), ({}, None)]
        for values, expected in cases:
            with self.subTest(values=values):
                self.assertIs(shark_analyzer._is_reply(cols(**values)), expected)

    def test_group_addresses(self):
        self.assertEqual([shark_analyzer._is_group_address(a) for a in
                          ('224.0.0.251', '239.255.255.250', '255.255.255.255', '10.1.0.255', 'ff02::fb', '10.1.0.10', '2001:db8::1', 'aa:bb:cc:dd:ee:ff')],
                         [True, True, True, True, True, False, False, False])


class TestProtocolDetails(unittest.TestCase):
    def test_each_field_is_asked_of_tshark_once(self):
        """REGRESSION: tshark fills only one column of a field asked for
        twice - SSDP reads http.* fields that flow orientation reads too."""
        from shark_protocols import PROTOCOLS, SSDP
        for fields in (shark_analyzer._FIRST_PASS_FIELDS, shark_analyzer._protocol_pass_fields(PROTOCOLS)):
            self.assertEqual(len(fields), len(set(fields)))
        self.assertTrue(set(SSDP.fields) & set(shark_analyzer._ORIENTATION_FIELDS), 'the case this guards')


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
        analysis built before a tshark change never got it - its
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

    def test_background_limit_is_a_packet_count(self):
        """tshark's memory follows packets, not bytes: the limit counts them."""
        self.assertEqual(shark_analyzer.packet_count(self.pcap), 52)
        self.assertTrue(shark_analyzer.background_eligible(self.pcap))
        with mock.patch.object(config, 'SHARK_BACKGROUND_MAX_PACKETS', 51):
            self.assertFalse(shark_analyzer.background_eligible(self.pcap))
            self.assertEqual(shark_analyzer.status(self.dir, self.pcap), {'status': 'too_large'})
        with mock.patch.object(config, 'SHARK_BACKGROUND_MAX_BYTES', 10):
            self.assertTrue(shark_analyzer.background_eligible(self.pcap), 'the file size no longer decides')
        self.assertFalse(shark_analyzer.background_eligible(os.path.join(self.dir, 'missing.pcap')))

    def test_without_capinfos_the_size_decides(self):
        real_which = shutil.which
        with mock.patch.object(shark_analyzer.shutil, 'which', side_effect=lambda n: None if n == 'capinfos' else real_which(n)):
            shark_analyzer._PACKET_COUNTS.clear()
            self.assertIsNone(shark_analyzer.packet_count(self.pcap))
            with mock.patch.object(config, 'SHARK_BACKGROUND_MAX_BYTES', 10):
                self.assertFalse(shark_analyzer.background_eligible(self.pcap))
        shark_analyzer._PACKET_COUNTS.clear()


def _row(event_type, cid='1:a', when='2026-01-01T00:00:10.000000+0000', app=None, end=None):
    e = {'event_type': event_type, 'community_id': cid, 'timestamp': when}
    if event_type == 'flow':
        e.update(app_proto=app or '', flow={'start': when, 'end': end or when})
    else:
        e[event_type] = {}
    return json.dumps(e)


class TestMergeRows(unittest.TestCase):
    """Which of a shark.db's rows join Suricata's in events.db."""
    SURICATA = {'1:http': [(1767225600.0, 1767225620.0)]}     # a flow Suricata called HTTP, 00:00:00-00:00:20

    def _kept(self, rows):
        return [(e['event_type'], e.get('app_proto')) for e in shark_analyzer.merge_rows(rows, self.SURICATA)]

    def test_records_of_protocols_suricata_lacks_and_none_of_its_own(self):
        self.assertEqual(self._kept([_row('s7comm'), _row('nbns'), _row('llmnr'), _row('ssdp'),
                                     _row('dns'), _row('http'), _row('smb'), _row('ftp_data'), _row('mdns')]),
                         [('s7comm', None), ('nbns', None), ('llmnr', None), ('ssdp', None)])

    def test_flows_become_connection_rows_only_for_protocols_with_nothing_else(self):
        self.assertEqual(self._kept([_row('flow', app='openvpn'), _row('flow', app='syslog'),
                                     _row('flow', app='telnet'), _row('flow', app='http'), _row('flow', app='arp'),
                                     _row('flow', app='s7comm'), _row('flow', app='')]),
                         [('conn_openvpn', 'openvpn'), ('conn_syslog', 'syslog')],
                         "telnet, http and arp are Suricata's; s7comm has records; '' is no protocol")

    def test_nothing_on_a_flow_suricata_gave_a_protocol(self):
        """The 4SICS case: a scanner's HTTP request to the rsh port is HTTP
        to Suricata and rsh to tshark - Suricata's word stands."""
        self.assertEqual(self._kept([_row('flow', cid='1:http', app='rsh'), _row('nbns', cid='1:http'),
                                     _row('flow', cid='1:http', app='rsh', when='2026-01-01T01:00:00.000000+0000'),
                                     _row('flow', cid='1:other', app='rsh')]),
                         [('conn_rsh', 'rsh'), ('conn_rsh', 'rsh')],
                         'the same Community ID an hour later is another connection; another ID is too')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestMerge(unittest.TestCase):
    """shark_analyzer.merge: tshark's rows into the analysis's events.db,
    built here from Suricata's output for the extra fixture capture."""

    def setUp(self):
        from tests.protocol_fixtures import write_extra_pcap
        self.dir = tempfile.mkdtemp()
        self.pcap = os.path.join(self.dir, 'extra.pcap')
        write_extra_pcap(self.pcap)
        self.events_db = os.path.join(self.dir, 'events.db')
        db.create_sqlite_db(self.events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                         'extra_fixture.eve.json'))
        self.suricata_counts = db.get_event_types_sqlite(self.events_db)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _added(self):
        after = db.get_event_types_sqlite(self.events_db)
        return {t: n - self.suricata_counts.get(t, 0) for t, n in after.items() if n != self.suricata_counts.get(t, 0)}

    def test_adds_what_suricata_lacks_once_both_are_done(self):
        self.assertIsNone(shark_analyzer.merge(self.dir), 'no shark.db yet')
        self.assertTrue(shark_analyzer.build(self.dir, self.pcap))
        with open(os.path.join(self.dir, '.phase'), 'w') as f:
            f.write('importing')
        self.assertIsNone(shark_analyzer.merge(self.dir), "Suricata isn't done")
        os.unlink(os.path.join(self.dir, '.phase'))
        self.assertEqual(shark_analyzer.merge(self.dir), 10)
        self.assertEqual(self._added(), {'s7comm': 4, 'ssdp': 3, 'nbns': 2, 'llmnr': 1},
                         "tshark's DNS, mDNS, HTTP and FTP records stay out - Suricata has those")
        self.assertTrue(shark_analyzer.merged(self.dir))
        self.assertEqual(db.tshark_types(self.events_db), ['llmnr', 'nbns', 's7comm', 'ssdp'], 'the cards marked as tshark\'s')
        self.assertIsNone(shark_analyzer.merge(self.dir), 'the same shark.db is merged once')

    def test_a_new_shark_db_replaces_the_rows_of_the_last(self):
        self.assertTrue(shark_analyzer.build(self.dir, self.pcap))
        shark_analyzer.merge(self.dir)
        time.sleep(0.01)
        self.assertTrue(shark_analyzer.build(self.dir, self.pcap))     # a retried run
        self.assertFalse(shark_analyzer.merged(self.dir))
        self.assertEqual(shark_analyzer.merge(self.dir), 10)
        self.assertEqual(self._added(), {'s7comm': 4, 'ssdp': 3, 'nbns': 2, 'llmnr': 1}, 'replaced, not added twice')
        self.assertEqual(db.get_event_types_sqlite(self.events_db, 'FILESERVER').get('nbns'), 1,
                         'search finds them (the full-text index was updated both times)')

    def test_the_queue_merges_when_its_run_finishes(self):
        shark_analyzer.enqueue(self.dir, self.pcap)
        self.assertTrue(shark_analyzer.wait_idle(30))
        self.assertTrue(shark_analyzer.merged(self.dir))
        self.assertEqual(self._added().get('s7comm'), 4)

    def test_a_bare_suricata_label_doesnt_keep_tshark_out(self):
        """Suricata 8.0.6 labelled the fixture's SSDP NOTIFY flow 'sip' but
        logged no SIP: the label alone doesn't make it Suricata's flow."""
        flows = [json.loads(line) for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                                'extra_fixture.eve.json')) if '"app_proto":"sip"' in line]
        self.assertEqual(len(flows), 1)
        self.assertNotIn(flows[0]['community_id'], db.suricata_identified_flows(self.events_db))

    def test_connection_rows_have_their_own_tab_but_stay_out_of_all_events(self):
        from tests.pcap_fixtures import write_pcap
        from tests.protocol_fixtures import _udp_packet
        syslog = os.path.join(self.dir, 'syslog.pcap')
        write_pcap(syslog, [_udp_packet('10.1.0.10', '10.1.0.99', 40514, 514, b'<34>Oct 11 22:14:15 host su: test')])
        os.replace(syslog, self.pcap)
        self.assertTrue(shark_analyzer.build(self.dir, self.pcap))
        shark_analyzer.merge(self.dir)
        self.assertEqual(self._added(), {'conn_syslog': 1})
        self.assertEqual([e['event_type'] for e in db.query_events_sqlite(self.events_db, 'conn_syslog')], ['conn_syslog'])
        self.assertNotIn('conn_syslog', {e['event_type'] for e in db.query_events_sqlite(self.events_db, limit=100000)},
                         "it's a connection Suricata's own flow row already lists")


class TestSettingsSwitch(unittest.TestCase):
    def test_on_unless_turned_off_and_survives_a_bad_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(shark_analyzer.enabled(d))
            shark_analyzer.set_enabled(d, False)
            self.assertFalse(shark_analyzer.enabled(d))
            shark_analyzer.set_enabled(d, True)
            self.assertTrue(shark_analyzer.enabled(d))
            with open(os.path.join(d, shark_analyzer.SHARK_SETTINGS), 'w') as f:
                f.write('not json')
            self.assertTrue(shark_analyzer.enabled(d), 'an unreadable setting leaves it on')

    def test_suricatas_completion_queues_shar_crates_only_when_on(self):
        import inspect
        import suricata_analyzer
        src = inspect.getsource(suricata_analyzer.spawn_suricata)
        self.assertIn('shark_analyzer.enabled(data_dir) and shark_analyzer.background_eligible(pcap_path)', src)


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
        # the build's start, tshark's deadline, then the build's end
        with mock.patch.object(shark_analyzer.time, 'monotonic', side_effect=[100.0, 100.0] + [117.4] * 50):
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

    def test_a_build_that_passes_the_memory_limit_is_stopped(self):
        """The limit covers the build and everything in its process group
        (tshark): here a child of the build is the one that grows."""
        grow = [sys.executable, '-c', 'import subprocess, sys; subprocess.run([sys.executable, "-c", '
                '"import time; x = bytearray(300 * 1024 * 1024); time.sleep(30)"])']
        with mock.patch.object(shark_analyzer, '_child_command', return_value=grow), \
                mock.patch.object(config, 'SHARK_MAX_MEMORY_BYTES', 100 * 1024 * 1024), \
                mock.patch.object(config, 'SHARK_MEMORY_CHECK_SECONDS', 0.05):
            start = time.monotonic()
            shark_analyzer.analyze(self.dirs[0], self.pcaps[0])
        self.assertLess(time.monotonic() - start, 15, 'stopped, not left to sleep')
        status = shark_analyzer.status(self.dirs[0])
        self.assertEqual(status['status'], 'error')
        self.assertIn('more than 0.0976562 GB of memory', status['message'])

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
        self.fail('tshark never finished')

    def test_first_status_request_queues_it_and_it_becomes_ready_and_merged(self):
        status, body = self._get(f'/api/shark-status?md5={self.md5}')
        self.assertEqual(status, 200)
        self.assertIn(body['status'], ('queued', 'running', 'ready'))
        body = self._wait_ready()
        self.assertIsInstance(body.pop('seconds'), int)
        self.assertEqual(body, {'status': 'ready', 'merged': True, 'types': []},
                         'types: what it added - nothing, so the page has nothing to reload')
        _, stats = self._get(f'/api/stats?md5={self.md5}')
        self.assertEqual(stats['tshark_types'], [], 'nothing here Suricata lacks - but the stats say so')

    def test_waits_for_suricata(self):
        with open(os.path.join(self.dir, '.phase'), 'w') as f:
            f.write('network')
        _, body = self._get(f'/api/shark-status?md5={self.md5}')
        self.assertEqual(body, {'status': 'waiting'})

    def test_too_large_waits_to_be_asked_then_shark_start_runs_it(self):
        with mock.patch.object(config, 'SHARK_BACKGROUND_MAX_PACKETS', 1):
            _, body = self._get(f'/api/shark-status?md5={self.md5}')
            self.assertEqual(body, {'status': 'too_large'})
            status, body = self._post('/api/shark-start', {'md5': self.md5})
            self.assertEqual(status, 200)
            self.assertIn(body['status'], ('queued', 'running', 'ready'))
            self.assertEqual(self._wait_ready()['status'], 'ready')

    def test_the_settings_switch_turns_shar_crates_off_and_on(self):
        self.assertEqual(self._get('/api/shark-settings')[1], {'enabled': True}, 'on by default')
        try:
            self.assertEqual(self._post('/api/shark-settings', {'enabled': False}), (200, {'enabled': False}))
            self.assertEqual(self._get('/api/shark-settings')[1], {'enabled': False})
            self.assertEqual(self._get(f'/api/shark-status?md5={self.md5}')[1], {'status': 'disabled'})
            self.assertEqual(self._post('/api/shark-start', {'md5': self.md5})[1], {'status': 'disabled'},
                             'nothing runs while it is off, even on request')
            self.assertEqual(self._post('/api/shark-settings', {'enabled': 'no'})[0], 400)
        finally:
            self._post('/api/shark-settings', {'enabled': True})
        self.assertEqual(self._wait_ready()['status'], 'ready', 'back on: the analysis gets its run')

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
