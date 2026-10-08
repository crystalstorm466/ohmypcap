#!/usr/bin/env python3
"""SHAR-CRATES: a tshark view of a PCAP, alongside Suricata's (SURI-CRATES).

Suricata stays the default analysis of every PCAP. Once it finishes, the
same capture is queued here for tshark, which decodes far more protocols
than Suricata - but packet by packet, the way Wireshark shows them. This
module turns that packet stream into Suricata-shaped records, written to
shark.db beside the analysis's events.db with the same schema, so the
existing query functions and UI can read either one.

So far it builds one 'flow' record per conversation (tshark's tcp.stream /
udp.stream numbers, or addresses for anything without a stream), in
Suricata's own flow-event layout - addresses, ports, packet and byte
counts per direction, start and end - plus the protocols tshark found in
it and its Community ID, which matches Suricata's community_id for the
same flow and links the two views.

tshark runs once per capture with plain field output (-T fields): its
JSON output is several times slower and many times larger for the same
packets (measured: 532 MB pcap, 10.6s and 81 MB of fields vs 168s and
8.5 GB of full JSON). It runs at low CPU and I/O priority, one capture
at a time, under a timeout. tshark's memory grows with the capture's
packet count (about 1.5 KB per packet measured), so captures over
config.SHARK_BACKGROUND_MAX_BYTES only run when the user asks.

Files in the analysis directory:
    shark.db       the records, written to shark.db.tmp then renamed, so
                   a reader never sees a half-built database
    .shark_error   why the last run failed
"""

import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone

import config
from db import create_shark_db

SHARK_DB = 'shark.db'
SHARK_ERROR = '.shark_error'
SHARK_ARTIFACTS = (SHARK_DB, SHARK_DB + '-wal', SHARK_DB + '-shm', SHARK_DB + '.tmp', SHARK_ERROR)

# One tshark field per column of its tab-separated output, in this order.
# occurrence=l takes the last value of a repeated field, so a tunneled
# packet (IP in GRE/VXLAN, etc.) reports its inner addresses and ports -
# the flow Suricata also reports.
_FIELDS = (
    'frame.time_epoch', 'frame.len', 'frame.protocols',
    'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'ip.proto', 'ipv6.nxt',
    'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport',
    'tcp.stream', 'udp.stream', 'tcp.flags.syn', 'tcp.flags.ack',
    'eth.src', 'eth.dst', 'communityid',
)
(_F_TIME, _F_LEN, _F_PROTOS, _F_IP_SRC, _F_IP_DST, _F_IP6_SRC, _F_IP6_DST, _F_IP_PROTO,
 _F_IP6_NXT, _F_TCP_SPORT, _F_TCP_DPORT, _F_UDP_SPORT, _F_UDP_DPORT, _F_TCP_STREAM,
 _F_UDP_STREAM, _F_SYN, _F_ACK, _F_ETH_SRC, _F_ETH_DST, _F_CID) = range(len(_FIELDS))

# IP protocol numbers Suricata names in a flow's proto field.
_IP_PROTO_NAMES = {'1': 'ICMP', '2': 'IGMP', '6': 'TCP', '17': 'UDP', '47': 'GRE',
                   '50': 'ESP', '58': 'IPv6-ICMP', '89': 'OSPF', '112': 'VRRP', '132': 'SCTP'}

_TRANSPORT_LAYERS = {'tcp', 'udp', 'sctp'}
# Layers that only carry another protocol, or carry undecoded payload -
# never a flow's application protocol. tpkt/cotp carry S7comm and MMS,
# nbss carries SMB, and the rest are tshark's names for raw data or
# reassembly bookkeeping.
_CARRIER_LAYERS = {'tpkt', 'cotp', 'nbss', 'tcp.segments', 'data', 'data-text-lines', 'media'}


def shark_db_path(dir_path):
    return os.path.join(dir_path, SHARK_DB)


def tshark_command(pcap_path):
    """The tshark command that dumps _FIELDS for every packet."""
    cmd = ['tshark', '-n', '-r', pcap_path, '--enable-protocol', 'communityid',
           '-T', 'fields', '-E', 'separator=\t', '-E', 'occurrence=l']
    for field in _FIELDS:
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
    for layer in above:
        if layer not in _CARRIER_LAYERS:
            return layer
    return ''


def _iso(epoch):
    """Suricata's timestamp format, so both views sort and compare alike."""
    when = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return when.strftime('%Y-%m-%dT%H:%M:%S.%f+0000')


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class _Flow:
    __slots__ = ('key', 'proto', 'ip_v', 'client', 'server', 'cport', 'sport', 'first', 'last',
                 'pkts_ts', 'pkts_tc', 'bytes_ts', 'bytes_tc', 'protocols', 'app_proto', 'community_id',
                 'stream', 'client_set_by_syn')

    def __init__(self, key, proto, ip_v, src, dst, sport, dport, when, stream):
        self.key, self.proto, self.ip_v, self.stream = key, proto, ip_v, stream
        self.client, self.server, self.cport, self.sport = src, dst, sport, dport
        self.first = self.last = when
        self.pkts_ts = self.pkts_tc = self.bytes_ts = self.bytes_tc = 0
        self.protocols = {}
        self.app_proto = ''
        self.community_id = ''
        self.client_set_by_syn = False

    def add(self, src, sport, length, when, app, community_id, syn_only):
        # The client is whoever sent the SYN; failing that (a capture that
        # starts mid-connection, or UDP), whoever sent the first packet.
        if syn_only and not self.client_set_by_syn:
            if src != self.client or sport != self.cport:
                self.client, self.server = self.server, self.client
                self.cport, self.sport = self.sport, self.cport
                self.pkts_ts, self.pkts_tc = self.pkts_tc, self.pkts_ts
                self.bytes_ts, self.bytes_tc = self.bytes_tc, self.bytes_ts
            self.client_set_by_syn = True
        if src == self.client and sport == self.cport:
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


def build_flows(lines):
    """Group tshark's per-packet field lines (tshark_command's output)
    into flow events, in order of each flow's first packet."""
    flows = {}
    for line in lines:
        f = line.rstrip('\n').split('\t')
        if len(f) < len(_FIELDS):
            continue
        try:
            when = float(f[_F_TIME])
        except ValueError:
            continue
        length = _int(f[_F_LEN])
        app = app_protocol(f[_F_PROTOS])
        if f[_F_IP_SRC] or f[_F_IP6_SRC]:
            ip_v = 4 if f[_F_IP_SRC] else 6
            src, dst = (f[_F_IP_SRC], f[_F_IP_DST]) if ip_v == 4 else (f[_F_IP6_SRC], f[_F_IP6_DST])
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
        flow.add(src, sport, length, when, app, f[_F_CID], syn_only)
    return [flow.event() for flow in sorted(flows.values(), key=lambda fl: fl.first)]


def _low_priority():
    """preexec_fn for tshark: lowest CPU priority, so a background run
    yields to Suricata and to the user's own work."""
    try:
        os.nice(19)
    except OSError:
        pass


def run_tshark(pcap_path, timeout=None, on_start=None):
    """Run tshark over pcap_path and return its flow events. Raises
    RuntimeError if tshark is missing, fails, is killed, or exceeds the
    timeout. on_start, if given, is called with the tshark process as soon
    as it starts (so the queue can kill it on cancel)."""
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
            events = build_flows(proc.stdout)
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


def analyze(dir_path, pcap_path, on_start=None):
    """Build dir_path's shark.db from pcap_path. On failure, writes the
    reason to .shark_error instead - unless the run was cancelled, whose
    directory is being cleared or removed."""
    db_path = shark_db_path(dir_path)
    tmp_path = db_path + '.tmp'
    _remove(os.path.join(dir_path, SHARK_ERROR))
    try:
        events = run_tshark(pcap_path, on_start=on_start)
        _remove(tmp_path)
        create_shark_db(tmp_path, events)
        os.replace(tmp_path, db_path)
    except Exception as e:
        _remove(tmp_path)
        if _was_cancelled(dir_path):
            return
        try:
            with open(os.path.join(dir_path, SHARK_ERROR), 'w') as f:
                f.write(str(e)[:500])
        except OSError:
            pass


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
        if _running in _cancelled:   # cancelled before tshark had started
            proc.kill()


def _work():
    global _running, _running_proc, _worker
    while True:
        with _lock:
            if not _queue:
                _running = _worker = None
                return
            dir_path = _queue.popleft()
            pcap_path = _pending.pop(dir_path)
            _running = dir_path
        if os.path.isfile(pcap_path):
            analyze(dir_path, pcap_path, on_start=_set_running_proc)
        with _lock:
            _running = _running_proc = None
            _cancelled.discard(dir_path)


def enqueue(dir_path, pcap_path):
    """Queue a SHAR-CRATES run for this analysis, unless one is already
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
    """Stop this analysis's SHAR-CRATES run (reanalyze/delete): drop it
    from the queue, or kill its tshark if it's running."""
    with _lock:
        if dir_path in _pending:
            del _pending[dir_path]
            _queue.remove(dir_path)
        elif dir_path == _running:
            _cancelled.add(dir_path)
            if _running_proc is not None:
                try:
                    _running_proc.kill()
                except OSError:
                    pass


def background_eligible(pcap_path):
    """Whether a capture is small enough to analyze without being asked."""
    try:
        return os.path.getsize(pcap_path) <= config.SHARK_BACKGROUND_MAX_BYTES
    except OSError:
        return False


def status(dir_path, pcap_path=None):
    """This analysis's SHAR-CRATES state: 'ready', 'queued', 'running',
    'error' (with 'message'), 'too_large' (over the background limit,
    not yet asked for) or 'not_started'."""
    if os.path.exists(shark_db_path(dir_path)):
        return {'status': 'ready'}
    with _lock:
        if dir_path == _running:
            return {'status': 'running'}
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
