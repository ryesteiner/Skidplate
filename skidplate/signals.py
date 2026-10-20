"""Bounded audit-only triage signals. No collection, commands or network I/O."""
from collections import OrderedDict, deque
from dataclasses import dataclass
import ipaddress
import statistics

SCANNERS = frozenset({'nmap', 'masscan', 'zmap'})
PRIVILEGE_TOOLS = frozenset({'/usr/bin/sudo', '/usr/bin/su', '/usr/bin/pkexec'})
REMOTE_TOOLS = frozenset({'sshd', 'sshd-session', 'dropbear', 'x11vnc', 'x0vncserver',
                          'Xvnc', 'tigervncserver', 'wayvnc', 'rustdesk', 'anydesk'})
SSH_EXECUTABLES = frozenset({'/usr/bin/sshd', '/usr/lib/ssh/sshd-session', '/usr/bin/dropbear'})
RISKY = ('/tmp/', '/var/tmp/', '/dev/shm/', '/home/', '/run/user/', '/memfd:', 'memfd:')
# Linux UAPI ABI numbers; only the effective-UID argument is decoded, never argv.
UID_CALLS = {'c000003e': {'105': ('setuid', 'a0'), '113': ('setreuid', 'a1'), '117': ('setresuid', 'a1')},
             '40000003': {'23': ('setuid', 'a0'), '213': ('setuid32', 'a0'),
                          '70': ('setreuid', 'a1'), '203': ('setreuid32', 'a1'),
                          '164': ('setresuid', 'a1'), '208': ('setresuid32', 'a1')},
             'c00000b7': {'146': ('setuid', 'a0'), '145': ('setreuid', 'a1'), '147': ('setresuid', 'a1')}}
RULES = {
    'sudo-authentication': 'Captured sudo/su/pkexec authentication or account-check result',
    'sudo-authorization': 'Captured sudo command authorization result; command contents excluded',
    'privilege-root-request': 'Captured request for effective UID zero; legitimate administration can match',
    'behavior-root-transition': 'Observed non-root execution followed by root execution with the same host/login/session/PID',
    'behavior-persistence-network': 'Persistence-location activity followed by a public-IP connect by the same observed process',
    'enumeration-tool': 'Successful execution with a known scanner basename; intent unverified',
    'network-port-sweep': '20 destination ports on one address in 60 seconds by the same observed process',
    'network-host-sweep': '30 addresses on one port in 60 seconds, with scanner name or mostly failed attempts',
    'network-periodic': '12 regularly spaced public-IP connect attempts; weak heuristic, not C2 identification',
    'remote-access-tool': 'Successful execution with a remote-access tool basename; authorization unverified',
    'remote-login': 'Captured successful SSH login/session event with a numeric remote address',
}


@dataclass(frozen=True)
class Signal:
    rule: str
    severity: str
    title: str
    detail: str
    first_event: str = ''


def direct(event, execution):
    exe, result = event.get('exe'), event.result.lower()
    success = result in {'yes', 'success', '1'}
    known = success or result in {'no', 'failed', 'failure', '0'}
    name = exe.rsplit('/', 1)[-1]
    identity = f'exe={exe}; login UID={event.get("auid")}; PID={event.get("pid")}; result={result}. '
    found = []
    if exe in PRIVILEGE_TOOLS and known and event.kinds & {'USER_AUTH', 'USER_ACCT'}:
        found.append(Signal('sudo-authentication', 'medium', 'Privilege-tool authentication/account check',
                            identity + 'This is a PAM decision, not proof that a command ran or obtained root.'))
    if exe == '/usr/bin/sudo' and known and 'USER_CMD' in event.kinds:
        found.append(Signal('sudo-authorization', 'medium', 'Sudo command authorization event',
                            identity + 'Authorization outcome only; command arguments are deliberately not retained.'))
    if 'SYSCALL' in event.kinds and event.get('requested_euid') == '0':
        # Root daemons routinely setuid(0); only non-system originating logins qualify.
        auid = event.get('auid')
        if auid.isdecimal() and len(auid) <= 10 and 1000 <= int(auid) < 4294967294 and known:
            found.append(Signal('privilege-root-request', 'high' if success and exe.startswith(RISKY) else 'medium',
                'Effective-root identity request ' + ('succeeded' if success else 'failed'),
                identity + f'operation={event.get("uid_operation")}; requested effective UID=0. '
                'This can be legitimate saved-ID restoration or administration; it does not prove an exploit or a transition from non-root.'))
    if execution and success:
        if exe in PRIVILEGE_TOOLS and 'sentinel_privilege_tool' not in event.get('key').split('\x01'):
            found.append(Signal('privilege-tool', 'medium', 'Privilege administration tool was executed',
                                identity + 'A tool launch alone does not prove authorization, command execution or privilege escalation.'))
        if name in SCANNERS:
            found.append(Signal('enumeration-tool', 'medium', 'Scanner-named executable launched',
                                identity + 'Name alone does not verify product identity, scanning mode or malicious intent.'))
        if name in REMOTE_TOOLS:
            found.append(Signal('remote-access-tool', 'high' if exe.startswith(RISKY) else 'medium',
                'Remote-access-named executable launched', identity + 'Verify expected installation and authorization. '
                'A basename is not verified product identity and does not establish a remote session.'))
    if success and event.kinds & {'USER_LOGIN', 'USER_START'} and exe in SSH_EXECUTABLES:
        try:
            address = ipaddress.ip_address(event.get('addr'))
            if not (address.is_unspecified or address.is_loopback or address.is_multicast):
                found.append(Signal('remote-login', 'high' if event.get('acct') == 'root' else 'medium',
                    'SSH login/session success recorded', identity + f'account={event.get("acct")}; source={address}. '
                    'USER_START may describe a session being opened; check related authentication records.'))
        except ValueError:
            pass
    return found


class Chokepoints:
    """Host/history/login/session/PID/exe gates supplied by the existing correlator.

    256 process buckets x 128 recent attempts, 256 endpoint series x 12 samples,
    512 exec/persistence observations. All are transient and reset with source.
    """
    def __init__(self):
        self.attempts = OrderedDict()
        self.series = OrderedDict()
        self.executions = OrderedDict()
        self.persistence = OrderedDict()

    @staticmethod
    def save(mapping, key, value, cap):
        mapping[key] = value
        mapping.move_to_end(key)
        while len(mapping) > cap:
            mapping.popitem(last=False)

    def reset_host(self, historical, node):
        for mapping in (self.attempts, self.series, self.executions, self.persistence):
            for key in list(mapping):
                if key[:2] == (historical, node):
                    del mapping[key]

    def observe(self, event, identity, execution, destinations, persistence):
        if identity is None:
            return []
        now, event_id, exe = event.timestamp, event.identity, event.get('exe')
        base = identity[:5]
        success = event.result.lower() in {'yes', 'success', '1'}
        context = (f'host={identity[1]}; login UID={identity[2]}; session={identity[3]}; '
                   f'PID={identity[4]}; exe={exe}. ')
        found = []
        if execution and success:
            previous = self.executions.get(base)
            if previous and now <= previous[0]:
                return found
            if previous and 0 < now - previous[0] <= 120 and previous[2] != '0' and event.get('euid') == '0':
                found.append(Signal('behavior-root-transition', 'high' if previous[3].startswith(RISKY) or exe.startswith(RISKY) else 'medium',
                    'Observed execution identity changed to effective root', context +
                    f'Prior execution={previous[1]}; prior effective UID={previous[2]}; prior exe={previous[3]}. '
                    'The same numeric PID/session is not a process-start token; PID reuse and legitimate privilege tools can match.', previous[1]))
            euid = event.get('euid')
            if euid.isdecimal() and len(euid) <= 10 and int(euid) < 4294967294:
                self.save(self.executions, base, (now, event_id, euid, exe), 512)
            else:
                self.executions.pop(base, None)
            # A successful exec invalidates pre-exec network/persistence state,
            # even when the path is unchanged. Never bridge executable images.
            for mapping in (self.attempts, self.series, self.persistence):
                for key in list(mapping):
                    if key[:5] == base:
                        del mapping[key]
        origin = self.persistence.get(identity)
        connected = success or event.get('exit') == '-115'
        if origin and connected and 0 < now - origin[0] <= 300 and any(ip.is_global for ip, _ in destinations):
            found.append(Signal('behavior-persistence-network', 'high', 'Persistence activity followed by an outbound public-IP connection',
                context + f'Persistence event={origin[1]}; connect event={event_id}. '
                'Captured successful/in-progress connect; completion may be unknown. This is not identification of C2 or proof of malicious persistence.', origin[1]))
        if persistence:
            self.save(self.persistence, identity, (now, event_id), 512)
        if not destinations:
            return found
        bucket = self.attempts.setdefault(identity, deque(maxlen=128))
        # Reject timestamp regression rather than joining observations backwards.
        if bucket and now < bucket[-1][0]:
            return found
        while bucket and now - bucket[0][0] > 60:
            bucket.popleft()
        for ip, port in destinations[:1]:
            if not port or ip.is_unspecified or ip.is_multicast:
                continue
            bucket.append((now, str(ip), port, not success and event.get('exit') != '-115', event_id))
            vertical = [item for item in bucket if item[1] == str(ip)]
            horizontal = [item for item in bucket if item[2] == port]
            if len({item[2] for item in vertical}) >= 20:
                found.append(Signal('network-port-sweep', 'medium' if ip.is_loopback else 'high', 'Rapid multi-port connection probing',
                    context + f'{len({item[2] for item in vertical})} distinct ports on {ip} in 60s. '
                    'Includes captured successful, pending and selected failed connects; authorized scans can match. Raw-packet scans are not covered.', vertical[0][4]))
            if len({item[1] for item in horizontal}) >= 30 and (exe.rsplit('/', 1)[-1] in SCANNERS or
                    sum(item[3] for item in horizontal) >= .8 * len(horizontal)):
                found.append(Signal('network-host-sweep', 'high', 'Rapid multi-host connection probing',
                    context + f'{len({item[1] for item in horizontal})} addresses on port {port} in 60s, with a scanner basename or >=80% failed attempts. '
                    'This can be authorized discovery or network failure, not proof of intrusion.', horizontal[0][4]))
            if ip.is_global:
                key = identity + (str(ip), port)
                series = self.series.setdefault(key, deque(maxlen=12))
                if not series or now > series[-1][0]:
                    series.append((now, event_id))
                if len(series) == 12:
                    gaps = [series[i][0] - series[i-1][0] for i in range(1, 12)]
                    median = statistics.median(gaps)
                    if 10 <= median <= 120 and now - series[0][0] >= 120 and all(abs(gap - median) <= .2 * median for gap in gaps):
                        found.append(Signal('network-periodic', 'medium', 'Regularly spaced outbound connection attempts',
                            context + f'12 attempts to [{ip}]:{port}; median spacing={median:.1f}s, tolerance=20%. '
                            'Legitimate polling can match. This does not identify C2 and misses persistent sockets, DNS/packet beacons and jittered activity.', series[0][1]))
                self.save(self.series, key, series, 256)
        self.save(self.attempts, identity, bucket, 256)
        return found
