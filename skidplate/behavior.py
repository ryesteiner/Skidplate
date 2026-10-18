"""Bounded local behavior correlation and plain-language investigation guidance."""
from collections import OrderedDict, deque
from dataclasses import dataclass
import re
from .persistence import changes as persistence_changes, PERSISTENCE_RULES
from .signals import RULES as CHOKEPOINT_RULES

WINDOW = 300
SEQUENCE_RULES = frozenset({'auth-success-after-failures', 'behavior-persistence', 'behavior-network', 'behavior-user-persistence'})
BEHAVIOR_RULES = SEQUENCE_RULES | PERSISTENCE_RULES | {'process-masquerade'} | CHOKEPOINT_RULES.keys()


def sequence_groups(rows, stats, now):
    """Retained chains and live groups last observed within 24h; not event counts."""
    groups = [row for row in rows if row[2] in SEQUENCE_RULES]
    live = [row for row in groups if now - 86400 <= row[1] <= now + 60 and not stats[row[0]][4]]
    return groups, live


def behavior_groups(rows, stats, now):
    groups = [row for row in rows if row[2] in BEHAVIOR_RULES]
    return groups, [row for row in groups if now - 86400 <= row[1] <= now + 60 and not stats[row[0]][4]]


IMPORTANT_RULES = frozenset({
    'auth-burst', 'auth-success-after-failures', 'behavior-persistence', 'behavior-network',
    'audit-health', 'audit-config', 'audit-tamper', 'root-temp-exec', 'root-user-exec',
    'memory-exec', 'process-injection', 'network-watchlist', 'network-temp-exec',
    'behavior-user-persistence', 'process-masquerade',
}) | PERSISTENCE_RULES | CHOKEPOINT_RULES.keys() | {'privilege-tool'}
PERSISTENCE_KEYS = {'systemd_persistence', 'systemd', 'cron', 'init', 'udev',
                    'shell_profiles', 'sentinel_persistence'}
RISKY_PATHS = ('/tmp/', '/var/tmp/', '/dev/shm/', '/home/', '/run/user/', '/memfd:', 'memfd:')


@dataclass(frozen=True)
class Finding:
    rule: str
    title: str
    detail: str
    first_event: str


def number(value, low=0):
    return bool(re.fullmatch(r'[0-9]{1,10}', value)) and low <= int(value) < 4294967294


def process_identity(event, historical):
    node, exe = event.records[0].node, event.get('exe')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', node):
        return None
    if not (number(event.get('pid'), 1) and number(event.get('auid'), 1000)
            and number(event.get('ses')) and exe and len(exe) <= 4096):
        return None
    return historical, node, event.get('auid'), event.get('ses'), event.get('pid'), exe


class BehaviorCorrelator:
    """In-memory windows only; separate live/history, no cross-restart claims."""
    def __init__(self):
        self.failures = OrderedDict()
        self.origins = OrderedDict()

    def observe(self, event, historical, auth_threshold, auth_window, execution, destinations):
        result = []
        successful = event.result.lower() in {'yes', 'success', '1'}
        timestamp = event.timestamp
        node = event.records[0].node
        if 'DAEMON_START' in event.kinds:
            for mapping in (self.failures, self.origins):
                for key in [key for key in mapping if key[:2] == (historical, node)]:
                    del mapping[key]
            return []
        # Only simple bounded identities can participate; retain logs regardless.
        account, address = event.get('acct'), event.get('addr') or 'local'
        auth_key = (historical, node, account, address)
        if ('USER_AUTH' in event.kinds and re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', account)
                and re.fullmatch(r'[A-Za-z0-9_.:%?-]{1,128}', address)
                and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', node)):
            if event.result.lower() in {'failed', 'failure', 'no', '0'}:
                bucket = self.failures.setdefault(auth_key, deque(maxlen=100))
                bucket.append((timestamp, event.identity))
                self.failures.move_to_end(auth_key)
            elif successful:
                bucket = self.failures.pop(auth_key, ())
                previous = [(when, identity) for when, identity in bucket
                            if 0 <= timestamp - when <= auth_window]
                if len(previous) >= auth_threshold:
                    result.append(Finding('auth-success-after-failures',
                        'Authentication succeeded after repeated failures',
                        f'{len(previous)} failed authentications followed by success for account={account}, '
                        f'address={address}, host={node}, within {auth_window}s. '
                        'This can be password guessing or legitimate retries; it does not prove an interactive login.',
                        previous[0][1]))
        while len(self.failures) > 1024:
            self.failures.popitem(last=False)
        identity = process_identity(event, historical)
        if identity is not None:
            origin = self.origins.get(identity)
            if origin and 0 < timestamp - origin[0] <= WINDOW:
                context = (f'Same host={node}, login UID={event.get("auid")}, session={event.get("ses")}, '
                           f'PID={event.get("pid")}, executable={event.get("exe")}. '
                           f'Execution event={origin[1]}; follow-up event={event.identity}. ')
                typed = persistence_changes(event)
                if 'SYSCALL' in event.kinds and successful and (typed or origin[2] and set(event.get('key').split('\x01')) & PERSISTENCE_KEYS):
                    result.append(Finding('behavior-persistence' if origin[2] else 'behavior-user-persistence',
                        'Risky root execution followed by a persistence change' if origin[2] else 'Temporary/memory-backed execution followed by persistence-location activity',
                        context + 'A risky executable then performed a successful operation at '
                        'a captured persistence location within five minutes. File contents and authorization are unverified. '
                        'Confirm whether this was planned installation.', origin[1]))
                public = [(ip, port) for ip, port in destinations if ip.is_global]
                if public and origin[2]:
                    pending = event.result.lower() in {'no', 'failed', 'failure', '0'}
                    targets = ', '.join(f'[{ip}]:{port}' for ip, port in public)
                    result.append(Finding('behavior-network',
                        'Risky root execution followed by a public-network connection',
                        context + f'Destination={targets}; ' +
                        ('nonblocking attempt, completion unknown.' if pending else 'connect syscall succeeded.') +
                        ' This is a behavior signal, not identification of a command-and-control server.', origin[1]))
            if execution and successful:
                # A new exec replaces any old image's origin even for the same PID.
                for old in [key for key in self.origins if key[:5] == identity[:5]]:
                    del self.origins[old]
                root_risky = event.get('euid') == '0' and event.get('exe').startswith(RISKY_PATHS)
                user_risky = event.get('exe').startswith(('/tmp/', '/var/tmp/', '/dev/shm/', '/memfd:', 'memfd:'))
                if root_risky or user_risky:
                    self.origins[identity] = timestamp, event.identity, root_risky
                    self.origins.move_to_end(identity)
        while len(self.origins) > 512:
            self.origins.popitem(last=False)
        return result


def guidance(rule):
    if rule in CHOKEPOINT_RULES:
        return (CHOKEPOINT_RULES[rule] + '.',
                'Review the cited event IDs, operation/result, originating login, exact executable and saved endpoints. '
                'Use nearby events as context only. Tool names, regular polling and authorized scans can match. '
                'PID/session reuse and missing audit coverage limit correlation; a rule match does not prove an exploit, C2 or unwanted access.')
    if rule == 'system-file-change':
        return ('A successful syscall carried a watch key for a system executable, loader or boot path.',
                'Check the saved syscall and PATH roles. An open or metadata operation does not prove file contents changed. '
                'For sbctl touching an EFI file, signing during boot/snapshot maintenance is a possible explanation, not verified authorization. '
                'Compare nearby captured service/package activity and the original audit event before suppressing it.')
    if rule in PERSISTENCE_RULES:
        return ('A captured successful operation matched a specific startup or persistent-access location.',
                'Review the target and operation, writer executable and login/session. A write-capable open is not proof contents changed. '
                'Compare with known-good configuration and expected package/install activity. Creation and writable-path writers increase priority; '
                'SSH/loader changes always require review. Do not execute an unfamiliar entry or delete it automatically.')
    if rule == 'process-masquerade':
        return ('An executable used a system-service basename from a writable/user location.',
                'Check its full path, package ownership and hash against your expected installation. Names are not product identity; '
                'legitimate local builds can also match. Inspect sockets and the originating session before containment.')
    if rule == 'policy-denial':
        return ('A security policy recorded an operation; a denial usually means protection blocked it.',
                'Check the profile, operation, target and denied permission. Confirm whether you initiated it. '
                'A blocked read alone does not show that the file was opened or executed.')
    if rule in {'auth-burst', 'auth-success-after-failures'}:
        return ('Authentication events matched the configured account/address window.',
                'Check the account, source address and timing. Confirm expected retries and review subsequent session activity.')
    if rule.startswith('behavior-'):
        return ('Two ordered events matched the same host, login UID, session, PID and executable within five minutes.',
                'Review both cited event IDs, the executable origin, destination/changed path and whether installation or maintenance was planned. '
                'PID reuse within the window is still possible; no process-start identifier is available.')
    if rule in {'audit-config', 'audit-health', 'audit-tamper'}:
        return ('Audit configuration or collection health changed; collection may be interrupted.',
                'Confirm authorized audit administration, daemon status and kernel audit state. A readable log does not establish complete collection.')
    if rule in {'network-watchlist', 'network-temp-exec'}:
        return ('A captured connect syscall matched the configured destination or executable-origin rule.',
                'Check the destination, executable and originating session. An EINPROGRESS result is an attempt, not a completed connection. '
                'Auditd does not provide packet contents or prove C2.')
    if rule in {'root-temp-exec', 'root-user-exec', 'memory-exec', 'process-injection', 'bpf-program-load'}:
        return ('A captured execution or memory/kernel operation matched a sensitive behavior rule.',
                'Verify the executable and session against expected tools or maintenance. Review related saved events; do not run an unfamiliar executable to inspect it.')
    return ('A captured event matched this rule or a configured audit watch key.',
            'Check success/failure, the executable, target and originating login. Compare the change with planned administration. '
            'A configuration change alone does not prove malicious persistence.')
