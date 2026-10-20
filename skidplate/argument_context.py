"""Best-effort redacted, display-only argv context. Never construct a command.

No shell, subprocess, path access, URL opening, interpolation or decoding action
exists here. Unknown secret formats can evade redaction: this is an explicit
private-history feature, not a credential vault or a safe-to-paste shell format.
"""
import json
import re

MAX_CONTEXT = 4096
SECRET_PARTS = ('password', 'passwd', 'passphrase', 'token', 'secret', 'apikey',
                'accesskey', 'privatekey', 'authorization', 'credential', 'cookie',
                'sessionkey', 'bearer', 'authentication')
PAYLOAD_OPTIONS = {'-c', '-e', '-d', '-F', '--eval', '--execute', '--command', '--data',
                   '--data-raw', '--data-binary', '--data-urlencode', '--json',
                   '--body-data', '--post-data', '--form', '--form-string'}
PRIVATE_OPTIONS = {'-p', '-u', '--user', '--proxy-user', '--pass', '--pwd', '-H', '--header'}
SHELL_META = '$`;&|<>()'


def sensitive_name(name):
    normalized = ''.join(c for c in name.casefold() if c.isalnum())
    return normalized in {'pass', 'pwd', 'auth', 'key'} or any(part in normalized for part in SECRET_PARTS)


def redact_value(value):
    """Conservative fixed recognizers; no claim to detect arbitrary secrets."""
    lowered = value.casefold().lstrip()
    if lowered.startswith(('{', '[', 'data:', 'javascript:', 'file:')):
        return '[REDACTED PAYLOAD]'
    if any(term in lowered for term in ('authorization:', 'cookie:', 'set-cookie:', 'bearer ')):
        return '[REDACTED CREDENTIAL/HEADER]'
    url = re.fullmatch(r'([A-Za-z][A-Za-z0-9+.-]{0,15})://([^/?#]{1,512})(.*)', value)
    if url:
        authority = url[2].rsplit('@', 1)[-1]
        if not re.fullmatch(r'[A-Za-z0-9.\[\]:-]{1,253}', authority):
            return '[REDACTED URL]'
        return url[1] + '://' + authority + ('/[URL DETAILS REDACTED]' if url[3] else '')
    if not value.startswith(('/', './', '../')) and re.fullmatch(r'[A-Za-z0-9_./+=-]{32,}', value):
        return '[REDACTED TOKEN-LIKE VALUE]'
    return value


def redacted_arguments(arguments):
    """Keep indices stable; mask the next value after sensitive/payload flags."""
    output, hide_next = [], False
    for index in range(len(arguments)):
        value = arguments[f'a{index}']
        if hide_next:
            output.append('[REDACTED VALUE]')
            hide_next = False
            continue
        # Compact forms can themselves contain '=' or sensitive words. Handle
        # them before assignment/flag-name logic, or '-pPASSWORD'/'-H...' could
        # be mistaken for a harmless option name and retained verbatim.
        if any(value.startswith(flag) and len(value) > len(flag) for flag in ('-p', '-u', '-H', '-c', '-e', '-d', '-F')) and not value.startswith('--'):
            output.append(value[:2] + '[REDACTED VALUE]')
            continue
        name, separator, content = value.partition('=')
        # A URL may contain '=' in its query or userinfo. Only treat a real
        # option/environment identifier as an assignment; otherwise sanitize
        # the complete URL before any prefix could retain its credentials.
        if separator and re.fullmatch(r'(?:--?[A-Za-z][A-Za-z0-9_-]*|[A-Za-z_][A-Za-z0-9_]*)', name):
            output.append(name + '=[REDACTED VALUE]' if sensitive_name(name) or name in PAYLOAD_OPTIONS or name in PRIVATE_OPTIONS
                          else name + '=' + redact_value(content))
        elif value in PRIVATE_OPTIONS or value in PAYLOAD_OPTIONS or (re.fullmatch(r'--[A-Za-z][A-Za-z0-9_-]*', value) and sensitive_name(value)):
            output.append(value)
            hide_next = True
        else:
            output.append(redact_value(value))
    return output


def escaped_data(value):
    # JSON escaping makes controls/bidi/newlines visible. Shell metacharacters
    # also use JSON Unicode escapes so the view is not a ready-to-paste payload.
    text = json.dumps(value, ensure_ascii=True)
    for char in SHELL_META:
        text = text.replace(char, '\\u' + format(ord(char), '04x'))
    return text


def describe_arguments(event):
    """Use only already-captured bounded data; never read /proc argv or files."""
    rows = [r for r in event.records if r.kind == 'EXECVE']
    if len(rows) != 1 or not rows[0].sigma_arguments:
        return ''
    arguments = redacted_arguments(rows[0].sigma_arguments)
    lines = ['SAVED COMMAND ARGUMENTS / DATA ONLY',
             'Captured argv; best-effort redaction. Unknown secrets may remain.',
             'Values are individually JSON-escaped, including shell metacharacters. Never paste evidence into a terminal.']
    for index, value in enumerate(arguments):
        line = f'arg[{index}]: ' + escaped_data(value)
        if sum(len(item) + 1 for item in lines) + len(line) > MAX_CONTEXT - 100:
            lines.append(f'arg[{index}] and remaining arguments omitted: display budget exceeded.')
            break
        lines.append(line)
    return '\n'.join(lines)
