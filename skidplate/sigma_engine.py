"""Offline, fail-closed execution of a documented subset of Sigma detection rules.

SigmaHQ supplies the rules; this module supplies the small local backend. pySigma
is a parser/converter, not an event-execution engine. Never eval conditions or
load executable rule plugins. Unsupported syntax disables that rule explicitly.
"""
from dataclasses import dataclass
import fnmatch
import hashlib
import json
from pathlib import Path
import re
import posixpath

import yaml

ROOT = Path(__file__).resolve().parents[1] / 'rules/sigma'
FIELDS = frozenset({'type', 'name', 'nametype', 'exe', 'comm', 'key', 'unit',
                    'uid', 'euid', 'auid', 'success', 'res', 'SYSCALL'} |
                   {f'a{i}' for i in range(16)})
LEVELS = {'informational': 'low', 'low': 'low', 'medium': 'medium',
          'high': 'high', 'critical': 'high'}
# Normalize numeric syscalls only for verified ABI/name pairs. Never guess an ABI.
CALLS = {'c000003e': {'133': 'mknod', '259': 'mknodat', '59': 'execve', '322': 'execveat', '103': 'syslog', '135': 'personality'},
         '40000003': {'14': 'mknod', '297': 'mknodat', '11': 'execve', '358': 'execveat', '103': 'syslog', '136': 'personality'},
         'c00000b7': {'33': 'mknodat', '221': 'execve', '281': 'execveat', '116': 'syslog', '92': 'personality'}}


class Unsupported(ValueError):
    pass


def wildcard(pattern, value):
    """Sigma * and ? only; brackets are literals, unlike shell fnmatch syntax.

    A greedy linear-space matcher avoids regex backtracking on hostile log text.
    Escaped wildcard syntax is deliberately unsupported rather than misread.
    """
    pattern, value = pattern.casefold(), str(value).casefold()
    i = j = 0
    star = -1
    restart = 0
    while j < len(value):
        if i < len(pattern) and (pattern[i] == '?' or pattern[i] == value[j]):
            i += 1; j += 1
        elif i < len(pattern) and pattern[i] == '*':
            star, restart = i, j
            i += 1
        elif star >= 0:
            restart += 1; j = restart; i = star + 1
        else:
            return False
    return all(c == '*' for c in pattern[i:])


def condition_tree(text, selections):
    """Parse a finite boolean grammar into tuples; no Python/query evaluation."""
    if not isinstance(text, str) or len(text) > 2048:
        raise Unsupported('Missing or oversized condition')
    tokens = re.findall(r'\(|\)|[A-Za-z0-9_*?-]+', text)
    if re.sub(r'\s+', '', text) != ''.join(tokens) or len(tokens) > 128:
        raise Unsupported('Unsupported condition syntax')
    position = 0
    def atom(depth):
        nonlocal position
        if depth > 16 or position >= len(tokens):
            raise Unsupported('Invalid/deep condition')
        token = tokens[position]; position += 1
        if token == 'not':
            return ('not', atom(depth + 1))
        if token == '(':
            result = expression(depth + 1)
            if position >= len(tokens) or tokens[position] != ')':
                raise Unsupported('Unbalanced condition')
            position += 1
            return result
        if token in {'1', 'all'}:
            if position + 1 >= len(tokens) or tokens[position] != 'of':
                raise Unsupported('Unsupported quantifier')
            pattern = tokens[position + 1]; position += 2
            selected = list(selections) if pattern == 'them' else [s for s in selections if fnmatch.fnmatchcase(s, pattern)]
            if not selected:
                raise Unsupported('Condition matches no selections')
            return ('or' if token == '1' else 'and', *(('selection', s) for s in selected))
        if token not in selections:
            raise Unsupported('Unknown selection: ' + token)
        return ('selection', token)
    def conjunction(depth):
        nonlocal position
        parts = [atom(depth)]
        while position < len(tokens) and tokens[position] == 'and':
            position += 1; parts.append(atom(depth))
        return ('and', *parts)
    def expression(depth):
        nonlocal position
        parts = [conjunction(depth)]
        while position < len(tokens) and tokens[position] == 'or':
            position += 1; parts.append(conjunction(depth))
        return ('or', *parts)
    tree = expression(0)
    if position != len(tokens):
        raise Unsupported('Trailing condition tokens')
    return tree


def validate_selection(selection):
    if isinstance(selection, list):
        validate_keywords(selection)
        return
    if not isinstance(selection, dict) or not 1 <= len(selection) <= 32:
        raise Unsupported('Only bounded field maps and string keyword lists are supported')
    for key, raw in selection.items():
        if not isinstance(key, str):
            raise Unsupported('Non-string field')
        field, *modifiers = key.split('|')
        if key == '|all':
            validate_keywords(raw)
            continue
        if field not in FIELDS:
            raise Unsupported('Unavailable field: ' + (field or '(fieldless expression)'))
        if modifiers not in ([], ['startswith'], ['endswith'], ['contains']):
            raise Unsupported('Unsupported modifiers: ' + key)
        values = raw if isinstance(raw, list) else [raw]
        if not 1 <= len(values) <= 128 or any(type(v) not in (str, int, bool) or len(str(v)) > 1024 for v in values):
            raise Unsupported('Unsupported/oversized field values')
        if any('\\' in str(v) for v in values):
            raise Unsupported('Escaped Sigma strings are not supported by this backend')


def validate_keywords(values):
    """Only finite literal/wildcard keyword lists, never regex or raw queries."""
    if not isinstance(values, list) or not 1 <= len(values) <= 128 or any(
            not isinstance(v, str) or not 1 <= len(v) <= 1024 or '\\' in v for v in values):
        raise Unsupported('Unsupported/oversized keyword list')


def selection_matches(selection, row):
    if isinstance(selection, list):
        return '_keywords' in row and any(wildcard('*' + v + '*', row['_keywords']) for v in selection)
    for key, wanted in selection.items():
        if key == '|all':
            if '_keywords' not in row or not all(wildcard('*' + v + '*', row['_keywords']) for v in wanted):
                return False
            continue
        field, *modifiers = key.split('|')
        if field not in row:
            return False
        values = wanted if isinstance(wanted, list) else [wanted]
        patterns = [str(v) for v in values]
        if modifiers == ['startswith']: patterns = [v + '*' for v in patterns]
        if modifiers == ['endswith']: patterns = ['*' + v for v in patterns]
        if modifiers == ['contains']: patterns = ['*' + v + '*' for v in patterns]
        actual = row[field] if isinstance(row[field], list) else [row[field]]
        if not any(wildcard(pattern, str(value)) for pattern in patterns for value in actual):
            return False
    return True


def evaluate(tree, matches):
    if tree[0] == 'selection': return matches[tree[1]]
    if tree[0] == 'not': return not evaluate(tree[1], matches)
    values = (evaluate(child, matches) for child in tree[1:])
    return all(values) if tree[0] == 'and' else any(values)


@dataclass
class Rule:
    metadata: dict
    selections: dict
    tree: tuple


class SigmaEngine:
    def __init__(self, directory=ROOT):
        self.rules, self.catalog = [], []
        manifest = json.loads((directory / 'snapshot.json').read_text())
        if len(manifest['files']) > 128:
            raise ValueError('Sigma pack exceeds rule limit')
        for entry in manifest['files']:
            name = entry['file']
            if Path(name).name != name or not name.endswith('.yml'):
                raise ValueError('Unsafe Sigma source path')
            path = directory / name
            if path.is_symlink() or path.stat().st_size > 65536:
                raise ValueError('Unsafe Sigma source')
            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != entry['sha256']:
                raise ValueError('Sigma source hash mismatch: ' + name)
            # Only the pinned bundled pack is parsed, never arbitrary log YAML.
            data = yaml.safe_load(content)
            metadata = {k: data.get(k, '') for k in ('id', 'title', 'author', 'description', 'status', 'level', 'tags', 'falsepositives')}
            metadata.update(source=entry['source'], file=name, support='supported', reason='Matching supported; live audit collection unverified')
            metadata['logic_digest'] = hashlib.sha256(json.dumps(data['detection'], sort_keys=True).encode()).hexdigest()
            try:
                source = data.get('logsource', {})
                application = (source.get('category') == 'application' and source.get('product') in
                               {'python', 'ruby_on_rails', 'nodejs'} and not source.get('service'))
                if not application and (source.get('product') != 'linux' or source.get('service') != 'auditd'):
                    raise Unsupported('Unsupported log source')
                metadata['source_kind'] = 'application' if application else 'auditd'
                metadata['source_product'] = source.get('product')
                detections = data['detection']
                selections = {k: v for k, v in detections.items() if k != 'condition'}
                if not 1 <= len(selections) <= 32:
                    raise Unsupported('Too many selections')
                for value in selections.values(): validate_selection(value)
                if application and not all(isinstance(value, list) or set(value) == {'|all'} for value in selections.values()):
                    raise Unsupported('Application sources support bounded message keyword lists only')
                metadata['argument_matching'] = not application and any(isinstance(value, list) or any(
                    key == '|all' or key.split('|')[0] in {f'a{i}' for i in range(16)}
                    for key in value) for value in selections.values())
                if metadata['argument_matching']:
                    metadata['reason'] = ('Bounded argument matching supported; complete EXECVE <=16 args/4096 bytes or verified numeric syscall a0 required; live collection unverified')
                if application:
                    metadata['reason'] = 'Requires explicitly selected ' + source['product'] + ' journal services; raw error text not saved; live coverage unverified'
                tree = condition_tree(detections.get('condition'), selections)
                self.rules.append(Rule(metadata, selections, tree))
            except Unsupported as exc:
                metadata.update(support='unsupported', reason=str(exc))
            self.catalog.append(metadata)
        self.catalog.extend(dict(row, support='not bundled', author='', level='') for row in manifest.get('unbundled', []))

    def detect(self, event):
        # Match each complete record independently. Flattening PATH records would
        # incorrectly combine CREATE on one path with a different protected path.
        rows = []
        exec_records = sum(r.kind == 'EXECVE' for r in event.records)
        cwd = next((r.values.get('cwd', '') for r in event.records if r.kind == 'CWD'), '')
        parents = {r.values.get('name') for r in event.records if r.kind == 'PATH'
                   and r.values.get('nametype') == 'PARENT' and r.values.get('name', '').startswith('/')}
        for record in event.records:
            row = dict(record.values, type=record.kind)
            row['_source'] = 'auditd'
            if record.kind == 'APPLICATION_LOG':
                row['_source'] = 'application:' + record.values.get('application_product', '')
                if record.application_message:
                    row['_keywords'] = record.application_message
            # Transient argument data is produced only by the strict parser.
            # It never enters saved summaries, notification bodies or evidence.
            arguments = record.sigma_arguments if record.kind != 'EXECVE' or exec_records == 1 else {}
            row.update(arguments)
            if record.kind == 'EXECVE' and arguments:
                row['_keywords'] = ' '.join(record.sigma_arguments[f'a{i}'] for i in range(len(record.sigma_arguments)))
            if record.kind == 'PATH' and row.get('name') and not row['name'].startswith('/') and row['name'] != '(null)':
                # Resolve lexical audit context only, never open a target. Keep
                # record roles together; ambiguous parent records stay relative.
                base = (next(iter(parents)) if len(parents) == 1 else '') if '/' not in row['name'] and parents else cwd
                if base.startswith('/'):
                    row['name'] = posixpath.normpath(posixpath.join(base, row['name']))
            if record.kind == 'SYSCALL':
                row['SYSCALL'] = CALLS.get(row.get('arch', '').lower(), {}).get(row.get('syscall'), '')
            if 'key' in row: row['key'] = row['key'].split('\x01')
            rows.append(row)
        matches = []
        for rule in self.rules:
            expected_source = ('application:' + rule.metadata['source_product']
                               if rule.metadata['source_kind'] == 'application' else 'auditd')
            for row in rows:
                if row['_source'] != expected_source or (rule.metadata.get('argument_matching') and not any(f'a{i}' in row for i in range(16))):
                    continue
                selected = {key: selection_matches(value, row) for key, value in rule.selections.items()}
                if evaluate(rule.tree, selected):
                    metadata = dict(rule.metadata)
                    metadata['matched_selections'] = [key for key, matched in selected.items() if matched][:16]
                    metadata['matched_argument_fields'] = [key + '.' + field for key, value in rule.selections.items()
                        if selected[key] and isinstance(value, dict) for field in value
                        if field.split('|')[0] in {f'a{i}' for i in range(16)}][:16]
                    if rule.metadata['source_kind'] == 'application':
                        terms = [term for value in rule.selections.values()
                                 for term in (value if isinstance(value, list) else value['|all'])]
                        metadata['matched_indicators'] = [term for term in terms if wildcard('*' + term + '*', row.get('_keywords', ''))][:8]
                    matches.append(metadata)
                    break
        return matches
