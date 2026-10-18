"""Presentation-only evidence tags. Text stays literal, selectable and copyable."""
import re

MAX_SCAN = 256 * 1024
MAX_TAGS = 2048
LEGEND = 'Highlights: cyan = users · amber = paths · violet = endpoints · bold = process IDs · green/rose = recorded result. Colors are field cues, not a safety verdict.'
STYLES = {
    'heading': {'foreground': '#eaf3ff', 'weight': 700},
    'user': {'foreground': '#80d9f5', 'weight': 700},
    'path': {'foreground': '#f3cb82', 'weight': 700},
    'endpoint': {'foreground': '#d4b4ff', 'weight': 700},
    'process': {'weight': 700},
    'success': {'foreground': '#8bd6a8', 'weight': 700},
    'failure': {'foreground': '#ffabb4', 'weight': 700},
}
HEADINGS = frozenset({'WHAT HAPPENED', 'WHY THIS RULE MATCHED', 'LATEST EVIDENCE',
    'GROUP', 'WHAT TO CHECK', 'RELATED SAVED EVENTS', 'NEARBY HOST ACTIVITY — MAY BE UNRELATED',
    'INVESTIGATE / CONTAIN', 'LIMITS', 'SAVED AUDIT EVIDENCE', 'SOCKET SNAPSHOT',
    'OBSERVED PROCESS HOLDERS', 'ASSOCIATION LIMITS'})
# Bounded value matches, no nested quantifiers, no markup, shell or links.
PATTERNS = (
    ('user', re.compile(r'\b(?:Originating login|Real UID|effective UID|Login UID|login UID|auid|euid|uid|account|acct|user)\s*[=:]\s*([^;\n·]{1,256})', re.I)),
    ('path', re.compile(r'^(?:Executable|Captured path|Persistence location|Target|Executable path):\s*(/[^\n;·]{1,512})', re.M)),
    ('path', re.compile(r'(?<![\w/])(/[^\s;<>\[\]"\x27,]{1,511})')),
    ('endpoint', re.compile(r'\b(?:Recorded connect destination|Local endpoint|Remote endpoint|destination|source|address|addr)\s*[=:]\s*(\[?[0-9a-fA-F:.]+\]?(?::[0-9]{1,5})?)')),
    ('endpoint', re.compile(r'(\[[0-9a-fA-F:]{2,45}\]:[0-9]{1,5}|\b[0-9]{1,3}(?:\.[0-9]{1,3}){3}:[0-9]{1,5}\b)')),
    ('process', re.compile(r'\b(?:parent\s+PID|PID|session|inode)\s*[=: ]\s*([0-9]{1,20})\b', re.I)),
    ('result', re.compile(r'\bresult\s*[=:]\s*(success|failed|failure|yes|no|1|0)\b', re.I)),
)


def spans(text):
    """Character offsets, not UTF-8 byte offsets; limits affect styling only."""
    sample = text[:MAX_SCAN]
    found = []
    offset = 0
    for line in sample.splitlines(keepends=True):
        heading = line.rstrip('\r\n')
        if heading in HEADINGS:
            found.append(('heading', offset, offset + len(heading)))
            if len(found) == MAX_TAGS:
                return found
        offset += len(line)
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(sample):
            style = kind
            if kind == 'result':
                style = 'success' if match[1].lower() in {'success', 'yes', '1'} else 'failure'
            start, end = match.span(1)
            found.append((style, start, end))
            if len(found) == MAX_TAGS:
                return found
    return found


def set_evidence(buffer, text):
    """Apply fixed GTK tags to literal text. Never hide or rewrite evidence."""
    table = buffer.get_tag_table()
    for name, properties in STYLES.items():
        if table.lookup('evidence-' + name) is None:
            buffer.create_tag('evidence-' + name, **properties)
    buffer.set_text(text)
    for name, start, end in spans(text):
        buffer.apply_tag_by_name('evidence-' + name,
            buffer.get_iter_at_offset(start), buffer.get_iter_at_offset(end))
