"""Account-local, reversible presentation exceptions, never host policy changes.

Default exceptions use the detector's exact pre-truncation context fingerprint.
The optional path-prefix mode requires explicit profile/executable/operation/
permission context and a deliberate absolute prefix. No regex or shell grammar.
"""
import json
import math
import time

MAX_EXCEPTIONS = 256
CONTEXT_FIELDS = ('node', 'exe', 'profile', 'operation', 'denied_mask')


class IgnoreList:
    def __init__(self, store):
        self.store = store
        store.db.execute('CREATE TABLE IF NOT EXISTS ignores (id INTEGER PRIMARY KEY, '
            'rule TEXT, criteria TEXT, reason TEXT, created REAL, expires REAL, '
            'enabled INTEGER DEFAULT 1, matches INTEGER DEFAULT 0, latest REAL)')
        self.cache = None

    def rows(self):
        return self.store.db.execute('SELECT id,rule,criteria,reason,created,expires,enabled,matches,latest '
                                     'FROM ignores ORDER BY id DESC LIMIT 256').fetchall()

    def save(self, rule, criteria, reason, seconds=0, identity=None, now=None):
        now = time.time() if now is None else now
        if seconds not in {None, 0, 600, 3600, 86400} or not math.isfinite(now) or seconds is None and identity is None:
            raise ValueError('Invalid exception expiry')
        if not reason.strip() or len(reason) > 512 or not rule or len(rule) > 128:
            raise ValueError('Supply a reason (up to 512 characters)')
        if set(criteria) in ({'fingerprint'}, {'fingerprint', 'display'}):
            import re
            if not re.fullmatch('[0-9a-f]{64}', criteria['fingerprint']):
                raise ValueError('Missing exact context fingerprint')
            if 'display' in criteria and (not isinstance(criteria['display'], str) or len(criteria['display']) > 4096):
                raise ValueError('Invalid exception description')
        elif set(criteria) == set(CONTEXT_FIELDS) | {'name_prefix'}:
            if rule != 'policy-denial':
                raise ValueError('Prefix exceptions are limited to policy denials')
            prefix = criteria['name_prefix']
            if not all(isinstance(v, str) and 0 < len(v) <= 4096 for v in criteria.values()):
                raise ValueError('All policy matching fields are required')
            if not prefix.startswith('/') or len(prefix) < 8 or '..' in prefix.split('/') or any(c in prefix for c in '*?\n\r'):
                raise ValueError('Use a literal absolute target prefix of at least eight characters')
        else:
            raise ValueError('Unsupported exception conditions')
        raw = json.dumps(criteria, sort_keys=True)
        if seconds is None:
            saved = self.store.db.execute('SELECT expires FROM ignores WHERE id=? AND rule=?', (identity, rule)).fetchone()
            if saved is None: raise ValueError('Exception no longer exists')
            expires = saved[0]
        else:
            expires = now + seconds if seconds else 0
        if identity is None:
            if self.store.db.execute('SELECT count(*) FROM ignores').fetchone()[0] >= MAX_EXCEPTIONS:
                raise ValueError('Exception limit reached; remove an old exception')
            self.store.db.execute('INSERT INTO ignores(rule,criteria,reason,created,expires) VALUES(?,?,?,?,?)',
                                  (rule, raw, reason, now, expires))
        else:
            self.store.db.execute('UPDATE ignores SET criteria=?,reason=?,expires=? WHERE id=? AND rule=?',
                                  (raw, reason, expires, identity, rule))
        self.cache = None
        self.store.commit()

    def change(self, identity, action):
        if action == 'delete':
            self.store.db.execute('DELETE FROM ignores WHERE id=?', (identity,))
        elif action == 'toggle':
            self.store.db.execute('UPDATE ignores SET enabled=1-enabled WHERE id=?', (identity,))
        else:
            raise ValueError('Unsupported exception action')
        self.cache = None
        self.store.commit()

    def match(self, rule, fingerprint, context, now, count=True):
        if self.cache is None:
            self.cache = [(row[0], row[1], json.loads(row[2]), row[5]) for row in self.rows() if row[6]]
        for identity, candidate_rule, criteria, expires in self.cache:
            if candidate_rule != rule or expires and expires <= now:
                continue
            exact = criteria.get('fingerprint') == fingerprint
            prefix = ('name_prefix' in criteria and context.get('name', '').startswith(criteria['name_prefix'])
                      and all(context.get(key) == criteria[key] for key in CONTEXT_FIELDS))
            if exact or prefix:
                if count:
                    self.store.db.execute('UPDATE ignores SET matches=min(matches+1,1000000000),latest=? WHERE id=?', (now, identity))
                return True
        return False
