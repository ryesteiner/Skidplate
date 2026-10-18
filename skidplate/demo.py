"""Synthetic records only; no actual host identifiers or credentials."""


def sample(now):
    rows = []
    for i in range(5):
        rows.append(f'''type=USER_AUTH msg=audit({now:.3f}:{i+1}): pid=42 uid=0 auid=1000 msg='op=PAM:authentication acct="demo-user" addr=192.0.2.10 res=failed' ''')
        rows.append(f"type=EOE msg=audit({now:.3f}:{i+1}):")
    rows += [f'type=CONFIG_CHANGE msg=audit({now:.3f}:20): auid=1000 op=add_rule res=1',
             f'type=EOE msg=audit({now:.3f}:20):',
             f'type=SYSCALL msg=audit({now:.3f}:21): arch=c000003e syscall=59 success=yes uid=0 euid=0 auid=1000 exe="/tmp/demo-helper"',
             f'type=EOE msg=audit({now:.3f}:21):']
    return "\n".join(rows) + "\n"
