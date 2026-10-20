"""Build additive rules as an ordinary user; never install or load them.

Collection categories informed by https://github.com/Neo23x0/auditd/blob/master/audit.rules.
This is an Arch/Omarchy adaptation, not an upstream ruleset replacement.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform


# Existing Omarchy identity/sudo/systemd/module rules remain authoritative;
# Skidplate recognizes their existing keys instead of duplicating those watches.
WATCHES = (
    ("/etc/audit", "sentinel_audit_config"),
    ("/etc/libaudit.conf", "sentinel_audit_config"),
    ("/etc/pacman.conf", "sentinel_pacman_config"),
    ("/etc/pacman.d", "sentinel_pacman_config"),
    ("/usr/share/libalpm/hooks", "sentinel_pacman_config"),
    ("/etc/pam.d", "sentinel_auth_policy"),
    ("/etc/security", "sentinel_auth_policy"),
    ("/etc/polkit-1", "sentinel_auth_policy"),
    ("/etc/login.defs", "sentinel_auth_policy"),
    ("/etc/subuid", "identity_changes"),
    ("/etc/subgid", "identity_changes"),
    ("/etc/nsswitch.conf", "identity_changes"),
    ("/etc/apparmor.d", "sentinel_mac_policy"),
    ("/etc/apparmor", "sentinel_mac_policy"),
    ("/etc/ssh", "sentinel_auth_policy"),
    ("/etc/sysctl.d", "sentinel_kernel_config"),
    ("/etc/sysctl.conf", "sentinel_kernel_config"),
    ("/etc/modprobe.d", "sentinel_kernel_config"),
    ("/etc/modules-load.d", "sentinel_kernel_config"),
    ("/etc/NetworkManager", "sentinel_network_config"),
    ("/etc/hosts", "sentinel_network_config"),
    ("/etc/hostname", "sentinel_network_config"),
    ("/etc/nftables.conf", "sentinel_network_config"),
    ("/etc/iptables", "sentinel_network_config"),
    ("/etc/udev/rules.d", "sentinel_persistence"),
    ("/etc/profile", "sentinel_persistence"),
    ("/etc/profile.d", "sentinel_persistence"),
    ("/etc/environment", "sentinel_persistence"),
    ("/etc/shells", "sentinel_persistence"),
    ("/etc/cron.d", "sentinel_persistence"),
    ("/etc/cron.daily", "sentinel_persistence"),
    ("/var/spool/cron", "sentinel_persistence"),
    ("/etc/crontab", "sentinel_persistence"),
    ("/etc/fstab", "sentinel_persistence"),
    ("/etc/ld.so.conf", "sentinel_system_files"),
    ("/etc/ld.so.conf.d", "sentinel_system_files"),
    ("/etc/ld.so.preload", "sentinel_system_files"),
    ("/usr/local/bin", "sentinel_system_files"),
    ("/usr/local/lib/systemd", "sentinel_persistence"),
    ("/boot", "sentinel_system_files"),
)

DNS_WATCHES = (
    "/etc/hosts", "/etc/nsswitch.conf", "/etc/resolv.conf",
    "/etc/systemd/resolved.conf", "/etc/systemd/resolved.conf.d",
    "/etc/NetworkManager/NetworkManager.conf", "/etc/NetworkManager/conf.d",
    "/etc/NetworkManager/system-connections", "/etc/NetworkManager/dnsmasq.d",
    "/etc/systemd/network",
)


def build_dns(root=Path("/"), architectures=("b64", "b32")):
    rules, skipped = [], []
    for relative in DNS_WATCHES:
        path = root / relative.lstrip("/")
        if not path.exists() or path.is_symlink():
            skipped.append(relative)
            continue
        field = "dir" if path.is_dir() else "path"
        for arch in architectures:
            # Prepend so broader already-live /etc/NM watches cannot mask keys.
            rules.append(f"-A always,exit -F arch={arch} -F {field}={relative} -F perm=wa -k sentinel_dns_config")
    return rules, skipped


def build(root=Path("/"), architectures=("b64", "b32"), home=None):
    home = str(Path.home()) if home is None else str(home)
    if not home.startswith('/') or any(c.isspace() for c in home) or any(c not in '/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-' for c in home) or '..' in Path(home).parts:
        raise ValueError('Audit rule home must be an absolute simple path without whitespace or parent traversal')
    rules, skipped = [], []
    user_watches = tuple((home.rstrip('/') + '/' + name, key) for name, key in (
        ('.config/systemd/user', 'sentinel_persistence'), ('.config/autostart', 'sentinel_persistence'), ('.ssh', 'sentinel_auth_policy')))
    for relative, key in WATCHES + user_watches:
        path = root / relative.lstrip("/")
        if not path.exists() or path.is_symlink():
            skipped.append(relative)
            continue
        field = "dir" if path.is_dir() else "path"
        for arch in architectures:
            rules.append(f"-a always,exit -F arch={arch} -F {field}={relative} -F perm=wa -k {key}")
    for arch in architectures:
        # libaudit's i386 table names syscall 283 sys_kexec_load. Fuzzy
        # ausyscall lookup also matches kexec_load, but auditctl requires exact.
        kexec_call = "sys_kexec_load" if arch == "b32" else "kexec_load"
        syscall_rules = [
            # No auid restriction here: root/system-service abuse matters too.
            f"-a always,exit -F arch={arch} -S execve,execveat -F euid=0 -k sentinel_root_exec",
            # Include EINPROGRESS so asynchronous connection attempts are visible.
            f"-a always,exit -F arch={arch} -S connect -F saddr_fam=2 -k sentinel_connect",
            f"-a always,exit -F arch={arch} -S connect -F saddr_fam=10 -k sentinel_connect",
            f"-a always,exit -F arch={arch} -S ptrace,process_vm_readv,process_vm_writev -k tracing",
            f"-a always,exit -F arch={arch} -S bpf -k bpf",
            f"-a always,exit -F arch={arch} -S {kexec_call} -k KEXEC",
            f"-a always,exit -F arch={arch} -S memfd_create,unshare,setns,pivot_root,io_uring_setup,userfaultfd -k sentinel_kernel_surface",
            f"-a always,exit -F arch={arch} -S mount,umount2,move_mount,open_tree,fsopen,fsconfig,fsmount -F auid>=1000 -F auid!=unset -k sentinel_mount",
            # Permission-denied evidence, avoiding routine ENOENT desktop noise.
            f"-a always,exit -F arch={arch} -S open,openat,openat2,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k sentinel_access_denied",
            f"-a always,exit -F arch={arch} -S open,openat,openat2,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k sentinel_access_denied",
        ]
        for tool, key in (("/usr/bin/pacman", "sentinel_pacman_exec"),
                          ("/usr/bin/sudo", "sentinel_privilege_tool"),
                          ("/usr/bin/su", "sentinel_privilege_tool"),
                          ("/usr/bin/pkexec", "sentinel_privilege_tool"),
                          ("/usr/bin/setcap", "sentinel_privilege_tool")):
            if (root / tool.lstrip("/")).is_file():
                rules.append(f"-a always,exit -F arch={arch} -F path={tool} -F perm=x -k {key}")
        # Specific executable watches precede generic root execution: first
        # match supplies the key, while root detections work independently of it.
        rules.extend(syscall_rules)
        # Parent fallback observes creation of currently absent files, including
        # ld.so.preload. Specific/Omarchy watches must precede this broad rule.
        rules.append(f"-a always,exit -F arch={arch} -F dir=/etc -F perm=wa -k sentinel_config_change")
    rules.append("-a always,exit -F arch=b64 -S kexec_file_load -k KEXEC")
    return rules, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[1] / "build/audit")
    parser.add_argument('--home', default=str(Path.home()), help='Home directory to include in the draft')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Generate as your normal user; this tool never needs root")
    if platform.machine() != "x86_64":
        parser.error("This draft generator targets x86_64 Arch Linux; review ABI/syscall support on other systems")
    uid_min = next((line.split()[1] for line in Path("/etc/login.defs").read_text().splitlines()
                    if line.split()[:1] == ["UID_MIN"]), None)
    if uid_min != "1000":
        parser.error("UID_MIN differs from the reviewed 1000; review user filters before generating")
    rules, skipped = build(home=args.home)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    header = ("# Arch/Omarchy Skidplate additive collection profile.\n"
              "# Review with docs/audit-collection.md before installing.\n"
              "# No reset, suppression, ignored errors, panic, rate or immutable directives.\n"
              "# Existing 50-omarchy-security.rules must remain installed.\n"
              "# b64 + direct b32 calls; legacy i386 socketcall is not covered.\n"
              "# Absent/symlink paths skipped on this host: " + ", ".join(skipped) + "\n")
    (args.output_dir / "60-skidplate.rules").write_text(header + "\n".join(rules) + "\n")
    # Exact removals, not auditctl -D: preserve every pre-existing live rule.
    (args.output_dir / "60-skidplate.rollback").write_text(
        "# Remove only this exact overlay from the live kernel.\n" +
        "\n".join(line.replace("-a always,exit", "-d always,exit", 1) for line in reversed(rules)) + "\n")
    dns_rules, dns_skipped = build_dns()
    (args.output_dir / "40-skidplate-dns.rules").write_text(
        "# Persistent DNS-related configuration watches only; no transient /run watches.\n"
        "# Prepend before broad watches. Skipped absent/symlink paths: " + ", ".join(dns_skipped) + "\n" +
        "\n".join(dns_rules) + "\n")
    (args.output_dir / "40-skidplate-dns.rollback").write_text(
        "# Exact DNS overlay removals, never a global reset.\n" +
        "\n".join(line.replace("-A always,exit", "-d always,exit", 1) for line in reversed(dns_rules)) + "\n")
    print(f"Prepared {len(rules)} additive rules and exact rollback; skipped {len(skipped)} absent/symlink paths.")
    print(f"Prepared {len(dns_rules)} persistent DNS watches and exact rollback; skipped {len(dns_skipped)} absent/symlink paths.")


if __name__ == "__main__":
    main()
