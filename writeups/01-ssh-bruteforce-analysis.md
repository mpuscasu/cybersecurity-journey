# SSH Brute-Force Analysis on a Fresh Cloud Server

**Date:** October 2026
**Environment:** Oracle Cloud (ARM VM), Oracle Linux 9, public IPv4, no domain name
**Exposed ports:** 22 (SSH), 80/443 (HTTP/S)
**Tools:** grep, awk, sort, uniq, sshd, fail2ban, firewalld

## 1. Context

I provisioned a new cloud server and, about 24 hours later, checked its
authentication logs to see whether it had already been targeted. The server
had no domain name and had not been announced anywhere, so any activity
would come from automated internet-wide scanning.

## 2. Observation

Counting failed authentication events in `/var/log/secure`:

    sudo grep -c "Invalid user\|Failed password\|authentication failure" /var/log/secure

**Result: 548 matching log lines in ~24 hours.**
(One connection attempt can produce more than one log line, so this is an
upper bound on attempts, not an exact count.)

### Top source IPs ("Invalid user" events)

    sudo grep "Invalid user" /var/log/secure | awk '{print $(NF-2)}' | sort | uniq -c | sort -rn | head -10

| Attempts | Source IP |
|---|---|
| 225 | 2.57.122.53 |
| 52 | 2.57.122.238 |
| 24 | 45.195.231.146 |
| 10 | 94.154.43.63 |
| 9 | 2.57.122.76 |

### Top attempted usernames

    sudo grep "Invalid user" /var/log/secure | awk '{print $8}' | sort | uniq -c | sort -rn | head -10

| Attempts | Username | Likely target |
|---|---|---|
| 43 | admin | Generic default credentials |
| 41 | ubuntu | Default cloud image user |
| 34 | user | Generic default credentials |
| 23 | config | Network/IoT devices |
| 23 | blank | Accounts with empty passwords |
| 21 | sol | Solana blockchain nodes |
| 20 | server | Generic |
| 20 | debian | Default cloud image user |
| 19 | support | Vendor/support accounts |
| 18 | ubnt | Ubiquiti devices (factory default) |

## 3. Analysis

- **Three of the top five IPs belong to the same /24 network (2.57.122.0/24)**
  and account for ~286 events. This suggests a single actor or a single
  hosting provider used for scanning, rotating IPs to avoid per-IP blocking.
- The username list is a **generic dictionary**, not a targeted attack: it
  covers default cloud users (`ubuntu`, `debian`), network devices (`ubnt`),
  and notably `sol`, which targets Solana validator nodes that may hold
  cryptocurrency wallets.
- **MITRE ATT&CK mapping:** T1595 Active Scanning (reconnaissance) followed by
  T1110 Brute Force (password guessing / spraying across many usernames).

## 4. Existing defenses (verified)

    sudo sshd -T | grep -E "passwordauthentication|permitrootlogin"

    passwordauthentication no
    permitrootlogin without-password

Password authentication is disabled, so **all of these attempts were
guaranteed to fail**: only SSH key authentication is accepted. This is
defense in depth: even a correct password guess would not grant access.

## 5. Mitigation: fail2ban

To reduce noise and resource usage, I deployed fail2ban integrated with
firewalld.

**Issue encountered:** `dnf install fail2ban` failed with "No match for
argument". On Oracle Cloud, the EPEL repository package is installed but the
repo is **disabled by default**. Fix:

    sudo dnf config-manager --enable ol9_developer_EPEL
    sudo dnf install -y fail2ban fail2ban-firewalld

Configuration (`/etc/fail2ban/jail.local`):

    [DEFAULT]
    bantime = 1h
    bantime.increment = true
    findtime = 10m
    maxretry = 5

    [sshd]
    enabled = true

- 5 failures within 10 minutes → 1 hour ban
- `bantime.increment` → repeat offenders get progressively longer bans
- `fail2ban-firewalld` → bans are applied as firewalld rules (one firewall, not two)

## 6. Result

Within seconds of starting the service:

    sudo fail2ban-client status sshd

    Currently failed: 1
    Total failed:     6
    Currently banned: 1
    Banned IP list:   2.57.122.238

The first banned IP belonged to the same 2.57.122.0/24 network identified
in the analysis: the attack was still ongoing, live.

## 7. Lessons learned

1. **Any public IP is scanned within hours.** Obscurity (no domain) provides
   no protection.
2. **Key-only SSH authentication is the most important control.** It made
   the brute-force campaign ineffective regardless of password strength.
3. **Log analysis with basic Unix tools** (grep, awk, sort, uniq) is enough to
   identify attack patterns, sources, and intent.
4. **Per-IP blocking has limits** when attackers rotate IPs within a network.

## 8. Next steps

- [ ] Set `PermitRootLogin no` (currently key-only, but root login is unnecessary)
- [ ] Evaluate blocking 2.57.122.0/24 permanently via a firewalld rich rule
- [ ] Compare with logs from a second server that hosts public websites
- [ ] Centralize logs and alerts with a SIEM (Wazuh)
