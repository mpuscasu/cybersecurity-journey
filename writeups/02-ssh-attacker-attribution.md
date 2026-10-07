# From Raw Logs to Attribution: Profiling SSH Attackers

**Date:** October 2026
**Environment:** Oracle Cloud (ARM VM), Oracle Linux 9, public IPv4
**Tools:** grep, awk, sort, uniq, fail2ban, whois
**Follow-up to:** 01-ssh-bruteforce-analysis

## 1. Goal

A few days after my first analysis, I went back to the same server to answer
three questions with the logs alone:

1. How many attacks are hitting the box now, and from where?
2. Which usernames are attackers trying?
3. Who actually *owns* the most aggressive source IP?

This write-up documents the method as much as the result, because the method
is what transfers to any other system.

## 2. A surprise: "Failed password" does not exist here

My instinct was to grep for the classic failure line:

    sudo grep "Failed password" /var/log/secure

**It returned nothing but my own sudo commands.** The reason is important:
this server has password authentication disabled (key-only SSH), so no one
ever reaches the password stage. The attack fails earlier, and leaves a
different signature.

**Lesson:** an attack's signature depends on the system's configuration.
Always read the log first (`tail`) to see what is actually written, then
build the filter — don't assume.

The real signature on this host is `Invalid user`:

    sudo grep -c "Invalid user" /var/log/secure
    # 1204 attempts

## 3. Building the analysis pipeline

I built the query incrementally, one pipe stage at a time, to understand each
step instead of copying a one-liner.

Final command (top source IPs):

    sudo grep " Invalid user " /var/log/secure \
      | grep sshd \
      | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
      | sort | uniq -c | sort -rn | head -10

Why each stage:

- `grep " Invalid user " /var/log/secure` — the real attack lines (file given once, on the first grep)
- `grep sshd` — keep only sshd lines, dropping my own sudo-logged commands (noise source #1)
- `awk '… if($i=="from") print $(i+1)'` — print the field **after** the word `from`. Robust to field shifts: on lines with an empty username the IP is not at a fixed column, so a hard-coded `$10` returns the word `port` instead (noise source #2). Keying off `from` fixes this.
- `sort | uniq -c | sort -rn` — group, count, rank descending

### Top source IPs

| Attempts | IP |
|---|---|
| 225 | 2.57.122.53 |
| 162 | 38.250.161.179 |
| 56 | 2.57.122.238 |
| 27 | 2.57.121.25 |
| 24 | 45.195.231.146 |
| 20 | 2.57.121.112 |
| 19 | 193.46.255.86 |
| 17 | 94.154.43.63 |
| 10 | 195.178.110.232 |

Three of the top entries sit in the **2.57.12x** range — the same network
flagged in my first write-up. A persistent actor.

### Top attempted usernames

Same pipeline, printing the field **before** `from` (`$(i-1)`):

| Attempts | Username | Likely target |
|---|---|---|
| 160 | admin | default credentials |
| 75 | user | generic |
| 66 | (blank) | empty-password accounts |
| 59 | debian | default cloud image user |
| 58 | config | network/IoT devices |
| 54 | centos | default cloud image user |
| 51 | ubnt | Ubiquiti devices (factory default) |
| 48 | test | generic |
| 48 | support | vendor accounts |
| 46 | guest | generic |

A generic dictionary, not a targeted attack: none of these is the server's
real user (`opc`).

## 4. Attribution: who owns the top attacker?

I installed `whois` and looked up the #1 IP:

    sudo dnf install -y whois
    whois 2.57.122.53

Key fields:

    inetnum:      2.57.122.0 - 2.57.122.255
    netname:      DMZHOSTdotco
    descr:        https://dmzhost.co
    country:      NL
    org-name:     TECHOFF SRV LIMITED  (GB)
    abuse-mailbox: dmzhostabuse@gmail.com

What this tells me:

1. **It's a rented VPS, not a home user.** The IP belongs to a hosting
   provider (DMZHOST). The attacker paid for a server and uses it as a weapon.
   So "which country" is the wrong question — the server is in NL, the company
   in GB, and the operator could be anywhere. The IP shows the location of the
   *tool*, not the person.
2. **DMZHOST markets offshore/anonymous hosting** — the kind favoured for abuse
   because it asks few questions.
3. **Red flag — the abuse contact is a @gmail.com address.** A reputable
   provider uses a corporate abuse mailbox. A Gmail abuse contact is typical of
   low-reputation hosting that ignores abuse reports. Reporting there would
   likely go unanswered.

This is infrastructure attribution: turning a raw IP into an understanding of
who operates it and how trustworthy they are.

## 5. Mitigation

- **fail2ban** is active (24h snapshot: 412 failed auth events, 11 IPs banned).
  It applies temporary, incrementing bans.
- Because the entire `2.57.122.0/24` block belongs to the same abusive
  provider and generated the bulk of the traffic, a **permanent /24 firewall
  drop** is justified rather than banning one IP at a time:

      sudo firewall-cmd --permanent \
        --add-rich-rule='rule family="ipv4" source address="2.57.122.0/24" drop'
      sudo firewall-cmd --reload

## 6. Lessons learned

1. Read the log before writing the filter — the attack signature depends on the
   system (no `Failed password` here, because passwords are disabled).
2. Fixed field positions (`$10`) are fragile; key off a landmark word (`from`)
   to survive line-structure variations.
3. Give the file once, on the first command; after a pipe, commands read from
   the pipe, not from a filename.
4. An IP is not a person. `whois` reveals the hosting provider behind it, and
   the quality of the provider (e.g. a Gmail abuse contact) is itself a signal.
5. When one network is responsible for most of the abuse, block the network,
   not the individual addresses.

## 7. Next steps

- [ ] Apply the permanent /24 block and confirm the drop in `Invalid user` events
- [ ] Repeat the whois attribution for the #2 source (38.250.161.179)
- [ ] Set `PermitRootLogin no` (currently key-only)
- [ ] Forward logs to a SIEM (Wazuh) for ongoing alerting
