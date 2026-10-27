# High-Value Threat Detection Rules for Wazuh

A **deliberately small** set of cross-domain, high-confidence attacker detections for Wazuh 4.x
that fire on everyday telemetry (auditd, sudo, UniFi CEF/firewall, TrueNAS audit, syscheck, sshd,
web access logs, Suricata eve.json, the manager's own `ossec.log`), plus **Spamhaus DROP** matching
with a ready-to-run list refresher.

> **Design principle:** this is **not** a "re-rate every stock rule to the alert gate" pack. It is
> scoped for a small team that has to triage every page — each rule here is something you'd want
> to be **paged** about: an interactive foothold, the audit system being disabled, an active
> (un-blocked) intrusion, a bootkit, an *allowed* connection with a hijacked network, clock
> tampering, a sudo burst, a rogue agent enrollment or a malicious network-IDS signature. All are
> rare and low-FP. No visibility-only or "unsilence the stock rule" alerts.

> **Home-grown** — not part of the stock Wazuh ruleset. Companion packs:
> [wazuh-unifi](https://github.com/secopsxsaiyan/wazuh-unifi),
> [wazuh-truenas](https://github.com/secopsxsaiyan/wazuh-truenas),
> [wazuh-proxmox](https://github.com/secopsxsaiyan/wazuh-proxmox),
> [wazuh-misp-ioc](https://github.com/secopsxsaiyan/wazuh-misp-ioc),
> [wazuh-fim-escalation](https://github.com/secopsxsaiyan/wazuh-fim-escalation),
> [wazuh-windows](https://github.com/secopsxsaiyan/wazuh-windows).

## Layout

```
custom_rules/zz_threat_detection_rules.xml   # all rules (keep the zz_ prefix — see "Load order")
feeds/refresh_spamhaus_drop.py               # Spamhaus DROP -> CDB list refresher (stdlib only)
```

## Rules

| ID | Level | Detects | Parent (telemetry) | MITRE |
|----|-------|---------|--------------------|-------|
| 101400 | 13 | Reverse/bind shell — `nc`/`ncat`/`netcat`/`socat` spawned with an exec/connect flag | `200111` auditd EXECVE | T1059.004 |
| 101403 | 13 | Auditd disabled or rules purged (`auditctl -D` / `-e`) — SIEM evasion | `200111` auditd EXECVE | T1562.012 |
| 101404 | 12 | Cryptominer by binary name (xmrig, kinsing, kdevtmpfsi, minerd, …) | `200111` auditd EXECVE | T1496 |
| 101410 | 14 | UniFi IPS **CRITICAL/HIGH** signature **NOT blocked** — active intrusion | `100310` UniFi CEF IPS | T1190 |
| 101420 | 10 | TrueNAS audit/syslog/alert configuration changed — SIEM blinding | `100345` TrueNAS audit | T1562.006 |
| 101430 | 12 | `/boot` kernel or bootloader file changed — bootkit/kernel tamper | `550/553/554` syscheck | T1601, T1542 |
| 101435 | 10 | System clock changed (auditd key `time-change`) by anything but a time daemon — forensic timestamp tampering | `80700` auditd (stock) | T1070.006 |
| 101436 | 1 | Clock change by a legitimate time daemon (`chronyd`, `systemd-timesyncd`, `ntpd`, `ntpdate`, `hwclock`, `systemd`) — de-rated child of 101435 | `101435` | — |
| 100362 | 10 | Sudo burst — 5 successful sudo-to-root by the **same user** in 60 s | `5402` sudo (stock) | T1548.003 |
| 101500 | 3 | `wazuh-authd` (agent enrollment) message — grouping rule | top-level match on the manager's `ossec.log` | — |
| 101501 | 12 | Failed/unauthorized agent enrollment (invalid password, rejected request, …) — rogue-agent registration | `101500` | T1200 |
| 101502 | 10 | **New** agent registration accepted — verify it is expected | `101500` | T1200 |
| 101451 | 12 | Suricata alert in a malicious category (Trojan, Malware, Exploit, C2, Coin Miner, Worm, Exfiltration, …) | `86601` Suricata alert (stock) | T1190 |
| 101452 | 12 | Suricata high-confidence ET signature class (`ET MALWARE/TROJAN/EXPLOIT/CNC/WORM/ATTACK_RESPONSE/MOBILE_MALWARE`) | `86601` Suricata alert (stock) | — |
| 101453 | 10 | Suricata scan/recon category (Network Scan, Attempted Information Leak, Potentially Bad Traffic) | `86601` Suricata alert (stock) | T1046 |
| 100234 | 12 | Spamhaus DROP: **allowed** UniFi firewall flow **from** a listed network | `100320` UniFi firewall | — |
| 100235 | 12 | Spamhaus DROP: **allowed** UniFi firewall flow **to** a listed network | `100320` UniFi firewall | — |
| 100236 | 12 | Spamhaus DROP: **successful SSH login** from a listed network | `5715` sshd (stock) | — |
| 100237 | 12 | Spamhaus DROP: web request from a listed network | `31100`, `31108` web access log (stock) | — |

`101410` fires for **every** unblocked critical/high IPS signature, whatever its category — this
pack does not de-rate or allow-list any signature class.

## Cross-pack parents (requirements)

Several rules are children (`if_sid`) of rules that live in **other** packs:

| Parent | Provided by | Used by | Notes |
|--------|-------------|---------|-------|
| `200111` | an external auditd ruleset's EXECVE grouping rule (not included) | 101400, 101403, 101404 | optional — or use the stock parent, see below |
| `100310` | [wazuh-unifi](https://github.com/secopsxsaiyan/wazuh-unifi) (IPS/IDS detected, not blocked) | 101410 | UniFi "SIEM Server" CEF feed |
| `100320` | [wazuh-unifi](https://github.com/secopsxsaiyan/wazuh-unifi) (gateway iptables firewall syslog) | 100234, 100235 | needs the `unifi.fw_action` field (A/D/R) |
| `100345` | [wazuh-truenas](https://github.com/secopsxsaiyan/wazuh-truenas) (TNAUDIT middleware audit) | 101420 | |
| `550/553/554`, `5715`, `31100`, `31108` | stock Wazuh ruleset | 101430, 100236, 100237 | always present |
| `80700` | stock Wazuh ruleset (auditd) | 101435 (→ 101436) | needs the `time-change` audit rules, see below |
| `5402` | stock Wazuh ruleset (sudo to root) | 100362 | always present |
| `86601` | stock Wazuh ruleset (Suricata `event_type=alert`) | 101451, 101452, 101453 | needs Suricata eve.json collected, see below |
| — (top-level `<match>wazuh-authd:</match>`) | this pack (101500) | 101501, 101502 | needs the manager's own `ossec.log` collected, see below |

TrueNAS **storage health** (ZFS pool degraded/faulted, zed checksum/IO errors, SMART) is covered by
[wazuh-truenas](https://github.com/secopsxsaiyan/wazuh-truenas), not by this pack.

### If a parent is missing

Nothing breaks. analysisd logs a warning for each orphaned child at start-up, ignores **only that
rule**, and loads everything else (verified on Wazuh 4.14.5):

```
wazuh-analysisd: WARNING: (7617): Signature ID '100310' was not found and will be ignored in the 'if_sid' option of rule '101410'.
wazuh-analysisd: WARNING: (7619): Empty 'if_sid' value. Rule '101410' will be ignored.
```

If only *some* IDs of a multi-parent `if_sid` are missing, only those IDs are dropped (`7617`) and
the rule stays active on the remaining parents. So you can install this pack without UniFi or
TrueNAS — the corresponding rules simply stay inert (and the warnings disappear once the parent
pack is installed). To silence the warnings permanently, delete the rules you can't use.

### Load order

Wazuh loads rule files **alphabetically** and resolves `if_sid` at load time: a child whose
parent file loads *later* is dropped with the warnings above. The file is named
`zz_threat_detection_rules.xml` so it loads **after** any auditd ruleset, `truenas_rules.xml` and
`unifi_rules.xml`. **Keep the `zz_` prefix** (or otherwise guarantee this file loads last).

### auditd parent `200111`

101400/101403/101404 chain off `200111`, an EXECVE grouping rule that some external auditd rulesets
provide. On stock Wazuh 4.x, auditd events decode under stock rule `80700`, and an auditd ruleset
whose base rules match `<decoded_as>auditd-*</decoded_as>` never fires (no stock decoder emits those
values), so `200111` must itself chain off `80700` (`<if_sid>80700</if_sid>` +
`<field name="audit.type">^EXECVE$</field>`). If you don't run such a ruleset, edit the three rules
in this pack to use the stock parent directly:

```xml
<if_sid>80700</if_sid>
<field name="audit.type">^EXECVE$</field>
```

auditd must also log `execve` (e.g. `-a always,exit -F arch=b64 -S execve -k audit-wazuh-c`; the
[wazuh-proxmox](https://github.com/secopsxsaiyan/wazuh-proxmox) pack ships a complete
`audit-rules/99-wazuh-mitre.rules`), and the agent must read `/var/log/audit/audit.log`
(`<log_format>audit</log_format>`).

## Clock tampering (101435 / 101436)

`101435` fires on any auditd event tagged with the key `time-change`; `101436` de-rates the
legitimate time sources to level 1, so only a clock change by anything else (an interactive
`date -s`, a custom binary calling `settimeofday`) reaches level 10. Nothing tags those syscalls by
default — add an auditd rule on each Linux host (e.g. `/etc/audit/rules.d/99-time-change.rules`,
then `augenrules --load`):

```
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
```

The [wazuh-proxmox](https://github.com/secopsxsaiyan/wazuh-proxmox) pack's
`audit-rules/99-wazuh-mitre.rules` already ships these lines (it additionally drops the `_chrony`
user's syscalls at the kernel). The agent must read `/var/log/audit/audit.log`
(`<log_format>audit</log_format>`). If your hosts sync time with a daemon not listed in `101436`,
add its executable to that rule's `audit.exe` pattern.

## Sudo burst (100362)

Five successful sudo-to-root commands (stock `5402`) by one user within 60 seconds. Correlation
uses `<same_srcuser />`, which compares the invoking user. Two look-alikes do **not** work and were
rejected after `wazuh-logtest` on 4.14.5:

- `<same_user />` compares the *target* user (`root` for every event), so five different users each
  running one sudo would fire it.
- `<same_field>data.srcuser</same_field>` never matches: `srcuser` is a static field, not a dynamic
  `data.*` field.

A user's first-ever sudo is claimed by stock `5403` ("First time user executed sudo") and is not
counted. If you run automation that sudoes in loops under a dedicated account, exclude that account
rather than raising the threshold.

## Agent enrollment monitoring (101500–101502)

`wazuh-authd` logs every enrollment request to the manager's own `/var/ossec/logs/ossec.log`, which
the manager does not analyse by default. Add this to the **manager's** `ossec.conf` (not an agent):

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/ossec/logs/ossec.log</location>
</localfile>
```

`ossec.log` lines (`2026/10/26 20:35:55 wazuh-authd: ERROR: ...`) are not syslog-formatted, so the
program-name pre-decoder can't be relied on; `101500` matches the raw `wazuh-authd:` tag instead and
groups every authd line at level 3.

- `101501` (L12) — `Invalid password`, `Unable to add agent`, rejected/unauthorized/denied requests:
  someone tried to enroll without the right credentials. Duplicate-name rejections are deliberately
  not matched (community rulesets already cover them) and stay at `101500`.
- `101502` (L10) — `Received request for a new agent` / `Agent key generated`: an agent was
  registered. Enrollment should be **rare** (new hosts, re-installs); one you didn't plan is the
  signal. Expect it to fire during a planned roll-out. Pair it with an enrollment password
  (`<use_password>yes</use_password>` in `<auth>`) so unauthenticated attempts land in `101501`.

## Suricata network IDS (101451–101453)

Children of stock `86601` (Suricata `event_type=alert`, level 3). They raise only malicious-intent
categories (`101451`), high-confidence Emerging Threats signature classes (`101452`) and scan/recon
categories (`101453`); everything else stays at `86601` level 3. Collect Suricata's eve.json on the
sensor's agent:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

A plain `alert.severity` → level mapping is intentionally **not** included: Suricata marks many
policy/informational signatures (e.g. `ET INFO`) as severity 1, so a severity re-rate floods triage
without adding detections. The category and signature-class matches above are the signal.

## Spamhaus DROP

[Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) ("Don't Route Or
Peer") lists netblocks hijacked or leased by professional spam/cyber-crime operations. No
legitimate traffic should come from them, so an **allowed** flow, a **successful** SSH login or a
web request from one is worth a page. Dropped flows (`fw_action` D) are already handled and do not
match.

### 1. Declare the list in `ossec.conf`

```xml
<ruleset>
  ...
  <list>etc/lists/spamhaus-drop</list>
</ruleset>
```

Every declared list must exist before the manager starts (an empty file is fine):

```bash
f=/var/ossec/etc/lists/spamhaus-drop; [ -e "$f" ] || { touch "$f"; chown wazuh:wazuh "$f"; }
```

### 2. Populate it — `feeds/refresh_spamhaus_drop.py`

Wazuh 4.x `address_match_key` matches an IP against keys of the form `a.`, `a.b.`, `a.b.c.` and
`a.b.c.d` — it does **not** match CIDR keys (`198.18.16.0/20:` never matches; verified on 4.14.5).
The script downloads DROP, keeps the IPv4 networks and expands each to exact octet-boundary
prefix keys (a `/20` becomes 16 `/24` keys, a `/15` two `/16` keys). A typical run turns ~1,700
networks into ~13,000 keys. It refuses a download outside 50–5,000 networks, so a bad fetch can't
wipe the list. Python 3 standard library only.

Write the file directly on the manager host:

```bash
SPAMHAUS_OUTPUT_FILE=/var/ossec/etc/lists/spamhaus-drop python3 feeds/refresh_spamhaus_drop.py
```

…or upload through the Wazuh API (works for remote / containerised managers):

```bash
export WAZUH_API=https://<WAZUH MANAGER>:55000
export WAZUH_USER=<API USER>            # an account allowed to PUT /lists/files
export WAZUH_PASS_FILE=/root/.wazuh-api-pass   # or WAZUH_PASS=...; keep the file 0600
export WAZUH_INSECURE=1                  # only for the default self-signed API certificate
python3 feeds/refresh_spamhaus_drop.py
```

| Var | Default | Meaning |
|-----|---------|---------|
| `SPAMHAUS_OUTPUT_FILE` | — | write the list to this path (file mode) |
| `WAZUH_API` / `WAZUH_USER` / `WAZUH_PASS` / `WAZUH_PASS_FILE` | — / `wazuh-wui` / — / — | API mode |
| `WAZUH_CA_BUNDLE` / `WAZUH_INSECURE` | — / `0` | API TLS verification |
| `SPAMHAUS_DROP_URL` | `https://www.spamhaus.org/drop/drop_v4.json` | feed URL (the legacy text `drop.txt` also works until Spamhaus retires it) |
| `LIST_NAME` | `spamhaus-drop` | CDB list name |
| `MIN_NETS` / `MAX_NETS` | `50` / `5000` | sanity bounds |
| `DRY_RUN` | `0` | `1` = fetch, convert and print a summary only |

analysisd only (re)loads CDB lists when it starts, so **restart the manager after a refresh**.
DROP changes slowly; once a day is plenty (never poll more often than hourly):

```cron
# /etc/cron.d/spamhaus-drop (manager host)
17 4 * * * root SPAMHAUS_OUTPUT_FILE=/var/ossec/etc/lists/spamhaus-drop /usr/bin/python3 /opt/wazuh-threat-detection/feeds/refresh_spamhaus_drop.py && /var/ossec/bin/wazuh-control restart
```

Check the [Spamhaus DROP terms of use](https://www.spamhaus.org/drop/terms/)
before using the feed in your environment.

## Scope & honest limits

- **Reverse shells:** auditd `execve` cleanly exposes the `nc`/`socat` exec-flag forms (single-token
  args). It does **not** reliably expose `bash -i >& /dev/tcp/...` (a bash redirection, not an
  execve arg) or `python -c '<payload>'` (auditd hex-encodes the quoted payload). Comprehensive
  shell-spawn detection needs eBPF `connect()` telemetry (Tetragon/Falco) — out of scope here.
- **auditctl:** `101403` also fires on `auditctl -e 1`/`-e 2` (the value is a separate argument).
  If your own audit-rule reload runs `auditctl -D`, scope the rule to interactive sessions
  (`audit.auid` ≥ 1000) or to your change window.
- **Cryptominer:** matches known miner binary names; fully-renamed miners evade name-matching but
  surface via the pool's stratum connection and CPU anomalies (defense in depth).
- **/boot:** kernel package updates legitimately touch `/boot` — an alert during a known `apt`/`dnf`
  upgrade is benign; one outside an update window is the signal. `/boot` must be in the agent's
  syscheck `<directories>` (it is in the default Linux agent config).
- **Spamhaus:** IPv4 only (DROP's IPv6 list is not used); `100237` needs a decoder that sets
  `srcip` on the access log (stock Apache/Nginx decoders do).

## Install

```bash
cp custom_rules/zz_threat_detection_rules.xml /var/ossec/etc/rules/
chmod 0644 /var/ossec/etc/rules/zz_threat_detection_rules.xml
chown wazuh:wazuh /var/ossec/etc/rules/zz_threat_detection_rules.xml

# confirm the ID ranges are free on your manager (expect empty):
grep -rhoE --exclude=zz_threat_detection_rules.xml \
  'rule id="(10140[0-4]|101410|101420|101430|10143[56]|10145[1-3]|10150[0-2]|100362|10023[4-7])"' \
  /var/ossec/etc/rules/ /var/ossec/ruleset/rules/

# declare + create the spamhaus-drop list (see above), then:
/var/ossec/bin/wazuh-analysisd -t        # config/ruleset test
/var/ossec/bin/wazuh-control restart     # or force-recreate for single-file bind mounts
grep -E "WARNING|ERROR" /var/ossec/logs/ossec.log | grep -E "rule '(1014|1015|10023|100362)"   # orphaned children, if any
```

Verify with `wazuh-logtest`:

```bash
printf 'type=EXECVE msg=audit(1700000000.123:456): argc=3 a0="nc" a1="-e" a2="/bin/sh"\n' \
  | /var/ossec/bin/wazuh-logtest        # -> 101400, level 13 (needs parent 200111)

printf 'type=SYSCALL msg=audit(1700000000.123:457): arch=c000003e syscall=227 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid=2201 pid=2250 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="date" exe="/usr/bin/date" key="time-change"\n' \
  | /var/ossec/bin/wazuh-logtest        # -> 101435, level 10 (exe=/usr/sbin/chronyd -> 101436, level 1)

printf '2026/10/26 20:35:55 wazuh-authd: ERROR: Invalid password provided by 192.0.2.10. Closing connection.\n' \
  | /var/ossec/bin/wazuh-logtest -l /var/ossec/logs/ossec.log   # -> 101501, level 12
```

> If you mount the rule file as a **single-file Docker bind mount**, an in-place editor replaces the
> inode and the container keeps serving the old content on a plain restart. Use
> `docker compose up -d --force-recreate <manager>` to re-resolve the mount.

## ID range / collisions

Uses **101400-101453** (101400, 101403, 101404, 101410, 101420, 101430, 101435, 101436,
101451-101453), **101500-101502**, **100362** and **100234-100237** — clear of stock Wazuh and the
other secopsxsaiyan packs (`wazuh-misp-ioc` uses 100210-100233, `wazuh-fim-escalation` 101440-101441,
`wazuh-proxmox` 101511). Verify they are also free on your manager before installing.

## License

MIT — see [LICENSE](LICENSE).
