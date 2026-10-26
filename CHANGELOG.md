# Changelog

All notable changes to this pack are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-10-26

- Initial public release.
- Rules **101400** (reverse/bind shell via nc/socat), **101403** (auditd disabled / rules
  purged), **101404** (cryptominer binary), **101410** (UniFi IPS critical/high not blocked),
  **101420** (TrueNAS audit/syslog/alert config change), **101430** (`/boot` kernel/bootloader
  change).
- Rules **101435** (system clock changed via auditd key `time-change`, T1070.006) and
  **101436** (legitimate time daemons de-rated to L1).
- Rule **100362** (5 successful sudo-to-root by the same user in 60 s; `<same_srcuser />`).
- Rules **101500–101502**: wazuh-authd agent-enrollment monitoring from the manager's own
  `ossec.log` (failed/unauthorized enrollment L12, new agent accepted L10).
- Rules **101451–101453**: Suricata malicious category (L12), high-confidence ET signature
  class (L12), scan/recon category (L10), children of stock `86601`. No severity-to-level
  mapping by design.
- Spamhaus DROP rules **100234–100237** (allowed UniFi flow from/to a listed network, successful
  SSH login, web request) on CDB list `etc/lists/spamhaus-drop`.
- `feeds/refresh_spamhaus_drop.py`: DROP → dotted-prefix CDB keys (Wazuh `address_match_key`
  does not match CIDR keys), written to a file or uploaded via the Wazuh API; refuses an
  empty/implausible download. Standard library only.
- README: cross-pack parents (auditd `200111`, wazuh-unifi `100310`/`100320`,
  wazuh-truenas `100345`, stock `80700`/`5402`/`86601`), behaviour when a parent is missing,
  load order, list declaration; `time-change` audit rules, manager `ossec.log` and Suricata
  eve.json collection snippets.
