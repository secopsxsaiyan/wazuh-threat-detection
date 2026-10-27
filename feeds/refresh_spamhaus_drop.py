#!/usr/bin/env python3
"""Refresh the Wazuh CDB list `spamhaus-drop` from the Spamhaus DROP feed.

Part of https://github.com/secopsxsaiyan/wazuh-threat-detection (rules 100234-100237).

The DROP list holds IPv4 CIDRs. Wazuh 4.x `address_match_key` does not match CIDR keys, so
each network is expanded to dotted-prefix keys on octet boundaries ("198.18.16.", "198.19.",
"10.") which `address_match_key` does match.

Output goes to ONE of:
  * a file      -- set SPAMHAUS_OUTPUT_FILE (e.g. /var/ossec/etc/lists/spamhaus-drop), or
  * the Wazuh API -- set WAZUH_API + WAZUH_USER + WAZUH_PASS (or WAZUH_PASS_FILE);
                    uploads via PUT /lists/files/spamhaus-drop?overwrite=true.

Environment (defaults in brackets):
  SPAMHAUS_DROP_URL     feed URL [https://www.spamhaus.org/drop/drop_v4.json]; the legacy
                        text drop.txt is also understood until Spamhaus retires it
  SPAMHAUS_OUTPUT_FILE  write the list here instead of using the API
  WAZUH_API             e.g. https://wazuh-manager.example:55000
  WAZUH_USER            API user [wazuh-wui]
  WAZUH_PASS            API password
  WAZUH_PASS_FILE       file holding the API password (used if WAZUH_PASS is unset)
  WAZUH_CA_BUNDLE       CA file to verify the API certificate
  WAZUH_INSECURE        "1" = skip API TLS verification (self-signed default certs)
  LIST_NAME             CDB list name [spamhaus-drop]
  MIN_NETS / MAX_NETS   sanity bounds on the parsed network count [50 / 5000]
  DRY_RUN               "1" = fetch + convert + print a summary, write nothing

The manager does NOT need a restart to receive the file, but analysisd only (re)loads CDB
lists when it starts: restart the manager after a refresh (e.g. in the same cron job).

A download outside MIN_NETS..MAX_NETS is refused, so a bad fetch can never wipe the current
list. Credentials are never printed. Standard library only.
"""
import base64
import ipaddress
import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "https://www.spamhaus.org/drop/drop_v4.json"
USER_AGENT = "wazuh-threat-detection/spamhaus-drop-refresh"
TIMEOUT = 60


def parse_networks(text):
    """Return sorted unique IPv4 CIDR strings from a DROP feed (text or JSON-lines form)."""
    out = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                line = str(json.loads(line).get("cidr", ""))
            except (ValueError, AttributeError):
                continue
        else:
            line = line.split(";", 1)[0].strip()
        if not line or "/" not in line or ":" in line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            out.add(str(net))
    return sorted(out, key=lambda n: ipaddress.ip_network(n))


def prefix_keys(nets):
    """Expand CIDRs to dotted-prefix CDB keys on octet boundaries.

    /0-/8 -> "a." per /8, /9-/16 -> "a.b.", /17-/24 -> "a.b.c.", /25-/32 -> one key per
    address ("a.b.c.d"). A /20 becomes 16 /24 keys, a /15 two /16 keys. Expansion is exact:
    no address outside the original network is ever covered.
    """
    out = set()
    for n in nets:
        net = ipaddress.ip_network(n, strict=False)
        p = net.prefixlen
        tgt = 8 if p <= 8 else 16 if p <= 16 else 24 if p <= 24 else 32
        k = tgt // 8
        for sub in net.subnets(new_prefix=tgt):
            octs = str(sub.network_address).split(".")
            out.add(".".join(octs[:k]) + ("." if k < 4 else ""))
    return sorted(out)


def render(keys):
    return "".join(f"{k}:\n" for k in keys)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", "replace")


def write_file(path, payload):
    """Atomic replace in the target directory; keeps the existing file's mode/owner if any."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".spamhaus-drop.", dir=d)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(payload)
        try:
            st = os.stat(path)
            os.chmod(tmp, st.st_mode & 0o7777)
            if hasattr(os, "chown"):
                try:
                    os.chown(tmp, st.st_uid, st.st_gid)
                except PermissionError:
                    pass
        except FileNotFoundError:
            os.chmod(tmp, 0o660)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def ssl_context():
    if os.environ.get("WAZUH_INSECURE") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    cafile = os.environ.get("WAZUH_CA_BUNDLE") or None
    return ssl.create_default_context(cafile=cafile)


def api_password():
    pw = os.environ.get("WAZUH_PASS")
    if pw:
        return pw
    pfile = os.environ.get("WAZUH_PASS_FILE")
    if pfile:
        with open(pfile, encoding="utf-8") as fh:
            return fh.read().strip()
    raise SystemExit("WAZUH_PASS or WAZUH_PASS_FILE is required for API mode")


def push_api(list_name, payload):
    api = os.environ["WAZUH_API"].rstrip("/")
    user = os.environ.get("WAZUH_USER", "wazuh-wui")
    ctx = ssl_context()
    basic = base64.b64encode(f"{user}:{api_password()}".encode()).decode()
    req = urllib.request.Request(
        f"{api}/security/user/authenticate",
        method="POST",
        headers={"Authorization": f"Basic {basic}", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        token = json.load(resp)["data"]["token"]
    url = f"{api}/lists/files/{urllib.parse.quote(list_name)}?overwrite=true"
    req = urllib.request.Request(
        url,
        data=payload.encode(),
        method="PUT",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/octet-stream",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=180, context=ctx) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as exc:
        print(f"API upload failed: HTTP {exc.code} {exc.read()[:200]!r}", file=sys.stderr)
        return False
    if body.get("error", 0) != 0 or body.get("data", {}).get("failed_items"):
        print(f"API upload reported an error: {str(body)[:200]}", file=sys.stderr)
        return False
    return True


def main():
    url = os.environ.get("SPAMHAUS_DROP_URL", DEFAULT_URL)
    list_name = os.environ.get("LIST_NAME", "spamhaus-drop")
    min_nets = int(os.environ.get("MIN_NETS", "50"))
    max_nets = int(os.environ.get("MAX_NETS", "5000"))
    out_file = os.environ.get("SPAMHAUS_OUTPUT_FILE")
    dry = os.environ.get("DRY_RUN") == "1"

    if not dry and not out_file and not os.environ.get("WAZUH_API"):
        print("set SPAMHAUS_OUTPUT_FILE or WAZUH_API (or DRY_RUN=1)", file=sys.stderr)
        return 2

    nets = parse_networks(fetch(url))
    if not (min_nets <= len(nets) <= max_nets):
        print(f"refusing: {len(nets)} networks parsed (want {min_nets}-{max_nets})", file=sys.stderr)
        return 1
    keys = prefix_keys(nets)
    payload = render(keys)
    summary = f"{list_name}: {len(nets)} networks -> {len(keys)} prefix keys ({keys[0]} .. {keys[-1]})"

    if dry:
        print(summary + " [dry run]")
        return 0
    if out_file:
        write_file(out_file, payload)
        print(f"{summary} -> {out_file}")
        return 0
    if not push_api(list_name, payload):
        return 1
    print(f"{summary} -> Wazuh API")
    return 0


if __name__ == "__main__":
    sys.exit(main())
