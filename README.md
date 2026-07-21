# Panorama REST API Toolkit

[Русская версия](README.ru.md)

A collection of standalone Python tools for day-to-day administration and security operations on **Palo Alto Networks Panorama**, built directly on top of the PAN-OS XML/REST API. No SDK, no vendor library — just `requests`, `xml.etree`, and a clear picture of what the API actually returns.

Each tool started as a fix for a real operational problem (auditing thousands of security rules by hand doesn't scale) and was cleaned up into a self-contained, reusable script.

## What this demonstrates

- Working directly against a vendor XML/REST API (auth via `keygen`, XPath-based config reads/writes, async log jobs with polling)
- Bulk configuration management with safe defaults: every write operation prints a plan, asks for `y/N` confirmation, and lands only in the **Candidate Configuration** — nothing auto-commits
- Log-based security analysis: paginated traffic-log queries, time-bucketing, source/destination correlation against known Address Objects
- General scripting fundamentals: CSV I/O, concurrent TCP/TLS scanning, X.509 parsing, CLI UX for non-developers

## Repository layout

```
├── address_object_tagging/     Bulk tag / rename / normalize Address Objects
├── security_rule_logging/      Bulk-manage rule logging settings
├── security_profile_audit/     Find & fix Security rules missing a profile group
├── url_category_generator/     Build custom URL Category wildcard patterns
├── tls_certificate_scanner/    Port + TLS certificate scanner & expiry report
├── traffic_log_analyzer/       Generic "who talks to X" traffic-log analyzer
└── kerberos_auth_investigator/ Investigate Kerberos (port 88) traffic spikes
```

## Tools

| Folder | Script | What it does |
|---|---|---|
| `address_object_tagging/` | `ADD_TAG.py` | Creates/attaches a tag to Address Objects (by name, value, or CSV list); bulk-renames Address Objects using a pattern (`{IP}`, `{FQDN}`, `{VALUE}`, `{N}`); strips a domain suffix from object names in bulk. |
| `security_rule_logging/` | `edit_log_start.py` | Audits and toggles **Log at Session Start** across chosen device-groups and rulebases. |
| `security_rule_logging/` | `edit_log_forwarding.py` | Bulk-replaces the **Log Forwarding** profile on security rules — by source profile, by single rule, or from a CSV list of rule numbers. |
| `security_profile_audit/` | `profile_audit.py` | Scans every security rule for a missing Security Profile Group (`None` / `Group(None)`), exports a numbered CSV report, then applies fixes from that CSV once you fill in a target profile per row. |
| `url_category_generator/` | `url_category.py` | Converts a flat list of domains into the `domain/*`, `domain/`, `www.domain`, `www.domain/*` patterns Panorama expects for custom URL Category objects. |
| `tls_certificate_scanner/` | `scan_cert.py` | Interactive scanner: **Search** mode sweeps TCP ports then pulls certificate chains via `openssl s_client`; **Audit** mode checks ~80 known TLS/management ports (K8s, Elastic, UniFi, NGFW/PAM/DLP/NAC admin ports, etc.). Exports full-chain and leaf-only CSV reports with expiry countdowns. Targets can come from a single host, a CSV, or a Panorama tag. |
| `traffic_log_analyzer/` | `search_bruteforce_mail.py` | Queries Panorama traffic logs (paginated log jobs), counts hits per source/destination IP, flags anything above a threshold. Ships with an SMTP-bruteforce preset but works as a general traffic analyzer. |
| `kerberos_auth_investigator/` | `kerberos_investigator.py` | Investigates a burst of Kerberos (AS-REQ / port 88) traffic from a set of PAM/jump-host IPs: buckets hits by time, correlates source ports to spot retry loops, and pulls the traffic that happened right before each Kerberos hit for context. Exports several CSV breakdowns. |

## Setup

```bash
git clone <this repo>
cd <this repo>
pip install -r requirements.txt
```

`tls_certificate_scanner/scan_cert.py` also needs the `openssl` binary on `PATH` (on Windows it will offer to install it via `winget` if missing).

### Configure API access

Every tool folder has its own `api_key.py` — this is a **template with empty values**, not a shared secret:

```python
api_ip = ""     # Panorama management IP or FQDN
api_key = ''    # paste a pre-generated API key here, or leave empty
user = ""       # Panorama username (only needed if api_key is empty)
passwd = ""     # Panorama password (only needed if api_key is empty)
```

`pan_api.py` in each folder uses these values to generate (via `type=keygen`) and validate an API key automatically, so you only need to fill in `api_ip` + `user`/`passwd`, or `api_ip` + `api_key`.

**Never commit a filled-in `api_key.py`.** After cloning, either edit it locally and keep the change unstaged (`git update-index --skip-worktree <folder>/api_key.py`), or keep your real credentials in an untracked copy and load it manually. The `.gitignore` in this repo already excludes generated report files, but it does **not** exclude `api_key.py` itself, since the empty template is meant to stay tracked.

## Design notes

- All API calls go through PAN-OS's own XML/REST endpoint (`type=config`, `type=log`, `type=op`) with `verify=False` (self-signed Panorama certs) — point it at a trusted network path.
- Write operations are always: **preview → confirm (`y/N`) → apply**. Applied changes go to the Candidate Configuration; you commit manually in Panorama when ready.
- CLI prompts and console output are in Russian (the author's working language); code, structure, and this README are in English.
- Example/seed CSVs in this repo (`ip_range.csv`, `dns_range.csv`, etc.) use documentation-only addresses (`192.0.2.0/24`, `192.168.0.0/16`) — replace them with your own inventory before running anything for real.

## Requirements

- Python 3.8+
- `requests` (see `requirements.txt`)
- `openssl` on `PATH` for `tls_certificate_scanner/`

## Disclaimer

Not affiliated with or endorsed by Palo Alto Networks. These are personal operational tools shared as-is; review them before running against a production Panorama, especially anything under a "write" mode. Tested against the PAN-OS XML/REST API conventions current at the time of writing — endpoint behavior may differ across PAN-OS versions.

## License

[MIT](LICENSE)
