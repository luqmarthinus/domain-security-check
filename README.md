# domain-security-check

A free, read-only check of a domain's email anti-spoofing and web security: SPF (including the 10-lookup limit), DKIM, DMARC, MTA-STS, TLS-RPT, MX, HTTPS certificate validity and expiry, and domain registration expiry. One bash script that runs on macOS and Linux, with JSON output and webhook alerts.

It only makes public DNS, WHOIS and HTTPS queries, so you can check any domain, including ones you don't own: suppliers, lookalike domains, or a domain you're about to buy.

## Quick start
```bash
git clone git@github.com:luqmarthinus/domain-security-check.git
```
```bash
./domain-security-check/domain-security-check.sh example.com
```

| Usage | What it does |
|---|---|
| `domain-security-check.sh example.com example.org` | Check one or more domains |
| `domain-security-check.sh -f domains.txt` | Read domains from a file, one per line (`#` comments allowed) |
| `domain-security-check.sh -H app.example.com example.com` | Also check the HTTPS certificate of extra hosts (repeatable) |
| `domain-security-check.sh --json example.com` | Machine-readable output |
| `domain-security-check.sh --post <url> example.com` | Also send the JSON report to a webhook (or set `DOMAINCHECK_WEBHOOK_URL`) |

**Exit codes:** 0 = no FAIL, 1 = at least one FAIL, 2 = usage error.

## What it checks
| Check | What it looks at |
|---|---|
| MX | Mail servers; recognises Google Workspace, Microsoft 365 and "null MX" (a domain that receives no mail) |
| SPF | Exactly one record, how strict it is (`-all` / `~all` / `?all`), DNS lookups counted recursively against the limit of 10 (over the limit, receivers treat SPF as broken) |
| DMARC | Record present, policy (`reject` / `quarantine` / `none`), `pct=`, reporting address (`rua=`) |
| DKIM | Keys under common selectors (`google`, `selector1`, `k1`, …); detects wildcard records |
| MTA-STS, TLS-RPT | Optional mail-transport hardening (shown as INFO) |
| HTTPS | Certificate valid for the domain, `www.` and any `-H` hosts; days left (WARN under 30, FAIL under 7) |
| Domain expiry | From WHOIS (WARN under 60 days, FAIL under 14). Some registries don't publish an expiry date; the result is then INFO |

Each result explains what's wrong and why it matters, for example: "p=none: monitoring only, spoofed mail is still delivered".

## Requirements
`bash`, `dig`, `curl` (7.75 or newer), `openssl` and `whois`.
- **macOS:** all built in.
- **Debian/Ubuntu:** `sudo apt-get install dnsutils whois`
- **Fedora/RHEL:** `sudo dnf install bind-utils whois`

## Running it on a schedule
Run it weekly with `--post <webhook-url>` to get an alert before a certificate or domain expires, or when someone weakens your SPF or DMARC. Any scheduler works:
- **cron** on a Linux server: `0 9 * * 1 /opt/domain-security-check/domain-security-check.sh -f /opt/domains.txt --post "$URL"`
- **GitHub Actions** on a `schedule:` trigger, with the webhook URL stored as a repository secret
- **an MDM or RMM job** on a Mac

Receivers that accept any JSON work directly: Slack and Teams workflows, n8n, Make, Zapier, or a Google Apps Script web app. The top-level `overall` and `failed_checks` fields make simple alert filters.

## Settings
Edit the block near the top of the script:
- `CERT_WARN_DAYS` / `CERT_FAIL_DAYS` (30 / 7)
- `DOMAIN_WARN_DAYS` / `DOMAIN_FAIL_DAYS` (60 / 14)
- `SPF_MAX_LOOKUPS` (10)
- `DKIM_SELECTORS`: add your mail provider's selector if it isn't in the list. DNS can't list selectors, so a custom one won't be found otherwise.

## Tested
macOS 26 against google.com, example.com and badssl.com's deliberately broken test sites. CI runs ShellCheck and live checks on both macOS and Ubuntu on every push.

## License
[MIT](LICENSE) © 2026 Luqmaan Marthinus. Free to use, modify and share; provided as-is, without warranty.
