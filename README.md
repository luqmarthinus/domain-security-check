# domain-security-check

[![CI](https://github.com/luqmarthinus/domain-security-check/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/luqmarthinus/domain-security-check/actions/workflows/ci.yml?query=branch%3Amain)

A free check of a domain's email anti-spoofing and web security: SPF (including the 10-lookup limit), DKIM, DMARC, MTA-STS, TLS-RPT, MX, HTTPS certificate validity and expiry, and domain registration expiry. One bash script that runs on macOS and Linux, with JSON output and webhook alerts.

It changes nothing. It makes public DNS and WHOIS lookups plus one HTTPS request (`GET /`) to each web host it checks, the same as a browser visit. So you can check any domain, including ones you don't own: suppliers, lookalike domains, or a domain you're about to buy. That HTTPS request will appear in the site's access logs.

## Quick start
```bash
git clone https://github.com/luqmarthinus/domain-security-check.git
```
```bash
./domain-security-check/domain-security-check.sh example.com
```

Sample output:
```text
example.com
  PASS  mx                         Null MX (domain declares it receives no mail)
  PASS  spf                        hard fail (-all). Record: v=spf1 -all
  PASS  spf_lookups                0 DNS lookups (limit 10)
  PASS  dmarc                      p=reject (spoofed mail is rejected). Record: v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s
  WARN  dmarc_reports              No rua= address: you receive no DMARC reports
  PASS  dkim                       Wildcard empty DKIM key (all selectors revoked): fine for a domain that sends no mail
  INFO  mta_sts                    No MTA-STS (optional: forces TLS for mail delivered to you)
  INFO  tls_rpt                    No TLS-RPT (optional: reports on mail TLS failures)
  PASS  https:example.com          Valid certificate from SSL Corporation, expires in 35 days
  PASS  https:www.example.com      Valid certificate from SSL Corporation, expires in 35 days
  INFO  domain_expiry              Could not read expiry from WHOIS; check with the registrar

Result: WARN (0 fail, 1 warn, 7 pass)
```

| Usage | What it does |
|---|---|
| `domain-security-check.sh example.com example.org` | Check one or more domains. A URL such as `https://example.com/path` is reduced to its domain |
| `domain-security-check.sh -f domains.txt` | Read domains from a file, one per line (`#` comments allowed) |
| `domain-security-check.sh -H app.example.com example.com` | Also check the HTTPS certificate of extra hosts (repeatable) |
| `domain-security-check.sh --json example.com` | Machine-readable output (see [JSON output](#json-output)) |
| `domain-security-check.sh --post <url> example.com` | Also send the JSON report to a webhook. For anything beyond a quick test, set `DOMAINCHECK_WEBHOOK_URL` instead (see [Security](#security)) |

## Results and exit codes
| Status | Meaning | Affects exit code |
|---|---|---|
| PASS | Configured well | No |
| WARN | Works, but weaker than it should be, or a certificate or domain expires soon | No |
| FAIL | Broken or missing in a way that allows spoofing or an outage | Yes |
| INFO | Optional feature not in use, or the check couldn't get an answer | No |

**Exit codes:** 0 = no FAIL (the overall result can still be WARN), 1 = at least one FAIL, 2 = usage error or missing tool.

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
`bash` (3.2 or newer), `dig`, `curl` (7.75 or newer), `openssl` and `whois`.
- **macOS:** all built in.
- **Debian/Ubuntu:** `sudo apt-get install dnsutils whois`
- **Fedora/RHEL:** `sudo dnf install bind-utils whois`

Check your curl with `curl --version`. Some long-term-support releases ship an older one, for example Debian 11 (7.74) and RHEL/Rocky 8 (7.61). With an older curl, every HTTPS check reports WARN "HTTPS request failed" instead of a real result.

## JSON output
`--json` and `--post` produce one object:

```json
{
  "timestamp": "2026-11-20T09:00:00Z",
  "overall": "FAIL",
  "pass": 7, "warn": 1, "fail": 1,
  "failed_checks": "example.org:dmarc",
  "checks": [
    {"domain": "example.org", "id": "dmarc", "status": "FAIL", "detail": "No DMARC record: …"}
  ]
}
```

| Field | Notes |
|---|---|
| `overall` | `PASS`, `WARN` or `FAIL`: the worst status of any check (INFO is ignored) |
| `pass`, `warn`, `fail` | Counts of checks with that status |
| `failed_checks` | Comma-separated `domain:id` pairs, as one string (not an array). Empty when nothing failed |
| `checks[].domain` | The domain checked. Hosts given with `-H` are listed under `(extra hosts)` |
| `checks[].id` | `mx`, `spf`, `spf_lookups`, `dmarc`, `dmarc_pct`, `dmarc_reports`, `dkim`, `mta_sts`, `tls_rpt`, `https:<host>`, `domain_expiry` |
| `checks[].status` | `PASS`, `WARN`, `FAIL` or `INFO` |

Some IDs appear only when relevant: `spf_lookups` only when there is exactly one SPF record, and `dmarc_pct` and `dmarc_reports` only when they find a problem.

## Running it on a schedule
Run it weekly with a webhook to get an alert before a certificate or domain expires, or when someone weakens your SPF or DMARC. Any scheduler works:
- **cron** on a Linux server. Keep the webhook URL in a file only the cron user can read (`chmod 600`) containing `DOMAINCHECK_WEBHOOK_URL=https://…`, then:
  ```text
  0 9 * * 1 set -a; . /etc/domain-security-check.env; /opt/domain-security-check/domain-security-check.sh -f /opt/domains.txt
  ```
- **GitHub Actions** on a `schedule:` trigger, with the webhook URL stored as a repository secret and passed in as the `DOMAINCHECK_WEBHOOK_URL` environment variable
- **an MDM or RMM job** on a Mac

For scheduled jobs, check out a release tag rather than `main`, so the script only changes when you choose to upgrade.

Receivers that accept any JSON work directly: Slack and Teams workflows, n8n, Make, Zapier, or a Google Apps Script web app. The `overall` and `failed_checks` fields make simple alert filters. If the webhook can't be reached, the script prints a warning and the exit code is unchanged, so monitor the job itself too.

## Settings
Edit the block near the top of the script:
- `CERT_WARN_DAYS` / `CERT_FAIL_DAYS` (30 / 7)
- `DOMAIN_WARN_DAYS` / `DOMAIN_FAIL_DAYS` (60 / 14)
- `SPF_MAX_LOOKUPS` (10)
- `DKIM_SELECTORS`: add your mail provider's selector if it isn't in the list. DNS can't list selectors, so a custom one won't be found otherwise.

## Security
- **Treat the webhook URL as a password.** Anyone who has it can post to your channel. A URL passed with `--post` is visible to other users in `ps` and can end up in shell history, so use `DOMAINCHECK_WEBHOOK_URL` from a protected file or a secret store. `*.env` files are already gitignored.
- **What leaves your machine:** DNS queries go to your configured resolver, WHOIS queries go to the registry's WHOIS servers, one HTTPS request goes to each web host checked, and the JSON report goes to the webhook if you set one. Nothing else is sent anywhere.
- To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Limitations
- **DMARC on subdomains:** checking `mail.example.com` reports FAIL if it has no `_dmarc` record of its own, even though receivers apply the parent domain's policy (and its `sp=` tag). Check the organisational domain instead.
- **DKIM:** only the selectors in `DKIM_SELECTORS` are tried, so "no key found" may mean a custom selector.
- **Domain expiry:** parsed from WHOIS text, whose format varies by registry (RDAP isn't used). WHOIS servers rate-limit, so long domain lists may get INFO results.
- **HTTPS:** port 443 only, and the certificate checked is the one served to `curl` and `openssl` from your network.
- **MTA-STS:** only the DNS record is checked, not the policy file it points to.
- **Not checked:** DNSSEC, CAA, BIMI, the DMARC `sp=` tag, DMARC alignment settings, and SPF void-lookup limits.

## Tested
macOS 26 against google.com, example.com and badssl.com's deliberately broken test sites. CI runs ShellCheck and live checks on both macOS and Ubuntu on every push.

## License
[MIT](LICENSE) © 2026 Luqmaan Marthinus. Free to use, modify and share; provided as-is, without warranty.
