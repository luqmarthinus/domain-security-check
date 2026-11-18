# domain-security-check

Checks the public DNS, WHOIS and HTTPS setup of your organisation's domains: email anti-spoofing records, certificate expiry and domain expiry. It doesn't need to run on a managed Mac, and it also runs on Linux.

```bash
./domain-security-check.sh example.com example.org
```
```bash
./domain-security-check.sh -f domains.txt -H app.example.com
```

`-f` reads one domain per line (`#` comments allowed). `-H` adds an extra HTTPS host to check (repeatable).

## Checks
| Check | What it looks at |
|---|---|
| MX | Mail servers; recognises Google Workspace, Microsoft 365 and "null MX" (a domain that receives no mail) |
| SPF | Exactly one record, how strict it is (`-all` / `~all` / `?all`), DNS lookups against the limit of 10 |
| DMARC | Record present, policy (`reject` / `quarantine` / `none`), `pct=`, reporting address (`rua=`) |
| DKIM | Keys under common selectors (`google`, `selector1`, `k1`, …); detects wildcard records |
| MTA-STS, TLS-RPT | Optional mail-transport hardening (shown as INFO) |
| HTTPS | Certificate valid for the domain, `www.` and any `-H` hosts; days left (WARN under 30, FAIL under 7) |
| Domain expiry | From WHOIS (WARN under 60 days, FAIL under 14). Some registries don't publish an expiry date; the result is then INFO |

## Running it on a schedule
Run it weekly from any machine with `--post <webhook-url>` to get an alert before a certificate or domain expires. Cron, a CI scheduler such as GitHub Actions, or the [LaunchDaemon template](../deploy/launchd/) (set `DOMAINS` in its config file) all work.

**Requirements:** `dig`, `curl`, `openssl` and `whois`. All are built into macOS; on Linux, install `dnsutils`/`bind-utils` and `whois`.
**Settings:** the certificate and domain-expiry warning thresholds, and `DKIM_SELECTORS`. Add your mail provider's selector if it isn't in the list.
**Exit code:** 0 = no FAIL, 1 = at least one FAIL, 2 = bad usage.
**Webhook from the environment:** `DOMAINCHECK_WEBHOOK_URL`.

## Tested
google.com, example.com and badssl.com's deliberately broken test sites, on macOS. **Not yet tested:** Linux.
