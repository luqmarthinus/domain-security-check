#!/bin/bash
# ---------------------------------------------------------------------------
# domain-security-check.sh
# Read-only checks for company domains: email anti-spoofing (SPF, DKIM, DMARC,
# MTA-STS, TLS-RPT), MX records, HTTPS certificate validity and expiry, and
# domain registration expiry. Only does public DNS / WHOIS / HTTPS lookups.
#
# Usage:
#   ./domain-security-check.sh example.com example.org
#   ./domain-security-check.sh -f domains.txt          # one domain per line
#   ./domain-security-check.sh -H app.example.com example.com   # extra HTTPS hosts
#   ./domain-security-check.sh --json example.com
#   ./domain-security-check.sh --post <url> example.com          # Zapier webhook
#
# Runs on macOS (built-in bash 3.2) or Linux. Needs: dig, curl, openssl, whois.
# Exit codes: 0 = no FAIL, 1 = at least one FAIL, 2 = bad usage
# ---------------------------------------------------------------------------
[ -n "${ZSH_VERSION:-}" ] && emulate ksh
set -f   # no filename globbing; DNS records are split on spaces below

# ---- Settings --------------------------------------------------------------
CERT_WARN_DAYS=30;   CERT_FAIL_DAYS=7
DOMAIN_WARN_DAYS=60; DOMAIN_FAIL_DAYS=14
SPF_MAX_LOOKUPS=10   # RFC 7208 limit
# Common DKIM selectors (google = Google Workspace default). Add your own.
DKIM_SELECTORS=(google selector1 selector2 k1 k2 k3 s1 s2 default dkim mail smtp mandrill mxvault zoho zmail pm sig1 hs1 hs2 sendgrid mte1 cm)
# ---------------------------------------------------------------------------

OUTPUT=text; WEBHOOK_URL="${DOMAINCHECK_WEBHOOK_URL:-}"; DOMAINS=(); EXTRA_HOSTS=()
while [ $# -gt 0 ]; do
  case $1 in
    --json) OUTPUT=json ;;
    --post) [ -n "${2:-}" ] || { echo "--post needs a URL" >&2; exit 2; }; WEBHOOK_URL=$2; shift ;;
    -f) [ -r "${2:-}" ] || { echo "-f needs a readable file" >&2; exit 2; }
        while read -r line; do line=${line%%#*}; line=${line//[[:space:]]/}; [ -n "$line" ] && DOMAINS+=("$line"); done < "$2"; shift ;;
    -H) [ -n "${2:-}" ] || { echo "-H needs a hostname" >&2; exit 2; }; EXTRA_HOSTS+=("$2"); shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    -*) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
    *) DOMAINS+=("$1") ;;
  esac
  shift
done
[ ${#DOMAINS[@]} -gt 0 ] || { echo "Give at least one domain (try --help)" >&2; exit 2; }
for t in dig curl openssl whois; do
  command -v $t >/dev/null || { echo "Missing required tool: $t" >&2; exit 2; }
done

R_DOMAIN=(); R_ID=(); R_STATUS=(); R_DETAIL=()
record() { R_DOMAIN+=("$CUR"); R_ID+=("$1"); R_STATUS+=("$2"); R_DETAIL+=("${3//$'\n'/; }"); }
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
json_esc() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/}; s=${s//$'\t'/\\t}
  printf '%s' "$s"
}
# TXT records for a name, one per line, with quote-splitting undone
txt() { dig +short +time=3 +tries=2 TXT "$1" 2>/dev/null | grep '^"' | sed -e 's/" "//g' -e 's/^"//' -e 's/"$//'; }
# Date string -> epoch seconds (macOS or GNU date)
to_epoch() {
  local s=$1 fmt=$2
  date -j -f "$fmt" "$s" +%s 2>/dev/null || date -d "$s" +%s 2>/dev/null
}
NOW=$(date +%s)
days_until() { echo $(( ($1 - NOW) / 86400 )); }

spf_lookups() {  # domain depth -> number of DNS-lookup mechanisms (recursive)
  local dom=$1 depth=$2 rec term t n=0
  [ "$depth" -gt 8 ] && { echo 99; return; }
  rec=$(lower "$(txt "$dom" | grep -i '^v=spf1' | head -1)")
  for term in $rec; do
    t=${term#[+~?-]}
    case $t in
      include:*)  n=$((n + 1 + $(spf_lookups "${t#include:}" $((depth + 1))))) ;;
      redirect=*) n=$((n + 1 + $(spf_lookups "${t#redirect=}" $((depth + 1))))) ;;
      a|a:*|a/*|mx|mx:*|mx/*|ptr|ptr:*|exists:*) n=$((n + 1)) ;;
    esac
  done
  echo $n
}
dmarc_tag() {  # record tag -> value
  printf '%s' "$1" | tr -d ' ' | tr ';' '\n' | awk -F= -v t="$2" 'tolower($1) == t { print tolower($2); exit }'
}

check_tls() {  # host required(1/0)
  local host=$1 required=$2 r ecode emsg end exp days issuer
  r=$(curl -s -o /dev/null -m 12 -w '%{http_code}|%{exitcode}|%{errormsg}' "https://$host/" 2>/dev/null)
  IFS='|' read -r _ ecode emsg <<< "$r"
  case ${ecode:-1} in
    0) ;;
    6) if [ "$required" = 1 ]; then record "https:$host" WARN "Name does not resolve"
       else record "https:$host" INFO "Name does not resolve (no such host)"; fi; return ;;
    7|28) record "https:$host" WARN "No HTTPS service reachable (${emsg:-connect failed})"; return ;;
    35|51|58|59|60|77|83|90|91) record "https:$host" FAIL "Certificate/TLS problem: ${emsg:-curl error $ecode}"; return ;;
    *) record "https:$host" WARN "HTTPS request failed: ${emsg:-curl error $ecode}"; return ;;
  esac
  end=$(echo | openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null \
        | openssl x509 -noout -enddate -issuer 2>/dev/null)
  exp=$(printf '%s\n' "$end" | sed -n 's/^notAfter=//p' | tr -s ' ')
  issuer=$(printf '%s\n' "$end" | sed -nE 's/^issuer=.*O ?= ?([^,/]+).*/\1/p')
  exp=$(to_epoch "$exp" "%b %d %T %Y %Z")
  if [ -z "$exp" ]; then record "https:$host" WARN "Valid HTTPS, but could not read certificate expiry"; return; fi
  days=$(days_until "$exp")
  local d="Valid certificate${issuer:+ from $issuer}, expires in $days days"
  if [ "$days" -lt "$CERT_FAIL_DAYS" ]; then record "https:$host" FAIL "$d"
  elif [ "$days" -lt "$CERT_WARN_DAYS" ]; then record "https:$host" WARN "$d"
  else record "https:$host" PASS "$d"; fi
}

check_domain() {
  local d=$1 mx spf n_spf all lookups dmarc p pct rua sel found w exp days registrar
  CUR=$d

  # MX
  mx=$(dig +short +time=3 +tries=2 MX "$d" 2>/dev/null | sort -n | awk '{print $2}')
  if [ "$mx" = "." ]; then
    record mx PASS "Null MX (domain declares it receives no mail)"
  elif [ -z "$mx" ]; then
    record mx WARN "No MX records. If this domain never sends mail, publish 'v=spf1 -all' and DMARC p=reject so it can't be spoofed."
  else
    mx=$(printf '%s\n' "$mx" | sed 's/\.$//' | tr '\n' ' '); mx=${mx% }
    case $(lower "$mx") in
      *google.com*|*googlemail.com*) record mx PASS "Google Workspace: $mx" ;;
      *outlook.com*) record mx PASS "Microsoft 365: $mx" ;;
      *) record mx PASS "$mx" ;;
    esac
  fi

  # SPF
  spf=$(txt "$d" | grep -i '^v=spf1')
  n_spf=$(printf '%s\n' "$spf" | grep -c .)
  if [ "$n_spf" -eq 0 ]; then
    record spf FAIL "No SPF record: anyone can claim to send mail as $d."
  elif [ "$n_spf" -gt 1 ]; then
    record spf FAIL "$n_spf SPF records found; only one is allowed, so SPF fails everywhere."
  else
    case $(lower "$spf") in
      *" -all"*) all=PASS; w="hard fail (-all)" ;;
      *"~all"*) all=WARN; w="soft fail (~all): OK with an enforcing DMARC policy, otherwise use -all" ;;
      *"?all"*|*"+all"*|*" all"*) all=FAIL; w="'?all' / '+all' lets anyone send as $d" ;;
      *redirect=*) all=PASS; w="uses redirect" ;;
      *) all=WARN; w="no 'all' mechanism at the end" ;;
    esac
    record spf $all "$w. Record: $spf"
    lookups=$(spf_lookups "$d" 0)
    if [ "$lookups" -gt "$SPF_MAX_LOOKUPS" ]; then
      record spf_lookups FAIL "$lookups DNS lookups (limit $SPF_MAX_LOOKUPS): receivers will treat SPF as broken (permerror)."
    elif [ "$lookups" -ge 8 ]; then
      record spf_lookups WARN "$lookups DNS lookups (limit $SPF_MAX_LOOKUPS): close to the limit."
    else
      record spf_lookups PASS "$lookups DNS lookups (limit $SPF_MAX_LOOKUPS)"
    fi
  fi

  # DMARC
  dmarc=$(txt "_dmarc.$d" | grep -i '^v=DMARC1' | head -1)
  if [ -z "$dmarc" ]; then
    record dmarc FAIL "No DMARC record: spoofed mail from $d is not blocked and you get no reports."
  else
    p=$(dmarc_tag "$dmarc" p); pct=$(dmarc_tag "$dmarc" pct); rua=$(dmarc_tag "$dmarc" rua)
    case $p in
      reject) record dmarc PASS "p=reject (spoofed mail is rejected). Record: $dmarc" ;;
      quarantine) record dmarc PASS "p=quarantine (spoofed mail goes to spam); p=reject is stronger. Record: $dmarc" ;;
      none) record dmarc WARN "p=none: monitoring only, spoofed mail is still delivered. Record: $dmarc" ;;
      *) record dmarc FAIL "Invalid or missing p= tag. Record: $dmarc" ;;
    esac
    [ -n "$pct" ] && [ "$pct" != 100 ] && record dmarc_pct WARN "pct=$pct: policy applies to only $pct% of mail"
    [ -z "$rua" ] && record dmarc_reports WARN "No rua= address: you receive no DMARC reports"
  fi

  # DKIM (common selectors only; custom selectors can't be discovered via DNS)
  # A real key has a non-empty p= value; a wildcard record answering every
  # selector (seen on random names) means the results can't be trusted.
  found=""
  has_key() { txt "$1._domainkey.$d" | grep -qiE 'p=[A-Za-z0-9+/]{20}'; }
  if has_key "zz-no-such-selector-$$"; then
    record dkim INFO "A wildcard DKIM record answers every selector, so selectors can't be checked"
  else
    for sel in "${DKIM_SELECTORS[@]}"; do has_key "$sel" && found="$found $sel"; done
    if txt "zz-no-such-selector-$$._domainkey.$d" | grep -qi 'v=DKIM1'; then
      [ -z "$found" ] && record dkim PASS "Wildcard empty DKIM key (all selectors revoked): fine for a domain that sends no mail"
    fi
  fi
  if [ -n "$found" ]; then record dkim PASS "DKIM key found for selector(s):$found"
  elif [ ${#R_ID[@]} -gt 0 ] && [ "${R_ID[${#R_ID[@]}-1]}" = dkim ]; then :
  else record dkim WARN "No DKIM key on common selectors. Check the selector your mail provider uses (Google Workspace: Admin console > Gmail > Authenticate email)."; fi

  # MTA-STS and TLS reporting (optional hardening)
  if txt "_mta-sts.$d" | grep -qi '^v=STSv1'; then record mta_sts PASS "MTA-STS published"
  else record mta_sts INFO "No MTA-STS (optional: forces TLS for mail delivered to you)"; fi
  if txt "_smtp._tls.$d" | grep -qi '^v=TLSRPTv1'; then record tls_rpt PASS "TLS-RPT published"
  else record tls_rpt INFO "No TLS-RPT (optional: reports on mail TLS failures)"; fi

  # HTTPS certificates
  check_tls "$d" 0
  check_tls "www.$d" 0

  # Domain registration expiry (WHOIS formats vary by registry)
  w=$(whois "$d" 2>/dev/null)
  exp=$(printf '%s\n' "$w" | grep -iE 'expir|paid-till|renewal date|valid until' \
        | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)
  registrar=$(printf '%s\n' "$w" | grep -iE '^ *registrar:' | head -1 | sed -E 's/^ *[Rr]egistrar: *//')
  if [ -n "$exp" ]; then
    days=$(days_until "$(to_epoch "$exp" "%Y-%m-%d")")
    local dd="Registration expires $exp ($days days)${registrar:+, registrar $registrar}"
    if [ "$days" -lt "$DOMAIN_FAIL_DAYS" ]; then record domain_expiry FAIL "$dd"
    elif [ "$days" -lt "$DOMAIN_WARN_DAYS" ]; then record domain_expiry WARN "$dd"
    else record domain_expiry PASS "$dd"; fi
  else
    record domain_expiry INFO "Could not read expiry from WHOIS; check with the registrar"
  fi
}

for d in "${DOMAINS[@]}"; do
  d=$(lower "${d#http*://}"); d=${d%%/*}
  [ "$OUTPUT" = text ] && [ -t 2 ] && echo "Checking $d..." >&2
  check_domain "$d"
done
CUR="(extra hosts)"
for h in ${EXTRA_HOSTS[@]+"${EXTRA_HOSTS[@]}"}; do check_tls "$h" 1; done

# ---- Summary & output -------------------------------------------------------
n_pass=0; n_warn=0; n_fail=0; failed=""
for ((i = 0; i < ${#R_ID[@]}; i++)); do
  case ${R_STATUS[i]} in
    PASS) n_pass=$((n_pass + 1)) ;;
    WARN) n_warn=$((n_warn + 1)) ;;
    FAIL) n_fail=$((n_fail + 1)); failed="${failed:+$failed, }${R_DOMAIN[i]}:${R_ID[i]}" ;;
  esac
done
if [ $n_fail -gt 0 ]; then OVERALL=FAIL; elif [ $n_warn -gt 0 ]; then OVERALL=WARN; else OVERALL=PASS; fi

build_json() {
  local i sep=""
  printf '{"timestamp":"%s","overall":"%s","pass":%d,"warn":%d,"fail":%d,"failed_checks":"%s","checks":[' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$OVERALL" "$n_pass" "$n_warn" "$n_fail" "$(json_esc "$failed")"
  for ((i = 0; i < ${#R_ID[@]}; i++)); do
    printf '%s{"domain":"%s","id":"%s","status":"%s","detail":"%s"}' "$sep" "$(json_esc "${R_DOMAIN[i]}")" \
      "$(json_esc "${R_ID[i]}")" "${R_STATUS[i]}" "$(json_esc "${R_DETAIL[i]}")"
    sep=","
  done
  printf ']}\n'
}
JSON=$(build_json)

if [ "$OUTPUT" = json ]; then
  printf '%s\n' "$JSON"
else
  if [ -t 1 ]; then G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' C=$'\033[36m' B=$'\033[1m' N=$'\033[0m'; else G='' Y='' R='' C='' B='' N=''; fi
  last=""
  for ((i = 0; i < ${#R_ID[@]}; i++)); do
    if [ "${R_DOMAIN[i]}" != "$last" ]; then last=${R_DOMAIN[i]}; printf '\n%s%s%s\n' "$B" "$last" "$N"; fi
    case ${R_STATUS[i]} in PASS) c=$G ;; WARN) c=$Y ;; FAIL) c=$R ;; *) c=$C ;; esac
    printf '  %s%-5s%s %-26s %s\n' "$c" "${R_STATUS[i]}" "$N" "${R_ID[i]}" "${R_DETAIL[i]}"
  done
  printf '\n%sResult: %s%s (%d fail, %d warn, %d pass)\n' "$B" "$OVERALL" "$N" "$n_fail" "$n_warn" "$n_pass"
fi

if [ -n "$WEBHOOK_URL" ]; then
  printf '%s' "$JSON" | curl -fsS -m 20 -X POST -H "Content-Type: application/json" --data-binary @- "$WEBHOOK_URL" >/dev/null \
    || echo "Warning: could not POST results to webhook" >&2
fi
[ $n_fail -gt 0 ] && exit 1
exit 0
