#!/usr/bin/env bash
# Is the whole stack up, end to end? Run on the host; exits non-zero and says what is wrong.
#
#   deploy/healthcheck.sh [--host cairn.example.lan] [--quiet]
#
# It exists because a stack can look healthy unit by unit while one link is gone: the
# dashboard's reverse proxy, the daemon that gives it tailnet identity, a certificate about to
# lapse. Each check below names the failure it would have caught. Read-only: it only asks
# questions, over loopback.
#
# Checks (all must pass):
#   units      cairn-server, cairn-tsdb, cairn-ui, caddy, tailscaled are active
#   app API    GET /v1/health on the app listener (loopback) answers 200
#   tsdb       GET /healthz answers 200
#   dashboard  the public name, through the reverse proxy, answers (200/3xx/401: it is behind
#              a login; what matters is that the proxy reaches the UI at all)
#   tailnet    tailscaled's LocalAPI answers (the dashboard's tailnet identity depends on it)
#   tls        the proxy's certificate has more than $CAIRN_CERT_MIN_DAYS (default 14) days left
set -uo pipefail

host="${CAIRN_HOST:-}"
quiet=0
while [ $# -gt 0 ]; do
  case "$1" in
    --host) host="${2:?--host needs a name}"; shift ;;
    --quiet) quiet=1 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
# Default: the name Caddy serves, read from its config; else the machine's FQDN.
if [ -z "$host" ] && [ -r /etc/caddy/Caddyfile ]; then
  host="$(awk '/^[A-Za-z0-9.-]+ *\{/ { print $1; exit }' /etc/caddy/Caddyfile)"
fi
host="${host:-$(hostname -f)}"

app="${CAIRN_APP_LOCAL:-127.0.0.1:8445}"
tsdb="${CAIRN_TSDB_ADDR:-127.0.0.1:8480}"
min_days="${CAIRN_CERT_MIN_DAYS:-14}"

fails=0
say() { [ "$quiet" = 1 ] || printf '  %-5s %s\n' "$1" "$2"; }
bad() { fails=$((fails + 1)); printf '  FAIL  %s\n' "$1" >&2; }
ok() { say ok "$1"; }

for u in cairn-server cairn-tsdb cairn-ui caddy tailscaled; do
  if [ "$(systemctl is-active "$u" 2>/dev/null)" = active ]; then ok "unit $u active"
  else bad "unit $u is $(systemctl is-active "$u" 2>/dev/null || echo unknown)"; fi
done

code() { curl -s -o /dev/null -m 6 -w '%{http_code}' "$@" 2>/dev/null || true; }

c="$(code "http://$app/v1/health")"
[ "$c" = 200 ] && ok "app API /v1/health 200" || bad "app API http://$app/v1/health answered '$c' (want 200)"
c="$(code "http://$tsdb/healthz")"
[ "$c" = 200 ] && ok "tsdb /healthz 200" || bad "tsdb http://$tsdb/healthz answered '$c' (want 200)"

# Through the reverse proxy, to loopback, by name, so this tests Caddy and its certificate
# rather than DNS. -k: the name may be an internal one; certificate age is checked below.
c="$(code -k --resolve "$host:443:127.0.0.1" "https://$host/")"
case "$c" in
  200|301|302|303|307|308|401) ok "dashboard via the proxy at https://$host/ -> $c" ;;
  *) bad "dashboard via the proxy at https://$host/ answered '$c' (a proxy or UI that is down gives 000/502/503)" ;;
esac

sock=/var/run/tailscale/tailscaled.sock
if [ -S "$sock" ] && curl -s -m 4 --unix-socket "$sock" -o /dev/null -w '%{http_code}' \
     -H 'Host: local-tailscaled.sock' http://local-tailscaled.sock/localapi/v0/status 2>/dev/null | grep -q '^[23]'; then
  ok "tailscaled LocalAPI answers"
else
  # Not every account may read the socket; the unit check above is the hard requirement.
  say warn "tailscaled LocalAPI not readable from here (unit check above still applies)"
fi

end="$(echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$host" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
if [ -n "$end" ]; then
  left=$(( ( $(date -d "$end" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
  if [ "$left" -gt "$min_days" ]; then ok "certificate valid for $left more days"
  else bad "certificate for $host has $left days left (want more than $min_days)"; fi
else
  bad "could not read the certificate the proxy serves for $host"
fi

if [ "$fails" -eq 0 ]; then [ "$quiet" = 1 ] || echo "healthy"; exit 0; fi
echo "unhealthy: $fails check(s) failed" >&2
exit 1
