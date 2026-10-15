#!/usr/bin/env bash
# Verify a proxy-chain subscription end to end, in the order the layers can fail.
#
#   SUB_URL='https://<worker>/sub?format=mihomo&entry64=...' ./scripts/verify-chain.sh
#
# Checks, in order:
#   1. the subscription answers and reports its health-index state
#   2. the emitted config parses in the real core
#   3. the live chain actually carries traffic, and where the egress lands
#   4. the core log carries no ECH resolution failure
#
# Exit codes: 0 all layers ok, 1 the config did not parse, 2 the chain did not
# carry traffic, 3 an ECH resolution failure appears in the log.
set -uo pipefail

SUB_URL="${SUB_URL:?set SUB_URL to the subscription URL}"
MIHOMO="${MIHOMO:-mihomo}"
PORT="${PORT:-7939}"
EGRESS_PROBE="${EGRESS_PROBE:-http://ip-api.com/line/?fields=query,countryCode}"

DIR="$(mktemp -d)"
cleanup() {
  [ -n "${CORE_PID:-}" ] && kill "$CORE_PID" 2>/dev/null
  rm -rf "$DIR"
}
trap cleanup EXIT

echo "[1/4] fetching the subscription"
code=$(curl -sS -D "$DIR/headers" -o "$DIR/sub.yaml" -w '%{http_code}' --max-time 45 "$SUB_URL") || {
  echo "      fetch failed (blocked network? try again through a working proxy)"
  exit 2
}
echo "      http $code, $(wc -c < "$DIR/sub.yaml") bytes"
grep -i '^x-health\|^x-ech' "$DIR/headers" | sed 's/^/      /' || true
[ "$code" = "200" ] || { echo "      subscription did not return 200"; exit 2; }

printf 'mixed-port: %s\nlog-level: warning\nmode: rule\ndns:\n  enable: true\n  nameserver: [223.5.5.5, 223.6.6.6]\n  proxy-server-nameserver: [223.5.5.5, 223.6.6.6]\n' "$PORT" > "$DIR/head.yaml"
cat "$DIR/head.yaml" "$DIR/sub.yaml" > "$DIR/config.yaml"

echo "[2/4] parsing the config with the real core"
if ! "$MIHOMO" -t -f "$DIR/config.yaml" -d "$DIR" > "$DIR/parse.log" 2>&1; then
  echo "      config did not parse:"
  tail -3 "$DIR/parse.log" | sed 's/^/      /'
  exit 1
fi
echo "      parsed ok ($(grep -c '^    name:' "$DIR/sub.yaml" || echo 0) proxies, $(grep -c 'dialer-proxy:' "$DIR/sub.yaml" || echo 0) chained)"

echo "[3/4] carrying real traffic through the chain"
"$MIHOMO" -f "$DIR/config.yaml" -d "$DIR/run" > "$DIR/core.log" 2>&1 &
CORE_PID=$!
sleep 7
if egress=$(curl -sS --max-time 25 -x "http://127.0.0.1:$PORT" "$EGRESS_PROBE" 2>&1); then
  echo "      egress: $(echo "$egress" | tr '\n' ' ')"
else
  echo "      the chain did not carry traffic: $egress"
  exit 2
fi

echo "[4/4] checking the core log for ECH failures"
if grep -qi 'resolve ECH config error\|ECHRejectionError' "$DIR/core.log"; then
  grep -i 'ech' "$DIR/core.log" | tail -3 | sed 's/^/      /'
  echo "      ECH lookup failed: point proxy-server-nameserver at a reachable resolver,"
  echo "      or request the subscription with ?ech=embed to pin the key."
  exit 3
fi
echo "      no ECH errors"
echo "all layers ok"
