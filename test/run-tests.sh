#!/usr/bin/env bash
# End-to-end tests of crowdsec-apache-bouncer against a real CrowdSec AppSec component.
#   ./run-tests.sh            build, run every case on every Apache flavour, tear down
#   KEEP=1 ./run-tests.sh     leave the containers running afterwards
set -euo pipefail
cd "$(dirname "$0")"

KEY=test-apache-bouncer-key
FLAVOURS="apache-debian13:18081 apache-ubuntu2204:18082"
failures=0

write_conf() { # key url
  cat > bouncer.conf <<CONF
API_KEY=$1
APPSEC_URL=$2
APPSEC_TIMEOUT_MS=500
EXCLUDE_LOCATION=/status
CONF
}

restart_apache() {
  docker compose restart apache-debian13 apache-ubuntu2204 >/dev/null
  for f in $FLAVOURS; do
    for _ in $(seq 30); do curl -s -o /dev/null "http://127.0.0.1:${f#*:}/" && break; sleep 1; done
  done
}

expect() { # name port expected_status expected_body_substring path [curl_args...]
  local name=$1 port=$2 want=$3 body_re=$4 path=$5; shift 5
  local out code body
  out=$(curl -s -w '\n%{http_code}' --max-time 5 "$@" "http://127.0.0.1:$port$path" || true)
  code=${out##*$'\n'}; body=${out%$'\n'*}
  if [[ $code == "$want" && ( -z $body_re || $body == *"$body_re"* ) ]]; then
    printf '  ok   %-45s %s\n' "$name" "$code"
  else
    printf '  FAIL %-45s got %s (want %s) body: %.80s\n' "$name" "$code" "$want" "$body"
    failures=$((failures + 1))
  fi
}

cleanup() { [[ ${KEEP:-} == 1 ]] || docker compose down -v >/dev/null 2>&1; rm -f bouncer.conf; }
trap cleanup EXIT

write_conf "$KEY" http://crowdsec:7422/
BOUNCER_KEY=$KEY docker compose up -d --build --wait >/dev/null
restart_apache

for f in $FLAVOURS; do
  svc=${f%:*} port=${f#*:}
  echo "== $svc"
  expect "clean GET passes"                    "$port" 200 'Apache'      /
  expect "/.env is blocked"                    "$port" 403 ''            /.env
  expect "virtual patch CVE-2017-9841 blocks"  "$port" 403 ''            /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
  expect "excluded location is not checked"    "$port" 404 ''            /status/.env
  expect "POST body reaches the handler"       "$port" 200 'POST 11'     /echo -X POST --data 'hello=world'
  expect "missing page still 404"              "$port" 404 ''            /nothing-here
done

echo "== wrong API key (fail open)"
write_conf wrong-key http://crowdsec:7422/; restart_apache
for f in $FLAVOURS; do expect "${f%:*}: /.env passes" "${f#*:}" 404 '' /.env; done

echo "== AppSec component unreachable (fail open, bounded latency)"
write_conf "$KEY" http://192.0.2.1:7422/; restart_apache
for f in $FLAVOURS; do
  start=$(date +%s)
  expect "${f%:*}: GET passes" "${f#*:}" 200 'Apache' /
  (( $(date +%s) - start <= 2 )) || { echo "  FAIL ${f%:*}: took more than 2 s"; failures=$((failures + 1)); }
done

echo "== bouncer log lines"
docker compose logs apache-debian13 apache-ubuntu2204 2>&1 | grep -o 'crowdsec: .*' | sort | uniq -c | sed 's/^/  /' | head -20

echo
(( failures == 0 )) && echo "All tests passed." || { echo "$failures test(s) failed."; exit 1; }
