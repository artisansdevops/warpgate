#!/usr/bin/env bash
# test-rabbitmq-target.sh — smoke-test the RabbitMQ target through Warpgate's
# RabbitMQ listener (AMQP 0-9-1 proxy on :5672), using a small pika-based
# Python client as the client would connect (SASL PLAIN, `user#target` as the
# authcid).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RABBITMQ_PORT="${RABBITMQ_PORT:-5672}"
WG_USER="${TEST_USERNAME:-rabbitmquser}"
WG_PASSWORD="${TEST_PASSWORD:-RabbitPass123!}"
TARGET_NAME="${TARGET_NAME:-my-rabbitmq}"
SECOND_TARGET_NAME="${SECOND_TARGET_NAME:-my-rabbitmq-second}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; exit 1; }

# The client needs `pika`. Prefer a local install; otherwise run the check
# inside a throwaway `python:3-alpine` container on the compose network,
# reaching Warpgate by its container name.
PY_HOST="localhost"
if python3 -c "import pika" >/dev/null 2>&1; then
    run_py() { local script="$1"; shift; python3 "$script" "$@"; }
else
    PY_HOST="wg-rabbitmq-poc"
    run_py() {
        local script="$1"; shift
        docker run --rm --network wg-rabbitmq-test-net \
            -v "$script:/check.py:ro" \
            python:3-alpine sh -c 'pip install -q pika >/dev/null 2>&1 && python3 /check.py "$@"' -- "$@"
    }
fi

check_script="$(mktemp)"
trap 'rm -f "$check_script"' EXIT

cat > "$check_script" <<'PYEOF'
import sys
import pika

host, port, user, password, target, second_target = sys.argv[1:7]
port = int(port)

def connect(authcid, pwd):
    params = pika.ConnectionParameters(
        host=host,
        port=port,
        credentials=pika.PlainCredentials(authcid, pwd),
        connection_attempts=20,
        retry_delay=1,
    )
    return pika.BlockingConnection(params)

# ── Authenticated round-trip through Warpgate ──────────────────────────────
conn = connect(f"{user}#{target}", password)
ch = conn.channel()
queue = ch.queue_declare(queue="", exclusive=True).method.queue
ch.basic_publish(exchange="", routing_key=queue, body=b"hello-from-warpgate")
_, _, body = ch.basic_get(queue, auto_ack=True)
assert body == b"hello-from-warpgate", f"unexpected body: {body!r}"
conn.close()
print("OK round-trip target-1")

# ── Round-trip through the second backend (distinct backend credentials) ──
conn2 = connect(f"{user}#{second_target}", password)
ch2 = conn2.channel()
queue2 = ch2.queue_declare(queue="", exclusive=True).method.queue
ch2.basic_publish(exchange="", routing_key=queue2, body=b"hello-from-second-backend")
_, _, body2 = ch2.basic_get(queue2, auto_ack=True)
assert body2 == b"hello-from-second-backend", f"unexpected body: {body2!r}"
conn2.close()
print("OK round-trip target-2")

# ── Wrong credentials are rejected ─────────────────────────────────────────
try:
    connect(f"{user}#{target}", "wrong-password")
    print("FAIL: wrong password was accepted")
    sys.exit(1)
except pika.exceptions.ProbableAuthenticationError:
    print("OK wrong-password rejected")

# ── Unknown target is rejected ─────────────────────────────────────────────
try:
    connect(f"{user}#no-such-target", password)
    print("FAIL: unknown target was accepted")
    sys.exit(1)
except pika.exceptions.ProbableAuthenticationError:
    print("OK unknown-target rejected")
PYEOF

echo -e "${CYAN}== Running AMQP checks through Warpgate ==${NC}"
OUT=$(run_py "$check_script" "$PY_HOST" "$RABBITMQ_PORT" "$WG_USER" "$WG_PASSWORD" "$TARGET_NAME" "$SECOND_TARGET_NAME")
echo "$OUT"

echo "$OUT" | grep -q "^OK round-trip target-1$" || fail "round-trip through target-1 failed"
pass "PUBLISH/GET round-tripped through the proxy (target-1)"

echo "$OUT" | grep -q "^OK round-trip target-2$" || fail "round-trip through target-2 failed"
pass "PUBLISH/GET round-tripped through the proxy (target-2, distinct backend credentials)"

echo "$OUT" | grep -q "^OK wrong-password rejected$" || fail "expected wrong password to be rejected"
pass "Wrong password rejected"

echo "$OUT" | grep -q "^OK unknown-target rejected$" || fail "expected unknown target to be rejected"
pass "Unknown target rejected"

echo ""
echo -e "${GREEN}All RabbitMQ target checks passed.${NC}"
