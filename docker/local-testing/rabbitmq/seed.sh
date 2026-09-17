#!/usr/bin/env bash
# seed.sh — seed warpgate with a test user, two RabbitMQ targets, and a role
# via the admin API. Idempotent: re-running it after a partial or full
# previous run only creates what's missing.
# Usage: seed.sh <http_port> <admin_token>
set -euo pipefail

HTTP_PORT="${1:-8888}"
TOKEN="${2:-token-value}"
BASE="https://localhost:$HTTP_PORT/@warpgate/admin/api"

TEST_USERNAME="${TEST_USERNAME:-rabbitmquser}"
TEST_PASSWORD="${TEST_PASSWORD:-RabbitPass123!}"
TARGET_NAME="${TARGET_NAME:-my-rabbitmq}"
SECOND_TARGET_NAME="${SECOND_TARGET_NAME:-my-rabbitmq-second}"
BACKEND_USERNAME="${BACKEND_USERNAME:-wguser}"
BACKEND_PASSWORD="${BACKEND_PASSWORD:-wgpassword123}"
SECOND_BACKEND_USERNAME="${SECOND_BACKEND_USERNAME:-wguser2}"
SECOND_BACKEND_PASSWORD="${SECOND_BACKEND_PASSWORD:-wgpassword456}"
ROLE_NAME="test-rabbitmq-role"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
skip() { echo -e "  ${YELLOW}↷${NC} $*"; }

api_get()  { curl -sk -H "X-Warpgate-Token: $TOKEN" "$BASE/$1"; }
api_post() { curl -sk -X POST -H "Content-Type: application/json" -H "X-Warpgate-Token: $TOKEN" ${2:+-d "$2"} "$BASE/$1"; }

find_id_by_name() { # <endpoint> <name-field> <name>
    api_get "$1" | python3 -c "
import sys, json
for item in json.load(sys.stdin):
    if item.get('$2') == '$3':
        print(item['id'])
        break
"
}

# ── role ───────────────────────────────────────────────────────────────────────
ROLE_ID=$(find_id_by_name "roles" "name" "$ROLE_NAME")
if [[ -n "$ROLE_ID" ]]; then
    skip "Role '$ROLE_NAME' already exists (id: $ROLE_ID)"
else
    ROLE_ID=$(api_post "roles" "{\"name\":\"$ROLE_NAME\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
    ok "Created role '$ROLE_NAME' (id: $ROLE_ID)"
fi

# ── user + password credential ────────────────────────────────────────────────
USER_ID=$(find_id_by_name "users" "username" "$TEST_USERNAME")
if [[ -n "$USER_ID" ]]; then
    skip "User '$TEST_USERNAME' already exists (id: $USER_ID)"
else
    USER_ID=$(api_post "users" "{\"username\":\"$TEST_USERNAME\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
    ok "Created user '$TEST_USERNAME' (id: $USER_ID)"

    api_post "users/$USER_ID/credentials/passwords" "{\"password\":\"$TEST_PASSWORD\"}" >/dev/null
    ok "Set password credential: $TEST_PASSWORD"
fi

api_post "users/$USER_ID/roles/$ROLE_ID" >/dev/null 2>&1 || true
ok "Assigned $TEST_USERNAME -> $ROLE_NAME"

# ── First RabbitMQ target, authenticating to rabbitmq-target as wguser ────────
TARGET_ID=$(find_id_by_name "targets" "name" "$TARGET_NAME")
if [[ -n "$TARGET_ID" ]]; then
    skip "Target '$TARGET_NAME' already exists (id: $TARGET_ID)"
else
    TARGET_ID=$(api_post "targets" "{
      \"name\": \"$TARGET_NAME\",
      \"description\": \"RabbitMQ test target (docker rabbitmq-target:5672)\",
      \"options\": {
        \"kind\": \"RabbitMq\",
        \"host\": \"rabbitmq-target\",
        \"port\": 5672,
        \"username\": \"$BACKEND_USERNAME\",
        \"auth\": { \"kind\": \"Password\", \"password\": \"$BACKEND_PASSWORD\" },
        \"tls\": { \"mode\": \"Disabled\", \"verify\": true }
      }
    }" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
    ok "Created RabbitMQ target '$TARGET_NAME' -> rabbitmq-target:5672 as $BACKEND_USERNAME (id: $TARGET_ID)"
fi

api_post "targets/$TARGET_ID/roles/$ROLE_ID" >/dev/null 2>&1 || true
ok "Assigned $TARGET_NAME -> $ROLE_NAME"

# ── Second RabbitMQ target: distinct backend credentials + a default vhost ────
# Exercises TargetRabbitMqOptions.username/auth against a second backend
# identity, plus default_vhost (purely descriptive - the client's own
# Connection.Open vhost is what's actually forwarded).
SECOND_TARGET_ID=$(find_id_by_name "targets" "name" "$SECOND_TARGET_NAME")
if [[ -n "$SECOND_TARGET_ID" ]]; then
    skip "Target '$SECOND_TARGET_NAME' already exists (id: $SECOND_TARGET_ID)"
else
    SECOND_TARGET_ID=$(api_post "targets" "{
      \"name\": \"$SECOND_TARGET_NAME\",
      \"description\": \"RabbitMQ test target (docker rabbitmq-target-second:5672)\",
      \"options\": {
        \"kind\": \"RabbitMq\",
        \"host\": \"rabbitmq-target-second\",
        \"port\": 5672,
        \"username\": \"$SECOND_BACKEND_USERNAME\",
        \"auth\": { \"kind\": \"Password\", \"password\": \"$SECOND_BACKEND_PASSWORD\" },
        \"default_vhost\": \"/wgvhost\",
        \"tls\": { \"mode\": \"Disabled\", \"verify\": true }
      }
    }" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
    ok "Created RabbitMQ target '$SECOND_TARGET_NAME' -> rabbitmq-target-second:5672 as $SECOND_BACKEND_USERNAME (id: $SECOND_TARGET_ID)"
fi

api_post "targets/$SECOND_TARGET_ID/roles/$ROLE_ID" >/dev/null 2>&1 || true
ok "Assigned $SECOND_TARGET_NAME -> $ROLE_NAME"

echo ""
echo -e "${CYAN}Seed complete.${NC}"
echo "  AMQP login (authcid#target selector, PLAIN mechanism):"
echo "    user:     $TEST_USERNAME#$TARGET_NAME"
echo "    password: $TEST_PASSWORD"
echo "  Second target: $TEST_USERNAME#$SECOND_TARGET_NAME / $TEST_PASSWORD"
