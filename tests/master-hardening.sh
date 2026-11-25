#!/usr/bin/env bash
# keycloak-init: what KEYCLOAK_INIT_ENABLED does to the master realm, on
# throwaway stacks this script brings up and tears down itself.
#
#   tests/master-hardening.sh              every scenario
#   tests/master-hardening.sh first fail   only those
#
# Each scenario starts a fresh stack under its own project name with its own
# env file (never the repository's .env), then reads the result from the
# database. Needs keycloak-network and traefik-network; the traefik scenario
# also needs ports 80 and 443 free.
#
# CI runs it in the master-hardening job.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROJECT="${PROJECT:-keycloak-init-test}"
DOCKER_COMPOSE_FILE="${DOCKER_COMPOSE_FILE:-keycloak-traefik-letsencrypt-docker-compose.yml}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93}"

ENV_FILE="$(mktemp)"
LOG="$(mktemp)"
ADMIN_PW="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"
DB_PW="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"

dc() { docker compose --env-file "$ENV_FILE" -f "$DOCKER_COMPOSE_FILE" -p "$PROJECT" "$@"; }
down() { dc down -v --remove-orphans >/dev/null 2>&1 || true; }
cleanup() {
  # On failure, the last stack's logs before it goes
  if [[ "$FAILS" -gt 0 ]]; then dc logs --tail 40 init keycloak 2>&1 || true; fi
  down; rm -f "$ENV_FILE" "$LOG"
}
FAILS=0
trap cleanup EXIT

pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; FAILS=$((FAILS + 1)); }
# same <got> <want> <what>
same() { if [[ "$1" == "$2" ]]; then pass "$3"; else fail "$3: expected ${2:-nothing}, got ${1:-nothing}"; fi; }
# differs <got> <unwanted> <what>
differs() { if [[ "$1" != "$2" ]]; then pass "$3"; else fail "$3: got $2"; fi; }

# env_file [extra lines]: the env file for the next stack
env_file() {
  cat > "$ENV_FILE" <<EOF
TRAEFIK_ACME_EMAIL=ci@example.com
TRAEFIK_HOSTNAME=traefik.keycloak.example.com
TRAEFIK_BASIC_AUTH=traefikadmin:\$\$2y\$\$10\$\$sMzJfirKC75x/hVpiINeZOiSm.Jkity9cn4KwNkRvO7hSQVFc5FLO
KEYCLOAK_DB_NAME=keycloakdb
KEYCLOAK_DB_USER=keycloakdbuser
KEYCLOAK_DB_PASSWORD=$DB_PW
KEYCLOAK_ADMIN_USERNAME=keycloakadmin
KEYCLOAK_ADMIN_PASSWORD=$ADMIN_PW
KEYCLOAK_HOSTNAME=keycloak.example.com
KEYCLOAK_BACKUP_INIT_SLEEP=30m
KEYCLOAK_BACKUP_INTERVAL=24h
KEYCLOAK_POSTGRES_BACKUP_PRUNE_DAYS=7
KEYCLOAK_POSTGRES_BACKUPS_PATH=/srv/keycloak-postgres/backups
KEYCLOAK_POSTGRES_BACKUP_NAME=keycloak-postgres-backup
EOF
  printf '%s\n' "$@" >> "$ENV_FILE"
}

# init: postgres and keycloak up, then the init service in the foreground; its
# exit status
init() {
  dc up -d --wait --wait-timeout 300 postgres keycloak >"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }
  dc up init --exit-code-from init --no-log-prefix >"$LOG" 2>&1
}

sql() { dc exec -T postgres psql -U keycloakdbuser -d keycloakdb -tAc "$1"; }
realm() { sql "select $2 from realm where name='$1'"; }
attr() { sql "select value from realm_attribute a join realm r on r.id = a.realm_id where r.name = '$1' and a.name = '$2'"; }
passkeys() { sql "select coalesce(string_agg(value, ','), '') from realm_attribute a join realm r on r.id = a.realm_id where r.name = '$1' and a.name ilike '%passkeysenabled%'"; }
otp_default() { sql "select default_action from required_action_provider p join realm r on r.id = p.realm_id where r.name = '$1' and p.alias = 'CONFIGURE_TOTP'"; }
temp_admin() { sql "select count(*) from client where client_id = 'temp-admin'"; }
admin_id() { sql "select id from user_entity where username = 'keycloakadmin'"; }
admin_mark() { sql "select count(*) from user_attribute a join user_entity u on u.id = a.user_id where u.username = 'keycloakadmin' and a.name = 'is_temporary_admin'"; }
admin_actions() { sql "select coalesce(string_agg(required_action, ',' order by required_action), '') from user_required_action a join user_entity u on u.id = a.user_id where u.username = 'keycloakadmin'"; }

# admin_sign_in: the password grant for the bootstrap admin with the .env
# password, the password sent on stdin; "token" or Keycloak's error_description
admin_sign_in() {
  { printf 'grant_type=password&client_id=admin-cli&username=keycloakadmin&password='; printf '%s' "$ADMIN_PW"; } \
    | docker run --rm -i --network keycloak-network "$CURL_IMAGE" -s --data-binary @- \
      "http://${PROJECT}-keycloak-1:8080/realms/master/protocol/openid-connect/token" \
    | sed -nE -e 's/.*"access_token".*/token/p' -e 's/.*"error_description":"([^"]*)".*/\1/p'
}

# bootstrap_service <env var> [value]: kc.sh bootstrap-admin service with
# Keycloak stopped, the secret read from that variable
bootstrap_service() {
  dc stop keycloak >/dev/null 2>&1
  dc run --rm --no-deps -T ${2:+-e "$1=$2"} keycloak \
    bootstrap-admin service --client-secret:env "$1" --no-prompt >"$LOG" 2>&1
}

# the master baseline, every row on
master_applied() {
  same "$(attr master bruteForceProtected)" true "brute force detection on"
  same "$(attr master permanentLockout)" false "temporary lockout only"
  same "$(attr master maxSecondaryAuthFailures)" 100 "OTP failures lockout at 100"
  same "$(realm master password_policy)" "length(15) and maxLength(64) and notUsername and notEmail" "password policy"
  same "$(otp_default master)" t "OTP setup a default required action"
  same "$(realm master access_code_lifespan)" 9 "authorization codes valid 9 seconds"
  same "$(passkeys master)" true "passkeys on"
  same "$(attr master offlineSessionMaxLifespanEnabled)/$(attr master offlineSessionMaxLifespan)" true/86400 "offline sessions end after 24 hours"
  same "$(realm master "events_enabled::text || '/' || admin_events_enabled::text")" true/true "login and admin events stored"
}

scenario_off() {
  echo "keycloak-init off: master as Keycloak leaves it"
  down; env_file
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0"
  same "$(temp_admin)" 0 "no temp-admin"
  same "$(admin_actions)" "" "bootstrap admin untouched"
  same "$(admin_sign_in)" token "bootstrap admin signs in with the .env password"
  same "$(attr master bruteForceProtected)" false "brute force detection still off"
}

scenario_first() {
  echo "keycloak-init on, first start"
  down; env_file KEYCLOAK_INIT_ENABLED=true
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0"
  same "$(temp_admin)" 0 "temp-admin deleted"
  master_applied
  same "$(attr master frontendUrl)" "" "no frontend URL without an admin hostname"
  same "$(admin_actions)" CONFIGURE_TOTP,UPDATE_PASSWORD "bootstrap admin must set a new password and OTP"
  same "$(admin_sign_in)" "Account is not fully set up" "the .env password only starts that setup"
  same "$(admin_mark)" 1 "bootstrap admin kept, still marked temporary"
  local id; id="$(admin_id)"

  echo "the next start"
  dc restart keycloak >/dev/null 2>&1
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0, nothing to do"
  same "$(admin_id)" "$id" "bootstrap admin unchanged"

  echo "re-applying: bootstrap-admin service with KC_BOOTSTRAP_ADMIN_CLIENT_SECRET"
  sql "update realm set access_code_lifespan = 60 where name = 'master'" >/dev/null
  bootstrap_service KC_BOOTSTRAP_ADMIN_CLIENT_SECRET
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0"
  same "$(realm master access_code_lifespan)" 9 "setting applied again"
  same "$(temp_admin)" 0 "temp-admin deleted"
  same "$(admin_id)" "$id" "bootstrap admin unchanged"

  echo "a plain recovery: bootstrap-admin service with another secret"
  bootstrap_service RECOVERY_SECRET "$DB_PW"
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0"
  same "$(temp_admin)" 1 "that temp-admin left alone"
}

scenario_off_rows() {
  echo "keycloak-init on, every row off, the README syntax example only"
  down; env_file KEYCLOAK_INIT_ENABLED=true \
    KEYCLOAK_INIT_BRUTE_FORCE=false KEYCLOAK_INIT_OTP_LOCKOUT=false KEYCLOAK_INIT_PASSWORD_POLICY=false \
    KEYCLOAK_INIT_OTP_REQUIRED=false KEYCLOAK_INIT_AUTH_CODE_LIFESPAN=false KEYCLOAK_INIT_PASSKEYS=false \
    KEYCLOAK_INIT_OFFLINE_SESSION_MAX=false KEYCLOAK_INIT_EVENTS=false \
    'KEYCLOAK_INIT_EXTRA_COMMANDS="' \
    '# A line starting with # is skipped, and so is a blank line.' \
    "update realms/master -s 'displayName=Example admin'" \
    '' \
    '  # Indenting is fine, and so is a comment after a command.' \
    '  update realms/master -s loginWithEmailAllowed=false   # usernames only' \
    '# update realms/master -s registrationAllowed=true' \
    '"'
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0"
  same "$(attr master bruteForceProtected)" false "brute force detection untouched"
  same "$(realm master password_policy)" "" "no password policy"
  same "$(otp_default master)" f "OTP setup not a default"
  same "$(realm master access_code_lifespan)" 60 "authorization codes untouched"
  differs "$(passkeys master)" true "passkeys untouched"
  same "$(realm master events_enabled)" f "events untouched"
  same "$(admin_actions)" UPDATE_PASSWORD "bootstrap admin must still set a new password"
  same "$(realm master display_name)" "Example admin" "README syntax example: quoted value applied"
  same "$(realm master login_with_email_allowed)" f "README syntax example: indented line with a comment applied"
  same "$(realm master registration_allowed)" f "README syntax example: commented-out line skipped"
}

scenario_admin_hostname() {
  echo "keycloak-init on with KEYCLOAK_ADMIN_HOSTNAME"
  down; env_file KEYCLOAK_INIT_ENABLED=true KEYCLOAK_ADMIN_HOSTNAME=keycloak-admin.example.com
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0"
  same "$(attr master frontendUrl)" https://keycloak-admin.example.com "master frontend URL set"
  same "$(temp_admin)" 0 "temp-admin deleted"
}

scenario_not_true() {
  echo "KEYCLOAK_INIT_ENABLED=false"
  down; env_file KEYCLOAK_INIT_ENABLED=false
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0"
  same "$(temp_admin)" 0 "the temp-admin Keycloak created is deleted"
  same "$(admin_actions)" "" "bootstrap admin untouched"
  same "$(attr master bruteForceProtected)" false "nothing applied"
}

scenario_readme() {
  echo "README example: another realm at the same level, one line commented out"
  down; env_file KEYCLOAK_INIT_ENABLED=true \
    'KEYCLOAK_INIT_EXTRA_COMMANDS="' \
    'create realms -s realm=employee -s enabled=true' \
    'update realms/employee -s bruteForceProtected=true' \
    'update realms/employee -s permanentLockout=false' \
    'update realms/employee -s maxSecondaryAuthFailures=100' \
    "update realms/employee -s 'passwordPolicy=length(15) and maxLength(64) and notUsername and notEmail'" \
    'update authentication/required-actions/CONFIGURE_TOTP -r employee -s enabled=true -s defaultAction=true' \
    'update realms/employee -s accessCodeLifespan=9' \
    '# update realms/employee -s webAuthnPolicyPasswordlessPasskeysEnabled=true' \
    'update realms/employee -s offlineSessionMaxLifespanEnabled=true -s offlineSessionMaxLifespan=86400' \
    'update realms/employee -s eventsEnabled=true' \
    'update realms/employee -s adminEventsEnabled=true' \
    '"'
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0"
  same "$(attr employee bruteForceProtected)/$(attr employee permanentLockout)" true/false "employee: brute force detection"
  same "$(attr employee maxSecondaryAuthFailures)" 100 "employee: OTP failures lockout"
  same "$(realm employee password_policy)" "length(15) and maxLength(64) and notUsername and notEmail" "employee: password policy"
  same "$(otp_default employee)" t "employee: OTP setup a default"
  same "$(realm employee access_code_lifespan)" 9 "employee: authorization codes"
  differs "$(passkeys employee)" true "employee: the commented-out passkeys line skipped"
  same "$(attr employee offlineSessionMaxLifespanEnabled)/$(attr employee offlineSessionMaxLifespan)" true/86400 "employee: offline sessions"
  same "$(realm employee "events_enabled::text || '/' || admin_events_enabled::text")" true/true "employee: events"

  echo "README example: removing the temporary-admin mark"
  down
  # shellcheck disable=SC2016 # expanded by keycloak-init, not here
  env_file KEYCLOAK_INIT_ENABLED=true \
    'KEYCLOAK_INIT_EXTRA_COMMANDS="' \
    'update users/profile -s unmanagedAttributePolicy=ADMIN_EDIT' \
    'update users/$(kcadm get users -q username=$KEYCLOAK_ADMIN_USERNAME -q exact=true --fields id --format csv --noquotes) -s attributes={}' \
    'update users/profile -d unmanagedAttributePolicy' \
    '"'
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0"
  same "$(admin_mark)" 0 "mark removed"
  same "$(admin_actions)" CONFIGURE_TOTP,UPDATE_PASSWORD "new password and OTP still required"
  same "$(sql "select count(*) from component_config where value ilike '%unmanagedAttributePolicy%'")" 0 "user profile back to its default"
}

scenario_fail() {
  echo "a failing extra command: temp-admin kept until .env is fixed"
  down; env_file KEYCLOAK_INIT_ENABLED=true KEYCLOAK_INIT_EXTRA_COMMANDS=no-such-command
  init && rc=0 || rc=$?
  differs "$rc" 0 "keycloak-init fails"
  same "$(temp_admin)" 1 "temp-admin kept"
  same "$(grep -q 'STILL THERE' "$LOG" && echo yes)" yes "the log says so"
  same "$(admin_actions)" "" "bootstrap admin untouched yet"
  sed -i 's/^KEYCLOAK_INIT_EXTRA_COMMANDS=.*/KEYCLOAK_INIT_EXTRA_COMMANDS=/' "$ENV_FILE"
  init && rc=0 || rc=$?
  same "$rc" 0 "keycloak-init exits 0 once fixed"
  same "$(temp_admin)" 0 "temp-admin deleted"
  same "$(admin_actions)" CONFIGURE_TOTP,UPDATE_PASSWORD "bootstrap admin hardened"
}

scenario_traefik() {
  echo "the whole stack: a failing keycloak-init keeps Traefik down"
  down; env_file KEYCLOAK_INIT_ENABLED=true KEYCLOAK_INIT_EXTRA_COMMANDS=no-such-command
  dc up -d --wait --wait-timeout 300 >"$LOG" 2>&1 && rc=0 || rc=$?
  differs "$rc" 0 "docker compose up fails"
  same "$(grep -q "init.*didn't complete successfully" "$LOG" && echo yes)" yes "and names init"
  same "$(dc ps -q traefik)" "" "Traefik not running"
  sed -i 's/^KEYCLOAK_INIT_EXTRA_COMMANDS=.*/KEYCLOAK_INIT_EXTRA_COMMANDS=/' "$ENV_FILE"
  dc up -d --wait --wait-timeout 300 >"$LOG" 2>&1 && rc=0 || rc=$?
  same "$rc" 0 "docker compose up succeeds once fixed"
  differs "$(dc ps -q traefik)" "" "Traefik running"

  echo "the whole stack with keycloak-init off"
  down; env_file
  dc up -d --wait --wait-timeout 300 >"$LOG" 2>&1 && rc=0 || rc=$?
  same "$rc" 0 "docker compose up succeeds"
  differs "$(dc ps -q traefik)" "" "Traefik running"
}

for s in "${@:-off first off_rows admin_hostname not_true readme fail traefik}"; do
  for t in $s; do "scenario_$t"; done
done

if [[ "$FAILS" -gt 0 ]]; then
  echo "$FAILS check(s) failed"
  exit 1
fi
echo "every master hardening check passed"
