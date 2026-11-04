#!/usr/bin/env bash
# Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#
# Hermetic end-to-end test: start cmd/fakevault and drive the real teamvault-cli
# binary against it (no live TeamVault, no Keychain). Shares setup/assert helpers
# with the scenarios via scenarios/helper/lib.sh.
set -uo pipefail

source "$(cd "$(dirname "$0")/.." && pwd)/scenarios/helper/lib.sh"

echo "e2e: building binaries"
build_binaries
echo "e2e: starting fakevault"
start_fakevault
echo "e2e: fakevault at $FV_URL"

# Secret reads (config resolved via TEAMVAULT_CONFIG env — set by start_fakevault).
assert_eq "password" "demo-pass-123"              "$("$TV" password --teamvault-key demo)"
assert_eq "username" "demo-user"                  "$("$TV" username --teamvault-key demo)"
assert_eq "url"      "https://demo.example/login" "$("$TV" url --teamvault-key demo)"
assert_eq "file"     "demo-file-contents"         "$("$TV" file --teamvault-key demo)"

# config parse — Go-template funcs resolve secrets from stdin to stdout.
assert_eq "config parse" "user=demo-user pass=demo-pass-123" \
	"$(printf 'user={{ teamvaultUser "demo" }} pass={{ teamvaultPassword "demo" }}' | "$TV" config parse)"

# not-found — an unknown key errors (non-zero exit).
assert_exit_nonzero "not-found error" "$TV" password --teamvault-key nope-does-not-exist

# config via env var (TEAMVAULT_CONFIG) — already exported; resolve without a flag.
assert_eq "config via env" "demo-user" "$("$TV" username --teamvault-key demo)"

# config via flag (--teamvault-config) — with TEAMVAULT_CONFIG unset, the flag wins.
assert_eq "config via flag" "demo-user" \
	"$(env -u TEAMVAULT_CONFIG "$TV" username --teamvault-config "$WORK_DIR/config.json" --teamvault-key demo)"

# config generate — render a template directory tree to a target directory.
mkdir -p "$WORK_DIR/gen-src"
printf 'db_pass={{ teamvaultPassword "demo" }}' >"$WORK_DIR/gen-src/app.conf"
"$TV" config generate --source-dir "$WORK_DIR/gen-src" --target-dir "$WORK_DIR/gen-out"
assert_eq "config generate" "db_pass=demo-pass-123" "$(cat "$WORK_DIR/gen-out/app.conf")"

# auth failure — a config with the wrong password gets 401 → non-zero exit.
printf '{"url":"%s","user":"test","pass":"wrong"}\n' "$FV_URL" >"$WORK_DIR/badconfig.json"
assert_exit_nonzero "auth failure (401)" \
	"$TV" password --teamvault-config "$WORK_DIR/badconfig.json" --teamvault-key demo
# the auth-failure error should point the user at `teamvault-cli login`.
assert_contains "auth failure suggests login" "teamvault-cli login" \
	"$("$TV" password --teamvault-config "$WORK_DIR/badconfig.json" --teamvault-key demo 2>&1 1>/dev/null)"

# Basic-auth-safe: raw output has NO trailing newline ("demo-pass-123" = 13 bytes).
assert_eq "no trailing newline" "13" "$("$TV" password --teamvault-key demo | wc -c | tr -d ' ')"

# trailing-slash URL — a config whose url ends in "/" must still resolve (the CLI
# normalizes it; without that, "<url>//api/secrets/…" 404s). This is the exact
# value a user copies from the browser.
printf '{"url":"%s/","user":"test","pass":"test"}\n' "$FV_URL" >"$WORK_DIR/slashconfig.json"
assert_eq "trailing-slash url resolves" "demo-user" \
	"$(env -u TEAMVAULT_CONFIG "$TV" username --teamvault-config "$WORK_DIR/slashconfig.json" --teamvault-key demo)"

# --- Scenario 008: create / search / update / read-back ---------------------

# create --password-stdin — the primary, secure create path (no --password
# flag, which warns about shell-history/ps leakage).
NEW_KEY="$(printf 'first-secret-pw' | "$TV" create --name write-search-e2e-secret --username wse-user --password-stdin)"
assert_eq "create returned a non-empty key" "nonempty" "$([ -n "$NEW_KEY" ] && echo nonempty || echo empty)"

# read-back — the created secret resolves through the same GET path as the
# seeded fixtures.
assert_eq "read back created password" "first-secret-pw" "$("$TV" password --teamvault-key "$NEW_KEY")"
assert_eq "read back created username" "wse-user"         "$("$TV" username --teamvault-key "$NEW_KEY")"

# search — the new secret is found by a name substring, via
# GET /api/secrets/?search=... -> {"results":[{"hashid":...,"name":...}]}.
assert_contains "search finds the new secret" "$NEW_KEY" "$("$TV" search write-search-e2e-secret)"
assert_contains "search shows the created name" "write-search-e2e-secret" "$("$TV" search write-search-e2e-secret)"

# update (value change) — a new password creates a new revision; read-back
# reflects it.
printf 'updated-secret-pw' | "$TV" update "$NEW_KEY" --password-stdin >/dev/null
assert_eq "read back updated password" "updated-secret-pw" "$("$TV" password --teamvault-key "$NEW_KEY")"

# update (metadata-only) — no value flag; the password from the prior update
# must be left untouched.
"$TV" update "$NEW_KEY" --username wse-user-renamed >/dev/null
assert_eq "read back updated username"                  "wse-user-renamed"  "$("$TV" username --teamvault-key "$NEW_KEY")"
assert_eq "password unchanged by metadata-only update" "updated-secret-pw" "$("$TV" password --teamvault-key "$NEW_KEY")"

# --- Scenario 009: htpasswd derives a user:bcrypt line from a secret ---------

# Seeded fixture (demo -> username demo-user / password demo-pass-123): the
# htpasswd line carries the username verbatim and a bcrypt hash ($2...).
HTP_DEMO="$("$TV" htpasswd --teamvault-key demo)"
assert_contains "htpasswd carries the username prefix" "demo-user:" "$HTP_DEMO"
assert_contains "htpasswd emits a bcrypt hash"         '$2'         "$HTP_DEMO"
assert_eq "htpasswd is a single user:bcrypt line" "1" \
	"$(printf '%s\n' "$HTP_DEMO" | grep -c '^demo-user:\$2')"

# Freshly created secret: htpasswd reads username+password back over real HTTP
# (same write path as scenario 008) and hashes them.
HTP_KEY="$(printf 'reg-pw' | "$TV" create --name htpasswd-e2e-secret --username reg-user --password-stdin)"
HTP_NEW="$("$TV" htpasswd --teamvault-key "$HTP_KEY")"
assert_contains "htpasswd of a created secret carries its username" "reg-user:" "$HTP_NEW"
assert_contains "htpasswd of a created secret is bcrypt"            '$2'        "$HTP_NEW"

# Poisoned stored usernames (seeded fixtures — a seed bypasses the write-side
# check, which is the only way such a value can exist). A username carrying a
# newline must collapse onto ONE line instead of injecting a second principal.
HTP_NL="$("$TV" htpasswd --teamvault-key newline-user)"
assert_eq "htpasswd of a newline username is a single line" "1" \
	"$(printf '%s\n' "$HTP_NL" | wc -l | tr -d ' ')"
assert_contains "htpasswd collapses the newline into a space" "admin attacker:" "$HTP_NL"

# A colon is the htpasswd field separator, so it is stripped rather than
# corrupting the principal Apache reads.
HTP_COLON="$("$TV" htpasswd --teamvault-key colon-user)"
assert_contains "htpasswd strips the colon from the principal" "evilgarbage:" "$HTP_COLON"

# A username with no printable characters must fail loudly: a blank username
# makes Apache reject the whole file, which would break every credential in it.
assert_exit_nonzero "htpasswd of a blank username fails" "$TV" htpasswd --teamvault-key blank-user

# --- The --help leak and the environment password path ----------------------
#
# A flag default is printed by --help, so TEAMVAULT_PASS must not be one.
HELP_OUT="$(TEAMVAULT_PASS=secret-sentinel "$TV" --help 2>&1)"
case "$HELP_OUT" in
	*secret-sentinel*) echo "  FAIL: --help leaked TEAMVAULT_PASS"; _FAIL=1 ;;
	*) echo "  ok: --help does not leak TEAMVAULT_PASS" ;;
esac

# The env path still has to work. The fakevault config supplies the password and
# would mask the env var entirely (factory overwrites from the config file), so
# this removes the config and pairs a positive run against a negative one —
# without the control it would pass even if TEAMVAULT_PASS support were deleted.
ENV_ON="$(TEAMVAULT_PASS=test "$TV" --teamvault-config /nonexistent.json \
	--teamvault-url "$FV_URL" --teamvault-user test password demo 2>/dev/null)"
assert_eq "env password authenticates without a config file" "demo-pass-123" "$ENV_ON"

ENV_OFF_RC=0
TEAMVAULT_PASS= "$TV" --teamvault-config /nonexistent.json \
	--teamvault-url "$FV_URL" --teamvault-user test password demo >/dev/null 2>&1 || ENV_OFF_RC=$?
assert_eq "no password source fails" "nonzero" \
	"$([ "$ENV_OFF_RC" -ne 0 ] && echo nonzero || echo zero)"

scenario_done
