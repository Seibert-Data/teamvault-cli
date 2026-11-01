---
status: manual
---

# Scenario 010: `share` / `shares` round trip against a live TeamVault

Validates the two access-grant subcommands against a real server: create a throwaway secret, grant a real user read access through `share`, confirm `shares` lists the grant, read the secret back **as that user**, then delete the throwaway.

**Why `status: manual`, not `active`.** Every other scenario is either hermetic (`cmd/fakevault`, run by `make e2e`) or macOS-only. This one needs a live TeamVault **and** a second real account that exists as a Django user — TeamVault only creates that row on the account's first login, so the share would be refused with a validation error against an account that has never signed in. There is no way to fake that hermetically without adding a shares endpoint to `cmd/fakevault`, which this scenario deliberately does not require.

## Prerequisites

- The CLI is built from the branch under test (`go build -o /tmp/tv .`), not the installed release.
- You are logged in as an account that owns or may share the secret (`teamvault-cli login` once, in a plain terminal).
- The target account has logged in to TeamVault at least once, so its username resolves as a share target.
- You can reach the TeamVault web UI to delete the throwaway at the end.

## Setup

```bash
TV=/tmp/tv
TV_USER=<your-teamvault-username>
TARGET_USER=<the account receiving read access>
```

## Action + Expected

**1. Create a throwaway secret** (its value is what the "never a secret value" check below looks for).

```bash
SHARE_PW="share-scenario-$(date +%Y%m%d%H%M%S)"
KEY="$(printf '%s' "$SHARE_PW" | "$TV" create --name "teamvault-cli share scenario $(date -I)" --password-stdin)"
echo "$KEY"
```

- [ ] Prints a 6-character key, exit 0

**2. Grant access — the 201 path, on a key with no prior grant.**

```bash
"$TV" share "$KEY" --user "$TARGET_USER" --description "scenario 010 round trip"
```

- [ ] Prints `<key> shared`, exit 0

**3. Re-run the same grant — the idempotency path.**

```bash
"$TV" share "$KEY" --user "$TARGET_USER" --description "scenario 010 round trip"
```

- [ ] Prints `<key> already-shared`, **exit 0** (a duplicate is an outcome, not a failure)

**4. List the grants — metadata only.**

```bash
"$TV" shares "$KEY"
```

- [ ] The row carries the target user, `scenario 010 round trip`, and your username under `GRANTED_BY`
- [ ] `"$TV" shares "$KEY" | grep -cF "$SHARE_PW"` prints `0` — no secret value is ever listed

**5. The refusal path — a key that does not exist.**

```bash
"$TV" share ZZZZZZ --user "$TARGET_USER" --description "scenario 010 refusal"; echo "exit=$?"
```

- [ ] Prints `ZZZZZZ refused (404: …)`, and `exit=1`

**6. Read it back as the target account.** `~/.config/teamvault-cli/config.json` overwrites `TEAMVAULT_USER`/`TEAMVAULT_PASS` whenever it exists, so the check must pass an explicit config or the environment is silently ignored and the read happens as *you* — who can read everything, which would make this step pass for the wrong reason.

```bash
umask 077
cat > /tmp/tv-scenario-target.json <<JSON
{"url": "<https://your-teamvault-host>", "user": "$TARGET_USER", "password": "<that account's password>"}
JSON
"$TV" --teamvault-config /tmp/tv-scenario-target.json password --teamvault-key "$KEY"
rm -f /tmp/tv-scenario-target.json
```

- [ ] Prints the throwaway's password — the grant actually took effect

**7. Delete the throwaway** in the TeamVault web UI (`…/secret/<key>/` → delete). TeamVault has no CLI delete.

- [ ] The secret is gone; `"$TV" shares "$KEY"` now errors with 404

## Cleanup

Nothing automated. Step 7 is the cleanup, and it is manual by design — the CLI has no delete subcommand.

## What this scenario would not catch

It exercises the real server's share creation, duplicate detection and read grant. It does **not** cover `--group` (no group exists on the instance at time of writing) and it does not run in CI; the unit and fake-server specs cover the request body and the status mapping for both `--user` and `--group`.
