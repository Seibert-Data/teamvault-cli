# Getting Started with `teamvault-cli`

`teamvault-cli` is a single command-line tool for reading secrets from a [TeamVault](https://github.com/trustedsec/teamvault) instance — passwords, usernames, URLs, and files — by their lookup key. It's built for both humans at a terminal and AI coding agents (e.g. Claude Code), as a company-sanctioned alternative to the 1Password `op` CLI for TeamVault-managed credentials.

One binary, a handful of subcommands, and your secret never has to sit in plaintext in a shell history or a repo.

## 1. Install

Pick the one for your OS. Each drops a single `teamvault-cli` binary on your `PATH`.

**macOS — [Homebrew](https://brew.sh) (recommended):**

```bash
brew install seibert-data/tap/teamvault-cli
```

Update later with `brew upgrade teamvault-cli`. The cask installs an unsigned binary and strips the download quarantine, so it runs without a Gatekeeper prompt.

**Linux — prebuilt release binary (no Go toolchain needed):**

```bash
curl -sSL "https://github.com/Seibert-Data/teamvault-cli/releases/latest/download/teamvault-cli_linux_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" | tar xz teamvault-cli && sudo install teamvault-cli /usr/local/bin/ && rm teamvault-cli
```

To update, re-run the command. (`x86_64` and `arm64`/`aarch64` are both covered.)

**Any platform — Go toolchain:**

```bash
go install github.com/Seibert-Data/teamvault-cli/v5@latest
```

Puts the binary in `$(go env GOPATH)/bin`.

Verify whichever you picked:

```bash
teamvault-cli --version
```

## 2. Configure

> **In a Claude Code session**, the `/teamvault-cli:setup` command walks through install, config, and login interactively — the rest of this section is the manual equivalent.

`teamvault-cli` needs to know your TeamVault URL and username. The password is best left out of the config file and stored in your macOS Keychain via `teamvault-cli login` (see step 3).

Create the config file. With no flag or env var set, the tool reads the first that exists, XDG path first:

1. `~/.config/teamvault-cli/config.json` (XDG — recommended; honors `$XDG_CONFIG_HOME`)
2. `~/.teamvault.json` (legacy fallback — still works)

```json
{
  "url": "https://teamvault.example.com",
  "user": "your-teamvault-username"
}
```

Two easy-to-miss details:

- **No trailing slash on `url`** — write `https://teamvault.example.com`, not `…/`. (Recent versions strip it defensively, but a trailing slash in an older config produced a double-slash API path that 404'd on the first fetch.)
- **`user` is your TeamVault username, not an email** — typically your directory/login name (some orgs derive it from your email's local part).

To use a different location, pass `--teamvault-config <path>` or export `TEAMVAULT_CONFIG=<path>` once (e.g. in your shell profile or a project `.envrc`) — both override the default lookup.

Every setting also has a flag and an environment variable, so you can skip the config file entirely if you prefer:

| Flag | Env var | Meaning |
|------|---------|---------|
| `--teamvault-url` | `TEAMVAULT_URL` | TeamVault base URL |
| `--teamvault-user` | `TEAMVAULT_USER` | your username |
| `--teamvault-pass` | `TEAMVAULT_PASS` | password (prefer Keychain via `login`) |
| `--teamvault-config` | `TEAMVAULT_CONFIG` | path to the JSON config above |
| `--teamvault-timeout` | `TEAMVAULT_TIMEOUT` | HTTP timeout (e.g. `5s`, `30s`) |
| `--cache` | `CACHE` | serve from a local disk cache if TeamVault is unreachable |
| `--staging` | `STAGING` | use fixture values instead of the real API |

Precedence is **flag → environment variable → config file**.

## 3. Log in (store your password in the Keychain)

```bash
teamvault-cli login
```

This prompts for your TeamVault password (input hidden), verifies it against the server, and stores it in your **macOS Keychain**. After that, you never pass `--teamvault-pass` again — every command reads the password from the Keychain automatically. (Keychain storage is macOS-only today; on other platforms, supply the password via `TEAMVAULT_PASS` or the config file.)

### Multiple instances (e.g. work and personal)

`teamvault-cli` handles more than one TeamVault at once. The Keychain stores each password keyed by the **instance URL**, so you `login` once per config and each resolves independently:

```bash
teamvault-cli login                                              # default instance (XDG config)
teamvault-cli login --teamvault-config ~/.teamvault-personal.json   # a second instance, its own config
```

Then point each call at the config you want — or let the default apply:

```bash
teamvault-cli password --teamvault-key <KEY>                                                 # default instance
teamvault-cli password --teamvault-config ~/.teamvault-personal.json --teamvault-key <KEY>   # second instance
```

The two configs must have **different URLs** — the Keychain key is the URL, so two configs sharing one URL would overwrite each other's stored password.

## 4. Read a secret

Every secret in TeamVault has a short **lookup key** — the alphanumeric ID in the TeamVault web UI URL when you open a secret (e.g. `https://teamvault.…/secret/AbC123/` → key `AbC123`).

```bash
teamvault-cli password --teamvault-key AbC123
teamvault-cli username --teamvault-key AbC123
teamvault-cli url      --teamvault-key AbC123
teamvault-cli file     --teamvault-key AbC123
```

Output is the raw value with **no trailing newline**, so it drops straight into other commands:

```bash
curl -u "$(teamvault-cli username --teamvault-key AbC123):$(teamvault-cli password --teamvault-key AbC123)" https://api.internal/…
```

## 5. Use it in projects with direnv

Instead of copying secrets into `.env` files, resolve them at shell-entry. In a project's `.envrc`:

```bash
export TEAMVAULT_CONFIG="$HOME/.teamvault.json"
export DB_PASSWORD="$(teamvault-cli password --teamvault-key AbC123)"
```

The secret lives only in memory for the session and never touches disk.

## 6. Use it with an AI agent (Claude Code)

When an agent needs a credential, have it call `teamvault-cli` rather than embedding secrets in prompts or code:

```bash
teamvault-cli password --teamvault-key AbC123
```

The agent gets the value it needs, the secret is resolved just-in-time from TeamVault, and nothing sensitive is written into the conversation or the repository. This is the sanctioned replacement for ad-hoc `op` usage on company-managed secrets.

## 7. Grant access (optional)

Grant a user or group read access to a secret, and check what is granted:

```bash
teamvault-cli share AbC123 --user nuke-apply-dev --description "dev apply reads it"
teamvault-cli share AbC123 AbC456 --group ops --description "ops on-call"
teamvault-cli shares AbC123
```

`share` prints one line per key — `<key> shared`, `<key> already-shared`, or `<key> refused (<status>: <server detail>)` — and exits non-zero when any key was refused, so a script cannot mistake a partial run for a clean one. Re-running a grant is safe: an existing grant reports `already-shared` instead of failing. Keys can be positional, repeated `--teamvault-key`, or `-` to read one key per line from stdin.

Add `--granted-until <RFC3339>` (e.g. `2030-01-01T00:00:00Z`) for an expiring grant; without it the grant is permanent.

`shares` lists the grant metadata — user, group, description, granted_by and granted_until — and never a secret value.

Sharing needs the `is_shareable_by_user` permission on the secret, so run it as an account that owns or may share it. A `403` here means that permission was refused, not that your login is wrong.

## 8. Config templating (optional)

Render config files with secrets pulled from TeamVault at build time:

- `teamvault-cli config parse` — reads a template from stdin, writes the rendered result to stdout.
- `teamvault-cli config generate --source-dir templates/ --target-dir out/` — renders every file in a directory tree.

## Command reference

| Command | Purpose |
|---------|---------|
| `teamvault-cli login` | verify credentials and store the password in the macOS Keychain |
| `teamvault-cli password --teamvault-key <KEY>` | print a secret's password |
| `teamvault-cli username --teamvault-key <KEY>` | print a secret's username |
| `teamvault-cli url --teamvault-key <KEY>` | print a secret's URL |
| `teamvault-cli file --teamvault-key <KEY>` | print a secret's file contents |
| `teamvault-cli share <KEY>... --user <NAME> --description <WHY>` | grant a user read access to one or more secrets |
| `teamvault-cli share <KEY>... --group <NAME> --description <WHY>` | grant a group read access to one or more secrets |
| `teamvault-cli shares <KEY>` | list who has read access to a secret |
| `teamvault-cli config parse` | render a template from stdin |
| `teamvault-cli config generate --source-dir <DIR> --target-dir <DIR>` | render a directory of templates |

Run `teamvault-cli <command> --help` for the full flag list on any subcommand.
