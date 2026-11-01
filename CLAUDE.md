# CLAUDE.md

TeamVault CLI — reads secrets (password / username / url / file) from a TeamVault server by lookup key. Ships as a single `teamvault-cli` binary, a Go library, and a Claude Code plugin.

## Development Standards

Follows the [coding-guidelines](https://github.com/bborbe/coding-guidelines).

### Build and test

- `make precommit` — format, generate, test, lint, vet, vulncheck, osv, trivy, license (run before every commit)
- `make test` — tests only
- `make generate` — regenerate Counterfeiter mocks into `pkg/mocks/`

### Test conventions

- Ginkgo/Gomega; one `RunSpecs` per test binary (`*_suite_test.go`)
- Counterfeiter mocks (`//counterfeiter:generate` directives, output to `pkg/mocks/`)
- External test packages (`package teamvault_test`, `package cli_test`)
- macOS-only Keychain paths are covered by `scenarios/001`–`005` (manual walk, real TeamVault + Keychain) — unit tests mock the keychain/executor and have shipped runtime-broken releases before, so run the scenario walk when touching login/keychain/secret-read paths.

## Architecture

- `main.go` — entry point at the module root; `func main()` → `cli.Execute()`. **Binary is named after the module base → `teamvault-cli`.**
- `pkg/` — `package teamvault`, the library. Connector interface + variants (`remote-connector.go`, `cache-connector.go`, `diskfallback-connector.go`, `dummy-connector.go`), template rendering (`config-parser.go`, `config-generator.go`), macOS Keychain (`keychain.go`, `keychain_impl.go`), value types (`key.go`, `api-url.go`, `staging.go`).
- `pkg/cli/` — cobra root command + subcommand factories (`cli.go`, `login.go`, `config.go`). One templated handler drives the four secret readers; `login` has its own path.
- `pkg/factory/` — `Create*` wiring (the one place that depends on every other package).
- `pkg/mocks/` — generated Counterfeiter fakes.

Library import path: `github.com/Seibert-Data/teamvault-cli/v5/pkg` (package `teamvault`).

## Key Design Decisions

- **Binary at the module root** — `main.go` lives at root so `go install …/v5@latest` produces a `teamvault-cli` binary. Do **not** reintroduce a `cmd/` dir.
- **Library stays in `pkg/`** (flat, `package teamvault`) with `pkg/factory/` split out — per [go-package-layout-guide](https://github.com/bborbe/coding-guidelines/blob/master/docs/go-package-layout-guide.md). Root holds only `main.go` + `pkg/`.
- **Secret readers print with NO trailing newline** — `password`/`username`/`url`/`file` output the raw value so `curl -u "$(… password …)"` is basic-auth-safe. Do not add a newline.
- **`KeychainServiceName = "teamvault-cli"`** (`pkg/keychain.go`) is the macOS Keychain storage key — renaming it orphans every user's stored credential. Treat as stable.
- **Persistent flags are seeded from `TEAMVAULT_*` env vars** — preserves the `.envrc`/direnv contract. Keep the arg + env names exactly.
- **Write surface is deliberate and closed** — `login` writes only to the local Keychain; `create`, `update`, `htpasswd`, `share` and `shares` call the TeamVault API. Add a command only when the server already exposes the operation and the CLI can print a per-item result the operator can check; `share`/`shares` exist because a grant made by hand in the web UI leaves no record of what succeeded.
- **bborbe conventions** — wrap errors with `github.com/bborbe/errors` (no `fmt.Errorf`), no `context.Background()` in business logic, `libtime` types over `time.Now()`. Factory functions are pure composition.

## Releases & Agents

Owned by `Seibert-Data` and managed by the Octopus agents (`.maintainer.yaml`: `autoRelease` + `autoApprove`):

- Add `## Unreleased` bullets in `CHANGELOG.md`. The pr-reviewer agent reviews PRs; a human merges the approved PR (the merge gate needs the bot's APPROVE — no admin bypass); the releaser agent tags `vX.Y.Z`.
- The releaser **refuses major bumps** (`major_bump_not_allowed`). The module major is `/v5` and stays there — if a change is classified major, tag `v5.x` by hand (never let it cut `v6.0.0` on a `/v5` module).

## Dark Factory (optional)

The repo carries `.dark-factory.yaml` + `prompts/`/`specs/`; code changes may go through the dark-factory YOLO flow. Prompts/specs go to the `prompts/`/`specs/` inbox roots (never `in-progress/`/`completed/`), never numbered by hand, never approve without user confirmation. See the dark-factory guides before authoring.
