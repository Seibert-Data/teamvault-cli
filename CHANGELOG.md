# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- fix: justify the #nosec G115 directive in isTTYStdin
- fix: correct "form" typo in the api-url parse error message

## v5.10.0

- test(e2e): add scenario 009 covering `htpasswd` end-to-end against fakevault (seeded fixture + a freshly created secret)
- feat(cli): add `htpasswd <KEY>` subcommand that prints an htpasswd-format credential (`user:$2...` bcrypt) built from a TeamVault secret's username + password, for secret-free htpasswd generation at deploy time (e.g. `--set-string secrets.htpasswd=$(teamvault-cli htpasswd <KEY>)`). Reuses the existing `HtpasswdGenerator` (same bcrypt path as the `teamvaultHtpasswd` config template func).
- feat(cli): `search` now prints an aligned `KEY  NAME` table by default, follows TeamVault pagination so results are not truncated to the first page, adds `--limit N` to cap results and `--keys-only` for bare-key-per-line scripting output. `--json` now emits an array of `{key,name,username,url}` objects instead of an array of key strings (breaking output-shape change).

## v5.9.1

- test: add hermetic end-to-end scenario for create/update/search via fakevault
- fix: bump golang.org/x/net (→v0.57.0) and golang.org/x/text (→v0.40.0) to clear trivy CVE-2026-46600 / CVE-2026-56852
- chore: bump bborbe/* module deps and ginkgo/gomega, x/crypto, x/tools, sentry-go

## v5.9.0

- feat(cli): add a `search <query>` subcommand that lists the keys of secrets matching a name search (`GET /api/secrets/?search=…`). Prints one key per line by default, or a JSON array of keys with `--json`. Zero matches exits 0 (empty output, or `[]` with `--json`).

## v5.8.0

- feat(library): add a `Writer` interface to `package teamvault` for creating secrets (`POST /api/secrets/`), updating existing secrets (`PATCH /api/secrets/<key>/`), and generating strong passwords (`POST /api/generate_password/`). Exposed via `NewRemoteWriter` and `CreateRemoteWriter` factory, reusing the read path's Basic-auth header, HTTP client, timeout, and non-2xx/auth error messaging. The existing `Connector` interface is unchanged — no breaking change to library consumers.

- feat(cli): add `create` and `update <key>` subcommands to `teamvault-cli`. The `create` command creates a new secret (password or file), requiring exactly one value source (`--password-stdin`, `--generate`, `--password`, or `--file`). The `update` command modifies an existing secret, allowing metadata-only changes (no value flag) or a new value. Password input is secure by default (`--password-stdin` reads from stdin; `--generate` asks the server); `--password` warns about shell-history/`ps` leak risk. The four value sources are mutually exclusive. Output is the bare key (no trailing newline) or `{"key","api_url"}` with `--json`.

## v5.7.0

- feat(cli): accept the TeamVault key as a positional argument on `password`/`username`/`url`/`file` (e.g. `teamvault-cli password AbC123`); `--teamvault-key` is no longer required and still works for backward compatibility. Add a `--json` flag to those four commands for keyed JSON output (e.g. `{"password":"…"}`), default raw-value output unchanged. Add a new `info` subcommand (`teamvault-cli info <KEY>`) that fetches username/url/password/file in one call and prints an aligned table, or a single JSON object with `--json`.

## v5.6.1

- docs: keep the public repo vendor-neutral — replace company-specific examples (domain, email, username) in the `/teamvault-cli:setup` command, the `teamvault` skill, docs, a code comment, and test data with generic placeholders (`teamvault.example.com`, `<your-username>`). Company-specific onboarding lives in downstream skill repos. Also add a "multiple instances (work + personal)" section to the getting-started guide.

## v5.6.0

- feat(cli): add the `/teamvault-cli:setup` Claude Code command — a guided first-time setup (Homebrew install, interactive+non-interactive PATH check, XDG config, login instruction, verify). It configures + instructs + verifies but never runs `login` itself, so the interactive password never enters an AI session.
- fix(url): strip a trailing slash (and surrounding whitespace) from the base TeamVault URL via `Url.Normalize()`, applied in `NewRemoteConnector` and the Keychain read/write. A configured base URL with a trailing slash (e.g. `https://teamvault.example.com/`) previously produced a double-slash API path (`…//api/secrets/…`) that 404'd on the first fetch; normalizing in both places also keeps the Keychain key consistent between `login` (write) and fetch (read). Added unit tests + a hermetic trailing-slash e2e case.
- docs(skill): sharpen the config guidance — `user` is your TeamVault username (typically a directory/login name, not an email), `url` has no trailing slash, and `login` runs in a plain terminal (never paste a secret into an AI session). Point new users at `/teamvault-cli:setup`.

## v5.5.3

- docs(skill): expand the "Handling secrets safely" section of the Claude Code skill with the inbound cloud-session risk — never ask the user to paste a secret, rotate any credential that reaches the transcript, and state the "credentials never leak" rule standalone so it holds for users outside the company who lack the org policy.

## v5.5.2

- fix(auth): on a `401`/`403` from TeamVault, and on a Keychain-read failure, the error now points the user at `teamvault-cli login` to (re)store their password — e.g. after the v5.2.0 Keychain service rename (`teamvault-utils` → `teamvault-cli`), a first fetch would 403 with no hint.
- refactor(errors): make `pkg/remote-connector.go` compliant with the `github.com/bborbe/errors` wrapping guide — replace `fmt.Errorf`/bare `return err` with `errors.Wrapf(ctx, …)`, and introduce `ErrUserType`/`ErrPasswordType` sentinels for the ctx-less `UnmarshalJSON` paths.

## v5.5.1

- test(e2e): add `cmd/fakevault` — a fake TeamVault HTTP server with seeded secrets — plus a `make e2e` target, scenario 007, and a CI job that drives the real `teamvault-cli` binary against it (temp config + `TEAMVAULT_PASS`, no live TeamVault / Keychain). Exercises the real HTTP connector, Basic-auth, and JSON-parse path that `--staging` and unit tests do not; makes the read scenarios hermetic and CI-runnable. `fakevault` is a test helper and is not shipped.

## v5.5.0

- feat(config): default the config location when neither `--teamvault-config` nor `TEAMVAULT_CONFIG` is set — read the XDG path `~/.config/teamvault-cli/config.json` (honors `$XDG_CONFIG_HOME`) if present, else the legacy `~/.teamvault.json`. No config was read by default before; explicit flag/env still override, and an absent file keeps prior behaviour. Aligns with the XDG Base Directory convention used across the toolchain.
- docs: add per-OS install instructions across the README, the getting-started guide, and the Claude Code skill — Homebrew for macOS (`brew install seibert-data/tap/teamvault-cli`), a prebuilt-binary `curl` one-liner for Linux (no Go toolchain needed), and `go install` as the any-platform fallback.

## v5.4.0

- feat(cli): add `--version` — `teamvault-cli --version` prints the release. Injected at build time via `-ldflags` (`make install`), with a `debug.ReadBuildInfo` fallback so `go install …/v5@vX.Y.Z` also reports the real module version.

## v5.3.0

- change(cli): the binary is now named **`teamvault-cli`** (was `teamvault`) — the entry point moved to the module root, so install is `go install github.com/Seibert-Data/teamvault-cli/v5@latest` (no more `/cmd/teamvault`). Update call sites: `teamvault password …` → `teamvault-cli password …`. The `TEAMVAULT_*` env/flag contract, the `~/.teamvault.json` config, and the Keychain service name are unchanged.
- docs: add `CLAUDE.md` (agent-operational context — build, architecture, design decisions) and restructure `README.md` around usage scenarios (install, Claude Code plugin, configure, shell scripts, k8s config templating, AI agents).

## v5.2.0

- chore(repo): relocated to the **`Seibert-Data`** org — module path is now `github.com/Seibert-Data/teamvault-cli/v5`; install with `go install github.com/Seibert-Data/teamvault-cli/v5/cmd/teamvault@latest`. (Was `github.com/seibert-media/teamvault-cli/v5` in v5.1.0; the seibert-media and bborbe URLs redirect.) Binary name, `cmd/teamvault` layout, and the `teamvault-cli` Keychain service are unchanged; only Go library importers update the import path.
- change(keychain): rename the macOS Keychain service name `teamvault-utils` → `teamvault-cli`. After upgrading, run `teamvault login` once to store the password under the new service name. The old `teamvault-utils` entry is left intact, so a previously-installed `teamvault-utils` binary keeps working in parallel.
- docs: finish the `teamvault-utils` → `teamvault-cli` rename in the plugin command, docs prose, scenario build paths, and the `docs/releasing-*` filename (the Go library import paths and module path already moved in v5.1.0).

## v5.1.0

- chore(repo): the project is now company-owned at **`github.com/seibert-media/teamvault-cli`** (transferred from `github.com/bborbe/teamvault-utils`, IT-44264). Module path becomes `github.com/seibert-media/teamvault-cli/v5` — install with `go install github.com/seibert-media/teamvault-cli/v5/cmd/teamvault@latest`. The `teamvault` binary name and `cmd/teamvault` layout are unchanged; only Go library importers must update the import path. The Claude Code plugin is renamed `teamvault-utils` → `teamvault-cli` (the `teamvault` skill inside is unchanged); re-add via `claude plugin marketplace add seibert-media/teamvault-cli`.

## v5.0.3

- refactor(library): move the Go library package from the module root into `pkg/` — import `github.com/bborbe/teamvault-utils/v5/pkg` (package `teamvault`), was `github.com/bborbe/teamvault-utils/v5`. Aligns the layout with the go-package-layout guide (all production code under `pkg/`; the module root now holds only `cmd/` and `pkg/`). The `teamvault` binary and its `go install github.com/bborbe/teamvault-utils/v5/cmd/teamvault@latest` install path are unchanged — only Go library importers must update the import path.

## v5.0.2

- fix(cli): the installed binary is now named **`teamvault`** — the entry point moved to `cmd/teamvault/`. Install with `go install github.com/bborbe/teamvault-utils/v5/cmd/teamvault@latest` (v5.0.1 installed a `teamvault-utils` binary because the entry point was at the module root).
- refactor(library): the Go library moves back to the module root — import `github.com/bborbe/teamvault-utils/v5` again (was `github.com/bborbe/teamvault-utils/v5/pkg/teamvault` in v5.0.0/v5.0.1). Minimal `/v4`→`/v5` bump for library consumers.
- feat(plugin): add a Claude Code plugin — a `teamvault` skill and `/teamvault` command that help set up the CLI and fetch TeamVault secrets from a Claude Code session, with a hard rule to never write a secret into the conversation, a file, or a commit.

## v5.0.1

- fix(install): remove the `exclude (cloud.google.com/go v0.26.0)` directive from `go.mod` — Go forbids `exclude`/`replace` directives when installing a module as a tool, so it made `go install github.com/bborbe/teamvault-utils/v5@latest` fail. (v5.0.0 is tagged but not installable; v5.0.1 is the first installable v5.)
- fix(login): `teamvault login` now rejects a negative `--teamvault-timeout` (and config `timeout`) and honors the config-file timeout, matching the other subcommands — previously a negative value silently disabled the HTTP timeout.
- test: harden CLI tests — the no-trailing-newline tests assert command success; add login-CLI-wiring tests (incl. the negative-timeout regression) and a `config generate` happy-path test.
- refactor: deduplicate the four secret-reader subcommands and the login password-verify block into shared helpers; wrap previously-bare errors.
- docs: refocus `README.md` on CLI usage for end users (install → login → read a secret → getting-started link); move the Go library examples out to `docs/library.md`.

## v5.0.0

**Breaking (v5): the seven `teamvault-*` binaries are replaced by a single `teamvault` command.**

- feat: Consolidate the seven binaries (`teamvault-login`, `teamvault-password`, `teamvault-username`, `teamvault-url`, `teamvault-file`, `teamvault-config-parser`, `teamvault-config-dir-generator`) into one `teamvault` command built with `spf13/cobra`. Subcommands: `login`, `password`, `username`, `url`, `file`, and `config parse` / `config generate`. Install with `go install github.com/bborbe/teamvault-utils/v5@latest`.
- build: bump module path to `github.com/bborbe/teamvault-utils/v5` (major/breaking). The library moves from the module root into `pkg/teamvault` (and the factory into `pkg/factory`), with a thin root `main.go`; library consumers update imports from `github.com/bborbe/teamvault-utils/v5` to `github.com/bborbe/teamvault-utils/v5/pkg/teamvault`.
- feat: the seven shared flags (`--teamvault-url/-user/-pass/-config`, `--staging`, `--cache`, `--teamvault-timeout`) are persistent on the root command, each still falling back to its `TEAMVAULT_*`/`STAGING`/`CACHE` env var — the existing `.envrc`/direnv contract is preserved; only the invocation changes (`teamvault-password …` → `teamvault password …`).
- fix: `password`/`username`/`url`/`file` print the resolved value with NO trailing newline, fixing the `curl -u` basic-auth breakage.
- feat: clean `--help` — cobra/pflag use a private flag set, eliminating the Ginkgo/glog flag pollution the old `argument/v2`-based binaries leaked into `--help`.
- fix: errors print exactly once (`SilenceErrors: true`) with a non-zero exit, instead of the doubled cobra + handler message.
- build: drop the now-unused `github.com/bborbe/service` and `github.com/bborbe/argument/v2` dependencies.

## v4.13.2

- fix(security): unblock `make precommit` baseline. Bump `go` directive 1.26.4 → 1.26.5 to clear stdlib advisory GO-2026-5856 (osv-scanner). Suppress GO-2026-5932 (`golang.org/x/crypto/openpgp` unmaintained/unsafe, no fix version, package not imported) in `VULNCHECK_IGNORE` (govulncheck) and `.trivyignore` (trivy).

## v4.13.1

- bump go 1.26.3 → 1.26.4
- update bborbe/* and golang.org/x/* dependencies
- drop errcheck + gosec standalone tools; inline config in golangci.yml
- add .maintainer.yaml (autoRelease + autoApprove)
- disable dark-factory autoRelease

## v4.13.0

- refactor: Migrate keychain implementation from hand-rolled `security` shell-out to `github.com/zalando/go-keyring`. Eliminates the REPL-script construction and quoting logic that produced bugs in v4.10–v4.12. Linux and Windows now have a working credential store as a side effect (Secret Service / Credential Manager). File renamed `keychain_darwin.go` → `keychain_impl.go` to drop the filename-implicit `_darwin` build constraint. The internal `Executor` interface, `osExecutor` type, and `NewKeychainWithExecutor` constructor are removed; new `NewKeychainWithClient(KeyringClient) Keychain` exposes the test seam. Backward-compatible read: Keychain entries written by v4.10–v4.12 remain readable. See spec 004.
- docs: Add `docs/releasing-teamvault-utils.md` capturing the release gate (walk active scenarios before approving binary-surface prompts), the `autoRelease` semantics, the manual-release procedure for stuck-prompt-killed-then-finished-manually paths, the per-prompt gate cadence table, and the post-v4.13.0 keychain side-effect (zalando stores in its own encoded format; raw `security -w` shows the encoded blob, but downstream binaries round-trip correctly).

## v4.12.1

- fix: `teamvault-login` now reliably stores the password in the macOS Keychain when invoked with stdin piped (non-interactive shell). The previous implementation silently stored an empty password because `security add-generic-password -w` without a positional value prompts on `/dev/tty`. Fix uses `security -i` REPL mode (or the Keychain Services API via cgo as fallback) so the password is sent via stdin and never appears in `ps` output. See spec 003.

## v4.12.0

- feat: `--teamvault-timeout` flag and `TEAMVAULT_TIMEOUT` env var across all `teamvault-*` CLI binaries; threads through to the new factory `CreateConnectorWithConfigAndTimeout`.

## v4.11.0

- feat: Add configurable HTTP timeout via `Config.Timeout` (`libtime.Duration`); resolution order is CLI > config > 5s default. The factory applies the resolved timeout to `httpClient.Timeout` for full-request deadlines.
- fix: Cache enable is now the logical OR of CLI `--cache` / `CACHE` and config `cacheEnabled` — previously the config silently overrode the CLI value at `factory/factory.go:71`.

## v4.10.1

- feat: Add `teamvault-login` command: verifies TeamVault credentials against the API and stores the password in the macOS Keychain on success. Replaces the need to write the TeamVault password into the config file as plaintext.
- docs: README adds "Setup (macOS, recommended)" link to the TOC and a `teamvault-login` subsection under "CLI Tools" so the keychain flow is discoverable from both entry points.
- note: v4.10.0 was tagged but retracted — it contained an accidentally-committed binary at the repo root. v4.10.1 ships the same feature content with the binary excluded.

## v4.9.0

- feat: Add macOS Keychain as a password fallback source. When the resolved config provides URL + user but no password, the library now looks up the password from the login Keychain (service `teamvault-utils`, account = URL). On non-macOS platforms this step is a no-op. New `CreateConnectorWithConfigAndKeychain` factory function enables Keychain injection for testing.

Please choose versions by [Semantic Versioning](http://semver.org/).

* MAJOR version when you make incompatible API changes,
* MINOR version when you add functionality in a backwards-compatible manner, and
* PATCH version when you make backwards-compatible bug fixes.

## v4.8.8

- update go to 1.26.3
- update bborbe/errors, service, time, validation, collection, run, sentry
- update getsentry/sentry-go v0.46.2

## v4.8.7

- chore: Migrate to tools.env + Makefile @version pattern; remove tools.go and obsolete replace block. go.mod reduced from 461 to 53 lines.

## v4.8.6

- update ginkgo/v2 to v2.28.2
- update gosec/v2 to v2.26.1
- update golang.org/x/vuln to v1.3.0
- update anthropic-sdk-go to v1.38.0, openai-go to v3.32.0, google/genai to v1.54.0

## v4.8.5

- Update bborbe/* dependencies (errors, http, service, time, validation, etc.)
- Update golang.org/x/* packages (crypto, net, sys, tools, vuln, etc.)
- Update getsentry/sentry-go v0.43.0 → v0.45.0
- Update go-git/go-git v5.17.2 → v5.18.0
- Add .dark-factory.log to .gitignore

## v4.8.4

- Update Go to 1.26.2
- Bump bborbe/* deps (errors, http, service, time, validation, collection, parse)
- Bump counterfeiter to v6.12.2
- Bump moby/buildkit to v0.29.0, docker/cli to v29.3.1
- Bump klauspost/compress to v1.18.5

## v4.8.3

- Update Go dependencies to latest versions
- Downgrade several indirect deps to stable releases
- Add replace directives for anthropic-sdk-go, cellbuf, go-header, go-diskfs, ginkgolinter

## v4.8.2

- Update dependencies to fix security vulnerabilities (go-git/v5 v5.17.2, buildkit v0.29.0)
- Add .trivyignore for docker/docker CVEs

## v4.8.1

- Update bborbe/* dependencies (errors, http, service, time, validation, etc.)
- Bump golangci-lint to v2.11.4, gosec to v2.25.0, osv-scanner to v2.3.5
- Update opentelemetry to v1.42.0, docker to v28.5.2, containerd to v1.7.30
- Bump golang.org/x/* packages (crypto, net, sys, tools, etc.)
- Remove stale exclude block and k8s.io/kube-openapi replace directive

## v4.8.0

- feat: enable golangci-lint in `check` Makefile target
- chore: update `.golangci.yml` to standard bborbe config with additional linters (nestif, errname, unparam, bodyclose, forcetypeassert, asasalint, prealloc)
- fix: replace `github.com/pkg/errors` with `github.com/bborbe/errors` in config-parser and diskfallback-connector
- fix: add `defer resp.Body.Close()` in remote-connector HTTP call
- fix: use comma-ok type assertion pattern for all `val.(string)` casts in config-parser template functions
- refactor: simplify `remoteConnector.call` by removing always-same-value `method` and `request` parameters

## v4.7.16

- chore: verify all tests pass and precommit checks succeed with no issues

## v4.7.14

- upgrade golangci-lint from v1 to v2
- standardize Makefile: add .PHONY declarations, multiline trivy, mocks mkdir
- update .golangci.yml to v2 format
- setup dark-factory config

## v4.7.13

- Update dependencies (gosec v2.24.7, errcheck v1.10.0, time v1.24.0, and others)
- Add gosec nosec annotations for false-positive path traversal warnings
- Fix vulnerable dependencies (go-sdk, circl, go-git)

## v4.7.12

- go mod update

## v4.7.11

- Use go-version-file from go.mod in CI workflow

## v4.7.10

- Update Go to 1.26.0 in CI workflow
- Update dependencies (errors, http, service, time, validation, osv-scanner, goimports-reviser, gosec)
- Add gosec suppression for false positive SSRF warning in HTTP client

## v4.7.9

- Update GitHub workflows to v1 plugin system
- Simplify Claude Code action with inline conditions
- Add ready_for_review and reopened triggers

## v4.7.8

- Update ginkgo/v2 from v2.27.5 to v2.28.1
- Update gomega from v1.39.0 to v1.39.1
- Update golang.org/x tools, mod, net, telemetry
- Add k8s.io/kube-openapi replace directive
- Add exclusion list for problematic k8s deps

## v4.7.7
- Update Go to 1.25.6
- Remove replace and exclude directives from go.mod

## v4.7.6
- Add .mcp-* pattern to .gitignore

## v4.7.5

- Add UnmarshalJSON to User and Password types to handle numeric JSON values
- Fix TeamVault parsing errors when secrets contain numbers instead of strings

## v4.7.4

- Update dependencies (http v1.23.0, osv-scanner v2.3.0, goimports-reviser v3.11.0, and others)

## v4.7.3

- Update Go version to 1.25.4
- Update dependencies (http v1.21.0, service v1.8.3, osv-scanner v2.2.4, ginkgo v2.27.2, and others)

## v4.7.2

- Fix race condition in cache connector by adding sync.RWMutex protection for concurrent map access
- Add comprehensive concurrent access tests for cache connector with race detection
- Fix copyright year ranges in doc.go and factory/doc.go to match git history
- Add coverprofile.out to .gitignore

## v4.7.1

- Remove deprecated io/ioutil package, use os.ReadFile/WriteFile instead
- Fix counterfeiter directive placement to keep directives out of GoDoc
- Update test target to use Ginkgo framework with race detection enabled
- Add missing GoDoc comments for factory package functions
- Remove legacy build tag comment (keep only //go:build directive)
- Simplify Makefile default target (remove explicit default: line)
- Add comprehensive Full Example section to README demonstrating real-world usage

## v4.7.0

- Add comprehensive GoDoc documentation for all exported items
- Add package-level documentation (doc.go files)
- Migrate from standard time package to github.com/bborbe/time
- Update dependencies (glog v1.2.4, golang.org/x/net v0.33.0)
- Add go-modtool to development tools
- Update README with library usage examples and API documentation
- Update license headers with correct year ranges

## v4.6.3

- Fix security issue: Remove sensitive data from verbose logging (passwords, secrets, files)
- Fix security issue: Add path traversal validation to readfile template function
- Add exclude directives in go.mod for incompatible versions
- Update dependencies

## v4.6.2

- Add `make all` target to run precommit checks and install binaries
- Reorganize Makefile structure
- Update dependencies

## v4.6.1

- Move NormalizePath function into package (remove external dependency)
- Remove dependency on github.com/bborbe/io and github.com/bborbe/assert
- Update Go version to 1.25.2

## v4.6.0

- Add GitHub workflows for CI, Claude Code review, and Claude
- Add golangci-lint configuration
- Add key validation with context support
- Add gosec suppressions for controlled file reads
- Update dependencies
- Update Makefile with security checks
- Update all commands to use libservice.MainCmd
- Add copyright headers to all files

## v4.5.3

- use service.MainCmd

## v4.5.2

- remove sentry
- prevent print args

## v4.5.1

- fix teamvault-config-parser

## v4.5.0

- go mod update
- use lib argument

## v4.4.4

- go mod update

## v4.4.3

- go mod update

## v4.4.2

- go mod update

## v4.4.1

- go mod update

## v4.4.0

- fix go module to github.com/bborbe/teamvault-utils/v4 

## v4.3.3

- go mod update
- remove deprecated golint

## v4.3.2

- refactor

## v4.3.1

- go mod update

## v4.3.0

- go mod update
- inline lib http helper
- refactor

## v4.2.0

- add cache option for secrets

## v4.1.1

- update all deps

## v4.1.0

- update all deps
- go version to 1.21

## v4.0.1

- update all deps
- go version to 1.19

## v4.0.0

- add teamvault-file command
- remove subpackages
- use go modules instead dep

## v3.4.0

- add readfile to read content from file
- add indent method

## v3.3.0

- Add Htpasswd generator 

## v3.2.0

- Add cache connector

## v3.1.1

- Create fallback dirs

## v3.1.0

- Add disk fallback connector

## v3.0.1

- Update deps

## v3.0.0

- Move mode and Connector interface to root

## v2.1.0

- add search method to connector

## v2.0.0

- rename bin to cmd
- replace unterscore with dash in commands
- check config file is no directory 

## v1.2.1

- fix commands

## v1.2.0

- add teamvault_username, teamvault_password and teamvault_url command

## v1.1.0

- Add teamvaultHtpasswd

## v1.0.0

- Initial version
