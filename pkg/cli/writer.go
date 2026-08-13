// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bborbe/errors"
	libtime "github.com/bborbe/time"
	"golang.org/x/term"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
	"github.com/Seibert-Data/teamvault-cli/v5/pkg/factory"
)

// newWriter is a seam that returns a teamvault.Writer. Defaults to the
// SharedFlags builder but is overridden by tests via SetNewWriterForTest.
var newWriter = func(sf *SharedFlags) func(context.Context) (teamvault.Writer, error) {
	return sf.buildWriter
}

// SetNewWriterForTest overrides the writer constructor for tests.
// Returns a function to call in AfterEach to reset.
func SetNewWriterForTest(
	f func(sf *SharedFlags) func(context.Context) (teamvault.Writer, error),
) func() {
	prev := newWriter
	newWriter = f
	return func() { newWriter = prev }
}

// ResetNewWriterForTest is an alias for the reset function returned by SetNewWriterForTest.
func ResetNewWriterForTest() {}

// buildWriter creates a TeamVault writer using the shared flags.
// Credentials resolve through the same precedence as the read path:
// flag → env var → config file → Keychain.
func (sf *SharedFlags) buildWriter(ctx context.Context) (teamvault.Writer, error) {
	httpClient, err := factory.CreateHttpClient(ctx)
	if err != nil {
		return nil, errors.Wrapf(ctx, err, "create httpClient failed")
	}

	resolvedURL := teamvault.Url(sf.url)
	resolvedUser := teamvault.User(sf.user)
	resolvedPass := teamvault.Password(sf.pass)

	configPath := teamvault.TeamvaultConfigPath(sf.configPath)
	if configPath.Exists() {
		config, err := configPath.Parse()
		if err != nil {
			return nil, errors.Wrapf(ctx, err, "parse teamvault config failed")
		}
		resolvedURL = config.Url
		resolvedUser = config.User
		if resolvedPass == "" {
			resolvedPass = config.Password
		}
	}

	if resolvedURL == "" {
		return nil, errors.New(
			ctx,
			"teamvault URL is required; use --teamvault-url, TEAMVAULT_URL, or configure in --teamvault-config",
		)
	}
	if resolvedUser == "" {
		return nil, errors.New(
			ctx,
			"teamvault user is required; use --teamvault-user, TEAMVAULT_USER, or configure in --teamvault-config",
		)
	}

	if resolvedPass == "" {
		kc := teamvault.NewKeychain()
		pass, err := kc.ReadPassword(ctx, resolvedURL)
		if err != nil {
			return nil, errors.Wrapf(
				ctx,
				err,
				"read keychain password for %s failed",
				resolvedURL,
			)
		}
		resolvedPass = pass
	}

	var cliTimeout libtime.Duration
	if sf.timeout != "" {
		d, err := libtime.ParseDuration(ctx, sf.timeout)
		if err != nil {
			return nil, errors.Wrapf(ctx, err, "parse teamvault-timeout %q failed", sf.timeout)
		}
		cliTimeout = *d
	}
	if cliTimeout.Duration() < 0 {
		return nil, errors.Errorf(ctx, "invalid timeout %v: must be >= 0", cliTimeout.Duration())
	}

	httpClient.Timeout = cliTimeout.Duration()
	if httpClient.Timeout == 0 {
		httpClient.Timeout = 5 * 1e9 // 5s default
	}

	return factory.CreateRemoteWriter(
		httpClient,
		resolvedURL,
		resolvedUser,
		resolvedPass,
		libtime.NewCurrentDateTime(),
	), nil
}

// isTTYStdin returns true if os.Stdin is connected to an interactive terminal.
func isTTYStdin() bool {
	// #nosec G115 -- Fd() returns a small file descriptor (0 for stdin); the
	// uintptr-to-int conversion cannot overflow on any supported platform.
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// readPasswordFromStdin reads a password from stdin to EOF. It rejects empty
// input and does not block forever on an interactive terminal.
// The stdin source is passed as an io.Reader so tests can inject a non-TTY reader;
// the TTY guard checks os.Stdin specifically to detect an interactive terminal.
func readPasswordFromStdin(ctx context.Context, in io.Reader) (teamvault.Password, error) {
	// Refuse to read from an interactive terminal — it would block forever.
	if isTTYStdin() {
		return "", errors.New(
			ctx,
			"--password-stdin requires piped input (e.g. echo -n pw | teamvault-cli create --password-stdin); refusing to block on an interactive terminal",
		)
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return "", errors.Wrapf(ctx, err, "read password from stdin failed")
	}
	// Trim only trailing \n and \r; preserve interior whitespace.
	trimmed := strings.TrimRight(string(data), "\n\r")
	if trimmed == "" {
		return "", errors.New(ctx, "password must not be empty")
	}
	return teamvault.Password(trimmed), nil
}

// writeKey prints the created/updated secret's key. Default: the bare key
// with NO trailing newline. --json: {"key":"…","api_url":"…"} single line.
func writeKey(
	ctx context.Context,
	out io.Writer,
	key teamvault.Key,
	apiURL teamvault.ApiUrl,
	asJSON bool,
) error {
	if !asJSON {
		if _, err := fmt.Fprintf(out, "%s", key.String()); err != nil {
			return errors.Wrapf(ctx, err, "write key failed")
		}
		return nil
	}
	encoded, err := json.Marshal(map[string]string{
		"key":     key.String(),
		"api_url": apiURL.String(),
	})
	if err != nil {
		return errors.Wrapf(ctx, err, "marshal json failed")
	}
	if _, err := fmt.Fprintf(out, "%s\n", encoded); err != nil {
		return errors.Wrapf(ctx, err, "write key failed")
	}
	return nil
}
