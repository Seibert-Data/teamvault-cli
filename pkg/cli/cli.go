// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cli provides the command-line interface for the teamvault utility.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"

	"github.com/bborbe/errors"
	libtime "github.com/bborbe/time"
	"github.com/spf13/cobra"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
	"github.com/Seibert-Data/teamvault-cli/v5/pkg/factory"
)

// version is injected at build time via -ldflags (see the Makefile). For a
// plain `go install …@vX.Y.Z` build (no ldflags) it falls back to the module
// version recorded in the binary's build info, so `--version` still reports the
// real release.
var version = "dev"

func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}

// legacyConfigPath is the historical home-root config location. Kept in tilde
// form so TeamvaultConfigPath.NormalizePath expands it at use time.
const legacyConfigPath = "~/.teamvault.json"

// resolveDefaultConfigPath decides which config file the CLI reads when no
// --teamvault-config flag is given. Precedence: the TEAMVAULT_CONFIG env var,
// then the XDG path (~/.config/teamvault-cli/config.json) when that file
// exists, then the legacy ~/.teamvault.json. The returned path is still passed
// through TeamvaultConfigPath.Exists/NormalizePath, so an absent legacy file
// leaves behaviour unchanged (no config read).
func resolveDefaultConfigPath() string {
	if env := os.Getenv("TEAMVAULT_CONFIG"); env != "" {
		return env
	}
	if xdg := xdgConfigPath(); xdg != "" && teamvault.TeamvaultConfigPath(xdg).Exists() {
		return xdg
	}
	return legacyConfigPath
}

// userHomeDir is a seam over os.UserHomeDir so tests can simulate a missing
// home directory deterministically — os.UserHomeDir's getpwuid_r fallback (cgo)
// can return a home from /etc/passwd even with $HOME unset, making env-only
// tests platform-dependent.
var userHomeDir = os.UserHomeDir

// xdgConfigPath returns the XDG Base Directory config location
// (${XDG_CONFIG_HOME:-$HOME/.config}/teamvault-cli/config.json), or "" when
// neither XDG_CONFIG_HOME nor a home directory can be determined.
func xdgConfigPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := userHomeDir()
		if err != nil || home == "" {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "teamvault-cli", "config.json")
}

// Execute runs the CLI application. It sets up signal handling for SIGINT and
// SIGTERM, configures structured logging, and executes the root command.
// The sole context.Background() is created here and passed to Run.
func Execute() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		cancel()
	}()

	slog.SetDefault(
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	)

	if err := Run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Run builds the root command and executes it with the given arguments.
// It returns any error from command execution.
func Run(ctx context.Context, args []string) error {
	rootCmd := NewRootCommand(ctx)
	rootCmd.SetArgs(args)
	return rootCmd.ExecuteContext(ctx)
}

// SharedFlags holds the seven shared CLI flags that apply to all subcommands.
// Each flag falls back to its corresponding environment variable when not set.
type SharedFlags struct {
	url        string
	user       string
	pass       string
	configPath string
	staging    bool
	cache      bool
	timeout    string
}

// NewRootCommand creates the root cobra command with all persistent flags
// and subcommands registered.
func NewRootCommand(ctx context.Context) *cobra.Command {
	sf := &SharedFlags{}
	rootCmd := &cobra.Command{
		Use:           "teamvault-cli",
		Short:         "TeamVault CLI for retrieving secrets",
		Version:       resolveVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
		// The password flag must not default to the environment value: a flag
		// default is printed by --help, which would leak TEAMVAULT_PASS into
		// terminal scrollback, CI logs and pasted bug reports. The environment is
		// resolved here instead — after cobra has parsed the flags, and only when
		// the flag itself was not given, so the env path still works.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("teamvault-pass") {
				sf.pass = os.Getenv("TEAMVAULT_PASS")
			}
			return nil
		},
	}

	pf := rootCmd.PersistentFlags()
	pf.StringVar(&sf.url, "teamvault-url", os.Getenv("TEAMVAULT_URL"), "teamvault url")
	pf.StringVar(&sf.user, "teamvault-user", os.Getenv("TEAMVAULT_USER"), "teamvault user")
	pf.StringVar(&sf.pass, "teamvault-pass", "", "teamvault password")
	pf.StringVar(
		&sf.configPath,
		"teamvault-config",
		resolveDefaultConfigPath(),
		"teamvault config file path (default: $TEAMVAULT_CONFIG, else ~/.config/teamvault-cli/config.json, else ~/.teamvault.json)",
	)
	pf.BoolVar(&sf.staging, "staging", envBool("STAGING"), "staging status")
	pf.BoolVar(&sf.cache, "cache", envBool("CACHE"), "enable teamvault secret cache")
	pf.StringVar(
		&sf.timeout,
		"teamvault-timeout",
		os.Getenv("TEAMVAULT_TIMEOUT"),
		"HTTP request timeout for TeamVault API calls (e.g. 5s, 30s); 0 = default 5s",
	)

	rootCmd.AddCommand(createLoginCommand(ctx, sf))
	rootCmd.AddCommand(createSecretCommand(
		ctx,
		sf,
		"password",
		"Retrieve a password from TeamVault",
		"password",
		"get password failed",
		func(ctx context.Context, conn teamvault.Connector, key teamvault.Key) (fmt.Stringer, error) {
			return conn.Password(ctx, key)
		},
	))
	rootCmd.AddCommand(createSecretCommand(
		ctx,
		sf,
		"username",
		"Retrieve a username from TeamVault",
		"username",
		"get user failed",
		func(ctx context.Context, conn teamvault.Connector, key teamvault.Key) (fmt.Stringer, error) {
			return conn.User(ctx, key)
		},
	))
	rootCmd.AddCommand(createSecretCommand(
		ctx,
		sf,
		"url",
		"Retrieve a URL from TeamVault",
		"url",
		"get url failed",
		func(ctx context.Context, conn teamvault.Connector, key teamvault.Key) (fmt.Stringer, error) {
			return conn.Url(ctx, key)
		},
	))
	rootCmd.AddCommand(createSecretCommand(
		ctx,
		sf,
		"file",
		"Retrieve a file from TeamVault",
		"file",
		"get file failed",
		func(ctx context.Context, conn teamvault.Connector, key teamvault.Key) (fmt.Stringer, error) {
			return conn.File(ctx, key)
		},
	))
	rootCmd.AddCommand(createInfoCommand(ctx, sf))
	rootCmd.AddCommand(createConfigCommand(ctx, sf))
	rootCmd.AddCommand(createCreateCommand(ctx, sf))
	rootCmd.AddCommand(createUpdateCommand(ctx, sf))
	rootCmd.AddCommand(createSearchCommand(ctx, sf))
	rootCmd.AddCommand(createHtpasswdCommand(ctx, sf))
	rootCmd.AddCommand(createShareCommand(ctx, sf))
	rootCmd.AddCommand(createSharesCommand(ctx, sf))

	return rootCmd
}

// envBool returns true if the environment variable is set to "true", false otherwise.
func envBool(name string) bool {
	return os.Getenv(name) == "true"
}

// resolveKey resolves the TeamVault key from a positional argument or the
// --teamvault-key flag, positional taking precedence. It returns an error
// naming both forms when neither is given, since the flag is no longer
// required and cobra can't enforce "one of" on its own.
func resolveKey(cmd *cobra.Command, args []string) (teamvault.Key, error) {
	if len(args) > 0 && args[0] != "" {
		return teamvault.Key(args[0]), nil
	}
	flagKey, _ := cmd.Flags().GetString("teamvault-key")
	if flagKey != "" {
		return teamvault.Key(flagKey), nil
	}
	return "", errors.Errorf(
		cmd.Context(),
		"teamvault key required: pass it as a positional argument or via --teamvault-key",
	)
}

// createSecretCommand builds a secret-reader subcommand. The four secret
// readers (password/username/url/file) differ only in their Use/Short strings,
// the JSON field name, the connector method invoked, and the error message;
// this helper captures the shared wiring (positional/--teamvault-key
// resolution, buildConnector, writeSecret).
func createSecretCommand(
	ctx context.Context,
	sf *SharedFlags,
	use, short, jsonField, errMsg string,
	fetch func(context.Context, teamvault.Connector, teamvault.Key) (fmt.Stringer, error),
) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use + " [key]",
		Short: short,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := resolveKey(cmd, args)
			if err != nil {
				return err
			}
			asJSON, _ := cmd.Flags().GetBool("json")
			conn, err := sf.buildConnector(ctx)
			if err != nil {
				return err
			}
			result, err := fetch(ctx, conn, key)
			if err != nil {
				return errors.Wrap(ctx, err, errMsg)
			}
			return writeSecret(ctx, cmd.OutOrStdout(), jsonField, result, asJSON)
		},
	}

	var key string
	cmd.Flags().
		StringVar(&key, "teamvault-key", "", "teamvault key (alternative to positional argument)")
	cmd.Flags().
		Bool("json", false, `print output as a JSON object (e.g. {"`+jsonField+`":"<value>"})`)

	return cmd
}

// writeSecret writes the secret value to the given writer. In the default
// mode it writes the raw value with no trailing newline, so curl -u style
// basic-auth usage composes directly in command substitution. In --json mode
// it writes a single-key JSON object ({"<field>":"<value>"}) with a trailing
// newline.
func writeSecret(
	ctx context.Context,
	out io.Writer,
	field string,
	value fmt.Stringer,
	asJSON bool,
) error {
	if !asJSON {
		if _, err := fmt.Fprintf(out, "%v", value); err != nil {
			return errors.Wrapf(ctx, err, "write secret failed")
		}
		return nil
	}
	encoded, err := json.Marshal(map[string]string{field: value.String()})
	if err != nil {
		return errors.Wrapf(ctx, err, "marshal json failed")
	}
	if _, err := fmt.Fprintf(out, "%s\n", encoded); err != nil {
		return errors.Wrapf(ctx, err, "write secret failed")
	}
	return nil
}

// createInfoCommand builds the `info` subcommand, which fetches and prints
// all four fields (username, url, password, file) for a key in one call.
// Missing/empty fields print empty rather than erroring, since not every
// TeamVault secret populates every field.
func createInfoCommand(ctx context.Context, sf *SharedFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info [key]",
		Short: "Retrieve username, url, password, and file for a TeamVault secret",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := resolveKey(cmd, args)
			if err != nil {
				return err
			}
			asJSON, _ := cmd.Flags().GetBool("json")
			conn, err := sf.buildConnector(ctx)
			if err != nil {
				return err
			}

			username, err := conn.User(ctx, key)
			if err != nil {
				return errors.Wrap(ctx, err, "get user failed")
			}
			url, err := conn.Url(ctx, key)
			if err != nil {
				return errors.Wrap(ctx, err, "get url failed")
			}
			password, err := conn.Password(ctx, key)
			if err != nil {
				return errors.Wrap(ctx, err, "get password failed")
			}
			file, err := conn.File(ctx, key)
			if err != nil {
				return errors.Wrap(ctx, err, "get file failed")
			}

			return writeInfo(ctx, cmd.OutOrStdout(), username, url, password, file, asJSON)
		},
	}

	var key string
	cmd.Flags().
		StringVar(&key, "teamvault-key", "", "teamvault key (alternative to positional argument)")
	cmd.Flags().Bool("json", false, "print output as a JSON object")

	return cmd
}

// writeInfo writes the four secret fields to the given writer. In the
// default mode it writes an aligned "key: value" table; in --json mode it
// writes a single JSON object with all four fields.
func writeInfo(
	ctx context.Context,
	out io.Writer,
	username teamvault.User,
	url teamvault.Url,
	password teamvault.Password,
	file teamvault.File,
	asJSON bool,
) error {
	if !asJSON {
		if _, err := fmt.Fprintf(
			out,
			"username: %s\nurl:      %s\npassword: %s\nfile:     %s\n",
			username,
			url,
			password,
			file,
		); err != nil {
			return errors.Wrapf(ctx, err, "write info failed")
		}
		return nil
	}
	encoded, err := json.Marshal(map[string]string{
		"username": username.String(),
		"url":      url.String(),
		"password": password.String(),
		"file":     file.String(),
	})
	if err != nil {
		return errors.Wrapf(ctx, err, "marshal json failed")
	}
	if _, err := fmt.Fprintf(out, "%s\n", encoded); err != nil {
		return errors.Wrapf(ctx, err, "write info failed")
	}
	return nil
}

// buildConnector creates a TeamVault connector using the shared flags.
func (sf *SharedFlags) buildConnector(ctx context.Context) (teamvault.Connector, error) {
	httpClient, err := factory.CreateHttpClient(ctx)
	if err != nil {
		return nil, errors.Wrapf(ctx, err, "create httpClient failed")
	}

	var timeout libtime.Duration
	if sf.timeout != "" {
		d, err := libtime.ParseDuration(ctx, sf.timeout)
		if err != nil {
			return nil, errors.Wrapf(ctx, err, "parse teamvault-timeout %q failed", sf.timeout)
		}
		timeout = *d
	}

	conn, err := factory.CreateConnectorWithConfigAndTimeout(
		ctx,
		httpClient,
		teamvault.TeamvaultConfigPath(sf.configPath),
		teamvault.Url(sf.url),
		teamvault.User(sf.user),
		teamvault.Password(sf.pass),
		teamvault.Staging(sf.staging),
		sf.cache,
		libtime.NewCurrentDateTime(),
		teamvault.NewKeychain(),
		timeout,
	)
	if err != nil {
		return nil, errors.Wrapf(ctx, err, "create connector failed")
	}
	return conn, nil
}
