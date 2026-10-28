// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"os"
	"path/filepath"

	"github.com/bborbe/errors"
	"github.com/spf13/cobra"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
)

// createCreateCommand creates the `create` subcommand.
func createCreateCommand(ctx context.Context, sf *SharedFlags) *cobra.Command {
	var (
		name          string
		username      string
		url           string
		description   string
		passwordStdin bool
		generate      bool
		password      string
		filePath      string
		asJSON        bool
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new secret in TeamVault",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// --- Value-source resolution (before any network call) ---
			valueFlags := countValueFlags(passwordStdin, generate, password != "", filePath != "")
			if valueFlags == 0 {
				return errors.New(
					ctx,
					"one of --password-stdin, --generate, --password, or --file is required",
				)
			}
			if valueFlags > 1 {
				return errors.New(
					ctx,
					"--password-stdin, --generate, --password, and --file are mutually exclusive",
				)
			}

			// Infer content type
			var contentType teamvault.ContentType
			if filePath != "" {
				contentType = teamvault.ContentTypeFile
			} else {
				contentType = teamvault.ContentTypePassword
			}

			// Resolve value
			var secret teamvault.CreateSecret
			secret.ContentType = contentType
			secret.Name = name
			if username != "" {
				secret.Username = username
			}
			if url != "" {
				secret.Url = url
			}
			if description != "" {
				secret.Description = description
			}

			switch {
			case filePath != "":
				data, err := os.ReadFile(filePath)
				if err != nil {
					return errors.Wrapf(ctx, err, "read file %q failed", filePath)
				}
				secret.FileContent = data
				// The server requires a filename for file secrets; only the base
				// name is sent so the local directory layout stays local.
				secret.Filename = filepath.Base(filePath)

			case passwordStdin:
				pw, err := readPasswordFromStdin(ctx, cmd.InOrStdin())
				if err != nil {
					return errors.Wrap(ctx, err, "read password from stdin failed")
				}
				secret.Password = pw

			case generate:
				writer, err := newWriter(sf)(ctx)
				if err != nil {
					return errors.Wrap(ctx, err, "create writer failed")
				}
				pw, err := writer.GeneratePassword(ctx)
				if err != nil {
					return errors.Wrap(ctx, err, "generate password failed")
				}
				secret.Password = pw

			case password != "":
				secret.Password = teamvault.Password(password)
			}

			// Build writer and create
			writer, err := newWriter(sf)(ctx)
			if err != nil {
				return errors.Wrap(ctx, err, "create writer failed")
			}
			key, apiURL, err := writer.Create(ctx, secret)
			if err != nil {
				return errors.Wrap(ctx, err, "create secret failed")
			}

			return writeKey(ctx, cmd.OutOrStdout(), key, apiURL, asJSON)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "secret name (required)")
	cmd.Flags().StringVar(&username, "username", "", "username")
	cmd.Flags().StringVar(&url, "url", "", "url")
	cmd.Flags().StringVar(&description, "description", "", "description")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin")
	cmd.Flags().BoolVar(&generate, "generate", false, "generate a secure password via the server")
	cmd.Flags().StringVar(
		&password,
		"password",
		"",
		"secret password (WARNING: visible in shell history and process list (ps); prefer --password-stdin or --generate)",
	)
	cmd.Flags().StringVar(&filePath, "file", "", "path to a file (content is base64-encoded)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print output as JSON object")

	return cmd
}

// countValueFlags returns how many of the four value-source flags are set.
func countValueFlags(passwordStdin, generate, hasPassword, hasFile bool) int {
	n := 0
	if passwordStdin {
		n++
	}
	if generate {
		n++
	}
	if hasPassword {
		n++
	}
	if hasFile {
		n++
	}
	return n
}
