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

// createUpdateCommand creates the `update` subcommand.
func createUpdateCommand(ctx context.Context, sf *SharedFlags) *cobra.Command {
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
		Use:   "update <key>",
		Short: "Update an existing TeamVault secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := teamvault.Key(args[0])
			if err := key.Validate(ctx); err != nil {
				return errors.Wrap(ctx, err, "invalid key")
			}

			// Mutual exclusion check: at most one value flag allowed
			valueFlags := countValueFlags(passwordStdin, generate, password != "", filePath != "")
			if valueFlags > 1 {
				return errors.New(
					ctx,
					"--password-stdin, --generate, --password, and --file are mutually exclusive",
				)
			}

			// Build UpdateSecret — only set fields that were actually passed
			var secret teamvault.UpdateSecret
			if cmd.Flags().Changed("name") {
				secret.Name = &name
			}
			if cmd.Flags().Changed("username") {
				secret.Username = &username
			}
			if cmd.Flags().Changed("url") {
				secret.Url = &url
			}
			if cmd.Flags().Changed("description") {
				secret.Description = &description
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
				secret.Password = &pw

			case generate:
				writer, err := newWriter(sf)(ctx)
				if err != nil {
					return errors.Wrap(ctx, err, "create writer failed")
				}
				pw, err := writer.GeneratePassword(ctx)
				if err != nil {
					return errors.Wrap(ctx, err, "generate password failed")
				}
				secret.Password = &pw

			case password != "":
				pw := teamvault.Password(password)
				secret.Password = &pw
			}

			writer, err := newWriter(sf)(ctx)
			if err != nil {
				return errors.Wrap(ctx, err, "create writer failed")
			}
			resultKey, apiURL, err := writer.Update(ctx, key, secret)
			if err != nil {
				return errors.Wrap(ctx, err, "update secret failed")
			}

			return writeKey(ctx, cmd.OutOrStdout(), resultKey, apiURL, asJSON)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "secret name")
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
