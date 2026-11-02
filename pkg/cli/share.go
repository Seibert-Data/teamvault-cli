// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"strings"

	"github.com/bborbe/errors"
	"github.com/spf13/cobra"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
)

const (
	// maxShareStdinBytes bounds how much of stdin `share -` will read.
	maxShareStdinBytes = 1 << 20
	// maxShareKeys bounds how many keys one invocation will act on.
	maxShareKeys = 10000
)

// createShareCommand creates the `share` subcommand.
func createShareCommand(ctx context.Context, sf *SharedFlags) *cobra.Command {
	var (
		flagKeys     []string
		user         string
		group        string
		description  string
		grantedUntil string
	)

	cmd := &cobra.Command{
		Use:   "share [key]...",
		Short: "Grant a user or group read access to one or more TeamVault secrets",
		Long: "Grant a user or group read access to one or more TeamVault secrets.\n\n" +
			"Prints one line per key: `<key> shared`, `<key> already-shared`, or\n" +
			"`<key> refused (<status>: <server detail>)`. Exits non-zero when any key\n" +
			"was refused.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			request := teamvault.ShareRequest{
				User:             user,
				Group:            group,
				GrantDescription: description,
				GrantedUntil:     grantedUntil,
			}
			if err := request.Validate(ctx); err != nil {
				return err
			}

			keys, err := collectShareKeys(cmd, args, flagKeys)
			if err != nil {
				return err
			}

			sharer, err := newSharer(sf)(ctx)
			if err != nil {
				return errors.Wrap(ctx, err, "create sharer failed")
			}

			out := cmd.OutOrStdout()
			refused := 0
			processed := 0
			for _, key := range keys {
				// Each key costs a round trip, so stop between keys when the
				// caller cancelled instead of walking the rest of the list.
				if err := ctx.Err(); err != nil {
					return errors.Wrapf(
						ctx,
						err,
						"share cancelled after %d of %d keys",
						processed,
						len(keys),
					)
				}
				line, err := shareOne(ctx, sharer, key, request)
				processed++
				if err != nil {
					refused++
				}
				if _, writeErr := fmt.Fprintln(out, line); writeErr != nil {
					return errors.Wrapf(ctx, writeErr, "write share result failed")
				}
			}

			if refused > 0 {
				return errors.Errorf(ctx, "%d of %d keys refused", refused, len(keys))
			}
			return nil
		},
	}

	cmd.Flags().
		StringArrayVar(&flagKeys, "teamvault-key", nil, "teamvault key (repeatable; alternative to positional arguments)")
	cmd.Flags().
		StringVar(&user, "user", "", "username to grant read access to (mutually exclusive with --group)")
	cmd.Flags().
		StringVar(&group, "group", "", "group name to grant read access to (mutually exclusive with --user)")
	cmd.Flags().StringVar(&description, "description", "", "why the access is granted (required)")
	cmd.Flags().StringVar(
		&grantedUntil,
		"granted-until",
		"",
		"RFC 3339 timestamp the grant expires at (e.g. 2026-12-31T23:59:59Z); omit for a permanent grant",
	)

	return cmd
}

// shareOne shares one key and returns the line to print. The error is returned
// only so the caller can count refusals; the printed line already carries the
// server's status and detail, which is what the operator needs.
func shareOne(
	ctx context.Context,
	sharer teamvault.Sharer,
	key teamvault.Key,
	request teamvault.ShareRequest,
) (string, error) {
	result, err := sharer.Share(ctx, key, request)
	if err != nil {
		var shareErr *teamvault.ShareError
		if stderrors.As(err, &shareErr) {
			return fmt.Sprintf(
				"%s refused (%d: %s)",
				key,
				shareErr.StatusCode,
				oneLine(shareErr.Detail),
			), err
		}
		return fmt.Sprintf("%s refused (error: %s)", key, oneLine(err.Error())), err
	}
	if result.Outcome == teamvault.ShareAlreadyExists {
		// A duplicate is the outcome the caller asked for: the access exists, so a
		// re-run stays idempotent rather than failing.
		return fmt.Sprintf("%s already-shared", key), nil
	}
	return fmt.Sprintf("%s shared", key), nil
}

// oneLine collapses a server-supplied message onto a single line: each result is
// one line by contract, and a body carrying CR/LF or other control characters
// would otherwise break the per-key output (and the parsing that reads it).
func oneLine(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

// collectShareKeys merges positional keys, repeated --teamvault-key values and,
// when a bare "-" is given, keys read one per line from stdin. Duplicates are
// dropped so a key listed twice is not reported twice; order is preserved.
func collectShareKeys(
	cmd *cobra.Command,
	args []string,
	flagKeys []string,
) ([]teamvault.Key, error) {
	raw := make([]string, 0, len(args)+len(flagKeys))
	raw = append(raw, args...)
	raw = append(raw, flagKeys...)

	readStdin := false
	candidates := make([]string, 0, len(raw))
	for _, candidate := range raw {
		candidate = strings.TrimSpace(candidate)
		if candidate == "-" {
			readStdin = true
			continue
		}
		if candidate != "" {
			candidates = append(candidates, candidate)
		}
	}

	if readStdin {
		// Bounded, and the bound is an ERROR rather than a quiet cut: this command
		// mutates access, so a truncated key list would share a partial set and exit
		// 0. Read one byte past the limit so hitting it is detectable — a bare
		// LimitReader reports EOF at the cap, indistinguishable from a complete read.
		data, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxShareStdinBytes+1))
		if err != nil {
			return nil, errors.Wrapf(cmd.Context(), err, "read keys from stdin failed")
		}
		if len(data) > maxShareStdinBytes {
			return nil, errors.Errorf(
				cmd.Context(),
				"stdin exceeds %d bytes; pass fewer keys or split the run",
				maxShareStdinBytes,
			)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				candidates = append(candidates, line)
			}
		}
	}

	// The cap applies to EVERY key source, not just stdin: positional arguments
	// and repeated --teamvault-key are equally unbounded.
	if len(candidates) > maxShareKeys {
		return nil, errors.Errorf(
			cmd.Context(),
			"too many keys: %d given, the maximum is %d",
			len(candidates),
			maxShareKeys,
		)
	}

	if len(candidates) == 0 {
		return nil, errors.New(
			cmd.Context(),
			"at least one key is required: pass it positionally, via --teamvault-key, or as - to read one key per line from stdin",
		)
	}

	seen := make(map[string]struct{}, len(candidates))
	keys := make([]teamvault.Key, 0, len(candidates))
	for _, candidate := range candidates {
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		keys = append(keys, teamvault.Key(candidate))
	}
	return keys, nil
}
