// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/bborbe/errors"
	"github.com/spf13/cobra"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
)

// createShareCommand creates the `share` subcommand.
func createShareCommand(ctx context.Context, sf *SharedFlags) *cobra.Command {
	var (
		flagKeys    []string
		user        string
		group       string
		description string
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
			for _, key := range keys {
				// Each key costs a round trip, so stop between keys when the
				// caller cancelled instead of walking the rest of the list.
				if err := ctx.Err(); err != nil {
					return errors.Wrapf(ctx, err, "share cancelled after %d keys", refused)
				}
				line, err := shareOne(ctx, sharer, key, request)
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
		if asShareError(err, &shareErr) {
			return fmt.Sprintf(
				"%s refused (%d: %s)",
				key,
				shareErr.StatusCode,
				shareErr.Detail,
			), err
		}
		return fmt.Sprintf("%s refused (error: %v)", key, err), err
	}
	if result.Outcome == teamvault.ShareAlreadyExists {
		return fmt.Sprintf("%s already-shared", key), nil
	}
	return fmt.Sprintf("%s shared", key), nil
}

// asShareError unwraps to a *teamvault.ShareError. The sharer returns it
// unwrapped, but a wrapper added later would still be found through Unwrap, so
// the check walks the chain rather than asserting on the outer value.
func asShareError(err error, target **teamvault.ShareError) bool {
	for err != nil {
		if shareErr, ok := err.(*teamvault.ShareError); ok {
			*target = shareErr
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
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
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, errors.Wrapf(cmd.Context(), err, "read keys from stdin failed")
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				candidates = append(candidates, line)
			}
		}
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
