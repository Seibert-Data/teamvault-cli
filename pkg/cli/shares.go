// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/bborbe/errors"
	"github.com/spf13/cobra"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
)

// createSharesCommand creates the `shares` subcommand.
func createSharesCommand(ctx context.Context, sf *SharedFlags) *cobra.Command {
	var (
		keyFlag string
		asJSON  bool
	)

	cmd := &cobra.Command{
		Use:   "shares [key]",
		Short: "List who has read access to a TeamVault secret",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := resolveKey(cmd, args)
			if err != nil {
				return err
			}

			sharer, err := newSharer(sf)(ctx)
			if err != nil {
				return errors.Wrap(ctx, err, "create sharer failed")
			}

			shares, err := sharer.Shares(ctx, key)
			if err != nil {
				return errors.Wrap(ctx, err, "list shares failed")
			}

			return writeShares(ctx, cmd.OutOrStdout(), key, shares, asJSON)
		},
	}

	cmd.Flags().
		StringVar(&keyFlag, "teamvault-key", "", "teamvault key (alternative to positional argument)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print output as JSON array")

	return cmd
}

// writeShares prints the grants on one secret. Default: one aligned row per
// grant, showing which user or group holds it, the recorded reason, who granted
// it and when it expires. --json: the same data as a JSON array.
//
// Only the grant metadata is printed — never a secret value, which the server's
// share serializer does not return in the first place.
func writeShares(
	ctx context.Context,
	out io.Writer,
	key teamvault.Key,
	shares []teamvault.Share,
	asJSON bool,
) error {
	if asJSON {
		// Project onto the grant fields the table shows (plus granted_on, which the
		// table has no column for), and drop the server's `secret` hashid: the caller
		// already passed the key, so repeating it adds nothing — and a JSON field
		// named "secret" invites a reader (and a scanner) to think a secret value is
		// being emitted.
		view := make([]shareJSON, 0, len(shares))
		for _, share := range shares {
			view = append(view, shareJSON{
				User:             share.User,
				Group:            share.Group,
				GrantDescription: share.GrantDescription,
				GrantedOn:        share.GrantedOn,
				GrantedUntil:     share.GrantedUntil,
				GrantedBy:        share.GrantedBy,
			})
		}
		encoded, err := json.Marshal(view)
		if err != nil {
			return errors.Wrapf(ctx, err, "marshal json failed")
		}
		if _, err := fmt.Fprintf(out, "%s\n", encoded); err != nil {
			return errors.Wrapf(ctx, err, "write shares failed")
		}
		return nil
	}

	if len(shares) == 0 {
		if _, err := fmt.Fprintf(out, "%s has no shares\n", key); err != nil {
			return errors.Wrapf(ctx, err, "write shares failed")
		}
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "KEY\tUSER\tGROUP\tDESCRIPTION\tGRANTED_BY\tGRANTED_UNTIL"); err != nil {
		return errors.Wrapf(ctx, err, "write shares failed")
	}
	for _, share := range shares {
		if _, err := fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			key,
			derefOrDash(share.User),
			derefOrDash(share.Group),
			share.GrantDescription,
			derefOrDash(share.GrantedBy),
			derefOrDash(share.GrantedUntil),
		); err != nil {
			return errors.Wrapf(ctx, err, "write shares failed")
		}
	}
	if err := w.Flush(); err != nil {
		return errors.Wrapf(ctx, err, "flush shares output failed")
	}
	return nil
}

// shareJSON is one grant as `shares --json` emits it: the same fields the table
// shows, and deliberately none of the server's internal identifiers.
type shareJSON struct {
	User             *string `json:"user"`
	Group            *string `json:"group"`
	GrantDescription string  `json:"grant_description"`
	GrantedOn        *string `json:"granted_on"`
	GrantedUntil     *string `json:"granted_until"`
	GrantedBy        *string `json:"granted_by"`
}

// derefOrDash renders an optional field, using "-" for an absent one so the
// columns stay aligned and an empty cell never reads as a missing column.
func derefOrDash(value *string) string {
	if value == nil || *value == "" {
		return "-"
	}
	return *value
}
