// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"strings"

	"github.com/bborbe/errors"
)

// validateUsername rejects a --username that cannot be stored as a single
// htpasswd principal. CR, LF and the other control characters would break the
// rendered line, and ':' is the field separator Apache reads — a username
// carrying one silently corrupts the principal. The error names the offending
// character in its escaped form so it can be located in the input.
//
// The render path sanitises instead (see htpasswdUsername), because a username
// that is already stored cannot be fixed from here; this check exists so no new
// poisoned value enters TeamVault through the CLI.
func validateUsername(ctx context.Context, username string) error {
	// Surrounding whitespace is refused because Apache skips it when parsing a
	// user:hash line: a stored " admin" authenticates as "admin", so the value
	// the operator typed is not the principal that gets rendered. An empty
	// username is left alone — create treats it as absent and update as a clear.
	if trimmed := strings.TrimSpace(username); trimmed != username {
		return errors.Errorf(
			ctx,
			"--username must not start or end with whitespace (it would be stored as %q)",
			trimmed,
		)
	}
	for _, r := range username {
		switch {
		case r == ':':
			return errors.Errorf(
				ctx,
				"--username must not contain ':' — it is the htpasswd field separator",
			)
		case r < 0x20 || r == 0x7f:
			return errors.Errorf(
				ctx,
				"--username must not contain control character %q",
				r,
			)
		}
	}
	return nil
}
