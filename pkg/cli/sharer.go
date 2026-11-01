// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"

	libtime "github.com/bborbe/time"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
	"github.com/Seibert-Data/teamvault-cli/v5/pkg/factory"
)

// newSharer is a seam that returns a teamvault.Sharer. Defaults to the
// SharedFlags builder but is overridden by tests via SetNewSharerForTest.
var newSharer = func(sf *SharedFlags) func(context.Context) (teamvault.Sharer, error) {
	return sf.buildSharer
}

// defaultNewSharer is the un-overridden seam, restored by ResetNewSharerForTest.
var defaultNewSharer = newSharer

// SetNewSharerForTest overrides the sharer constructor for tests.
// Returns a function to call in AfterEach to reset.
func SetNewSharerForTest(
	f func(sf *SharedFlags) func(context.Context) (teamvault.Sharer, error),
) func() {
	prev := newSharer
	newSharer = f
	return func() { newSharer = prev }
}

// ResetNewSharerForTest restores the default sharer constructor. A spec that
// needs the flag-built sharer must call this: without it a mock installed by an
// earlier spec stays in place for the rest of the package run.
func ResetNewSharerForTest() { newSharer = defaultNewSharer }

// buildSharer creates a TeamVault sharer using the shared flags. It resolves
// credentials through exactly the same path as buildWriter, so a command cannot
// end up writing as one account and reading as another.
func (sf *SharedFlags) buildSharer(ctx context.Context) (teamvault.Sharer, error) {
	creds, err := sf.resolveCredentials(ctx)
	if err != nil {
		return nil, err
	}
	return factory.CreateRemoteSharer(
		creds.httpClient,
		creds.url,
		creds.user,
		creds.pass,
		libtime.NewCurrentDateTime(),
	), nil
}
