// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import (
	"context"
	"fmt"
	"time"

	"github.com/bborbe/errors"
	"github.com/bborbe/validation"
)

// ShareRequest asks the server to grant read access to one secret. Exactly one
// of User or Group is set: TeamVault rejects a request carrying both or
// neither. GrantDescription is required by the server and is what the grant
// list shows, so it should say why the access exists.
type ShareRequest struct {
	// User is the username slug to grant access to. Mutually exclusive with Group.
	User string
	// Group is the group name slug to grant access to. Mutually exclusive with User.
	Group string
	// GrantDescription is the human-readable reason for the grant (required).
	GrantDescription string
	// GrantedUntil is the RFC 3339 timestamp the grant expires at, or empty for
	// a permanent grant. The server requires the field to be present either way,
	// so an empty value is sent as an explicit null.
	GrantedUntil string
}

// Validate reports whether the request is well formed. The server enforces the
// same rules; checking here turns a round-trip 400 into an immediate error.
//
// validation.Either passes only when exactly one member is valid, which is
// precisely the "one of user or group, never both" rule.
func (r ShareRequest) Validate(ctx context.Context) error {
	return validation.All{
		validation.Name("user/group", validation.Either{
			validation.Name("user", validation.True(r.User != "")),
			validation.Name("group", validation.True(r.Group != "")),
		}),
		validation.Name("grant description", validation.True(r.GrantDescription != "")),
		validation.Name("granted until", validation.HasValidationFunc(r.validateGrantedUntil)),
	}.Validate(ctx)
}

// validateGrantedUntil accepts an empty value (a permanent grant) or an RFC 3339
// timestamp, so a typo fails locally instead of as a server 400.
func (r ShareRequest) validateGrantedUntil(ctx context.Context) error {
	if r.GrantedUntil == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, r.GrantedUntil); err != nil {
		return errors.Wrapf(
			ctx,
			validation.Error,
			"granted-until %q is not an RFC 3339 timestamp (e.g. 2026-12-31T23:59:59Z)",
			r.GrantedUntil,
		)
	}
	return nil
}

// Share is one access grant as the server reports it. A grant targets either a
// user or a group, never both, so exactly one of User/Group is non-nil. The
// type carries no secret value: the server's share serializer exposes only the
// secret's hashid.
type Share struct {
	// ID is the server-side grant id.
	ID int `json:"id"`
	// GrantDescription is the reason recorded with the grant.
	GrantDescription string `json:"grant_description"`
	// GrantedOn is when the grant was created, or nil when the server omits it.
	// Pointer, not string: a null in one row would otherwise fail the decode for
	// the whole list.
	GrantedOn *string `json:"granted_on"`
	// GrantedUntil is when the grant expires, or nil for a permanent grant.
	GrantedUntil *string `json:"granted_until"`
	// Group is the granted group's name, or nil for a user grant.
	Group *string `json:"group"`
	// User is the granted username, or nil for a group grant.
	User *string `json:"user"`
	// GrantedBy is the username that created the grant, or nil when the server
	// omits it. Pointer for the same reason as GrantedOn.
	GrantedBy *string `json:"granted_by"`
	// Secret is the granted secret's hashid.
	Secret string `json:"secret"`
}

// ShareOutcome reports what a Share call did.
type ShareOutcome int

const (
	// ShareCreated means the server created a new grant.
	ShareCreated ShareOutcome = iota
	// ShareAlreadyExists means the grant was already present. The server answers
	// a duplicate with a 400 DRF ValidationError carrying code='unique'; the
	// caller sees it as a successful no-op rather than a failure, so re-running
	// a grant over an already-shared key is idempotent.
	ShareAlreadyExists
)

// ShareResult is the outcome of a Share call. Share is populated only when
// Outcome is ShareCreated.
type ShareResult struct {
	// Outcome reports whether the grant was created or already present.
	Outcome ShareOutcome
	// Share is the created grant; zero when Outcome is ShareAlreadyExists.
	Share Share
}

// ShareError is a share call the server refused. It carries the HTTP status and
// the server's own detail so a caller can print both rather than parsing them
// out of a formatted message.
type ShareError struct {
	// Key is the secret the call was made against.
	Key Key
	// StatusCode is the HTTP status the server answered with.
	StatusCode int
	// Detail is the response body, capped and trimmed by the caller.
	Detail string
}

// Error renders the refusal. It never contains a secret value: only the status
// and the server's own response body are included.
func (e *ShareError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("share %s failed with status: %d: %s", e.Key, e.StatusCode, e.Detail)
	}
	return fmt.Sprintf("share %s failed with status: %d", e.Key, e.StatusCode)
}

//counterfeiter:generate -o mocks/sharer.go --fake-name Sharer . Sharer

// Sharer grants and lists read access to TeamVault secrets. It is separate from
// Writer for the same reason Writer is separate from Connector: adding a method
// to an exported interface breaks every external implementer.
type Sharer interface {
	// Share grants read access to the secret named by key. A grant that already
	// exists is reported as ShareAlreadyExists, not as an error.
	Share(ctx context.Context, key Key, request ShareRequest) (ShareResult, error)
	// Shares lists the grants on the secret named by key.
	Shares(ctx context.Context, key Key) ([]Share, error)
}
