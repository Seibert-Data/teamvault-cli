// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import (
	"context"
	"strings"

	"github.com/bborbe/errors"
	"github.com/foomo/htpasswd"
	"github.com/golang/glog"
)

// HtpasswdGenerator generates htpasswd formatted credentials from TeamVault secrets.
type HtpasswdGenerator interface {
	Generate(ctx context.Context, key Key) ([]byte, error)
}

// NewHtpasswdGenerator creates a new HtpasswdGenerator with the given Connector.
func NewHtpasswdGenerator(connector Connector) HtpasswdGenerator {
	return &htpasswdGenerator{
		connector: connector,
	}
}

type htpasswdGenerator struct {
	connector Connector
}

func (c *htpasswdGenerator) Generate(ctx context.Context, key Key) ([]byte, error) {
	pass, err := c.connector.Password(ctx, key)
	if err != nil {
		glog.V(2).Infof("get password from teamvault for key %v failed: %v", key, err)
		return nil, err
	}
	user, err := c.connector.User(ctx, key)
	if err != nil {
		glog.V(2).Infof("get user from teamvault for key %v failed: %v", key, err)
		return nil, err
	}
	username, err := htpasswdUsername(ctx, key, string(user))
	if err != nil {
		return nil, err
	}
	pws := make(htpasswd.HashedPasswords)
	err = pws.SetPassword(username, string(pass), htpasswd.HashBCrypt)
	if err != nil {
		glog.V(2).Infof("set password failed for key %v failed: %v", key, err)
		return nil, err
	}
	return pws.Bytes(), nil
}

// htpasswdUsername reduces a stored username to a value that can occupy exactly
// one htpasswd line. OneLine collapses CR/LF and drops the remaining control
// characters; ':' is removed on top of that because it is the field separator,
// and a username carrying one would silently corrupt the principal Apache
// reads. A username that sanitises to blank is an error rather than a rendered
// line: Apache rejects an htpasswd file whose username is empty, which would
// break every credential in the file, not just the poisoned one.
//
// The render path sanitises rather than rejects on purpose — a username that is
// already stored cannot be changed from here, and refusing to render it would
// only move the outage.
func htpasswdUsername(ctx context.Context, key Key, raw string) (string, error) {
	sanitized := strings.ReplaceAll(OneLine(raw), ":", "")
	if strings.TrimSpace(sanitized) == "" {
		return "", errors.Errorf(
			ctx,
			"secret %q has a username with no printable characters — fix the username in the TeamVault UI before rendering htpasswd",
			key,
		)
	}
	return sanitized, nil
}
