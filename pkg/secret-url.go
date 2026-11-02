// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import (
	"net/url"
	"strings"
)

// secretPath returns the path of one secret on the configured TeamVault host.
// Every caller that addresses a secret builds it here, so the read, write and
// share paths cannot drift apart again — the original defect was exactly that
// drift: the share path escaped its key and the other two did not.
func secretPath(key Key) string {
	return "/api/secrets/" + escapeKeySegment(key) + "/"
}

// escapeKeySegment renders a key as exactly one URL path segment. The key is
// caller-supplied (a template expression or a CLI argument), so it must not be
// able to change the request target: url.PathEscape covers "?", "#", "/" and
// space, but leaves "." and ".." alone, and a segment consisting only of dots
// is resolved by proxies and servers as a directory step — a key of ".." would
// turn "/api/secrets/../" into "/api/". Encoding every dot removes that: a
// path is split on "/" before its segments are percent-decoded, so "%2E" can
// never become a dot step.
func escapeKeySegment(key Key) string {
	return strings.ReplaceAll(url.PathEscape(key.String()), ".", "%2E")
}
