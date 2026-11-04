// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import "strings"

// OneLine collapses a server-supplied message onto a single line: each result is
// one line by contract, and a body carrying CR/LF or other control characters
// would otherwise break the per-key output (and the parsing that reads it).
func OneLine(value string) string {
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
