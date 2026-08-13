// Copyright (c) 2016-2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import (
	"fmt"
	"strings"
)

// ApiUrl represents a TeamVault API URL.
type ApiUrl string

// String returns the string representation of the ApiUrl.
func (a ApiUrl) String() string {
	return string(a)
}

// Key extracts the TeamVault Key from the API URL path.
func (a ApiUrl) Key() (Key, error) {
	parts := strings.Split(a.String(), "/")
	if len(parts) < 3 {
		return "", fmt.Errorf("parse key from api-url failed")
	}
	return Key(parts[len(parts)-2]), nil
}
