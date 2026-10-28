// Copyright (c) 2016-2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import "context"

// ContentType is the TeamVault secret content type. Only "password" and
// "file" are supported; "cc" is deliberately out of scope.
type ContentType string

const (
	// ContentTypePassword is a password secret.
	ContentTypePassword ContentType = "password"
	// ContentTypeFile is a file secret.
	ContentTypeFile ContentType = "file"
)

// CreateSecret describes a new secret to create. Exactly one of Password
// or FileContent carries the value; ContentType selects which. Metadata
// fields (Username/Url/Description) are optional and omitted from the
// request body when empty.
type CreateSecret struct {
	// ContentType selects the secret type: ContentTypePassword or ContentTypeFile.
	ContentType ContentType
	// Name is the secret name (required).
	Name string
	// Username is the optional username field.
	Username string
	// Url is the optional URL field.
	Url string
	// Description is the optional description field.
	Description string
	// Password is the password value, used when ContentType == ContentTypePassword.
	Password Password
	// FileContent is the raw file bytes, base64-encoded into secret_data when
	// ContentType == ContentTypeFile.
	FileContent []byte
	// Filename is the file name stored alongside FileContent. It is sent as the
	// top-level `filename` field, never inside secret_data, and TeamVault
	// rejects a file secret without it.
	Filename string
}

// UpdateSecret describes a partial update. Only non-nil pointer fields are
// sent, so a metadata-only update omits secret_data entirely, and each
// absent field is left untouched server-side. A non-nil Password or
// FileContent creates a new revision.
type UpdateSecret struct {
	// Name is the new secret name.
	Name *string
	// Username is the new username.
	Username *string
	// Url is the new URL.
	Url *string
	// Description is the new description.
	Description *string
	// Password is the new password value; non-nil creates a new revision.
	Password *Password
	// FileContent is the new file content; non-nil creates a new revision.
	FileContent []byte
	// Filename is the new file name, sent as the top-level `filename` field.
	// Omitted from the request when empty.
	Filename string
}

//counterfeiter:generate -o mocks/writer.go --fake-name Writer . Writer

// Writer creates and updates TeamVault secrets. It is intentionally
// separate from Connector so the read interface stays unchanged (a new
// method on the exported Connector would be a breaking, major-bump change).
type Writer interface {
	// Create posts a new secret and returns its key and api_url.
	Create(ctx context.Context, secret CreateSecret) (Key, ApiUrl, error)
	// Update patches an existing secret named by key. Only the fields set
	// in UpdateSecret are sent.
	Update(ctx context.Context, key Key, secret UpdateSecret) (Key, ApiUrl, error)
	// GeneratePassword asks the server to generate a strong password.
	GeneratePassword(ctx context.Context) (Password, error)
}
