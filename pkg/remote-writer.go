// Copyright (c) 2016-2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bborbe/errors"
	"github.com/bborbe/time"
	"github.com/golang/glog"
)

// maxErrorDetailBytes bounds how much of a non-2xx response body is folded into
// the returned error, so a misbehaving proxy cannot balloon the message.
const maxErrorDetailBytes = 4096

// NewRemoteWriter creates a Writer that issues POST/PATCH calls to a remote
// TeamVault instance, reusing HTTP Basic auth identical to the read path.
func NewRemoteWriter(
	httpClient *http.Client,
	url Url,
	user User,
	pass Password,
	currentDateTime time.CurrentDateTime,
) Writer {
	return &remoteWriter{
		httpClient:      httpClient,
		url:             url.Normalize(),
		user:            user,
		pass:            pass,
		currentDateTime: currentDateTime,
	}
}

type remoteWriter struct {
	httpClient      *http.Client
	url             Url
	user            User
	pass            Password
	currentDateTime time.CurrentDateTime
}

func (w *remoteWriter) Create(ctx context.Context, secret CreateSecret) (Key, ApiUrl, error) {
	secretData := make(map[string]string)
	switch secret.ContentType {
	case ContentTypePassword:
		secretData["password"] = secret.Password.String()
	case ContentTypeFile:
		secretData["file_content"] = base64.StdEncoding.EncodeToString(secret.FileContent)
	}

	body := map[string]any{
		"content_type": string(secret.ContentType),
		"name":         secret.Name,
		"secret_data":  secretData,
	}
	// filename is a field on the Secret itself, not on secret_data, and
	// TeamVault rejects a file secret without it.
	if secret.ContentType == ContentTypeFile && secret.Filename != "" {
		body["filename"] = secret.Filename
	}
	if secret.Username != "" {
		body["username"] = secret.Username
	}
	if secret.Url != "" {
		body["url"] = secret.Url
	}
	if secret.Description != "" {
		body["description"] = secret.Description
	}

	var response struct {
		ApiUrl ApiUrl `json:"api_url"`
	}
	if err := w.call(ctx, http.MethodPost, fmt.Sprintf("%s/api/secrets/", w.url.String()), body, &response); err != nil {
		return "", "", err
	}
	key, err := response.ApiUrl.Key()
	if err != nil {
		return "", "", errors.Wrapf(ctx, err, "parse key from api_url failed")
	}
	return key, response.ApiUrl, nil
}

func (w *remoteWriter) Update(
	ctx context.Context,
	key Key,
	secret UpdateSecret,
) (Key, ApiUrl, error) {
	body := make(map[string]any)

	if secret.Name != nil {
		body["name"] = *secret.Name
	}
	if secret.Username != nil {
		body["username"] = *secret.Username
	}
	if secret.Url != nil {
		body["url"] = *secret.Url
	}
	if secret.Description != nil {
		body["description"] = *secret.Description
	}

	// Only include secret_data when a value field is set
	hasValue := false
	secretData := make(map[string]string)
	if secret.Password != nil {
		secretData["password"] = secret.Password.String()
		hasValue = true
	}
	if secret.FileContent != nil {
		secretData["file_content"] = base64.StdEncoding.EncodeToString(secret.FileContent)
		hasValue = true
	}
	if hasValue {
		body["secret_data"] = secretData
	}
	if secret.Filename != "" {
		body["filename"] = secret.Filename
	}

	var response struct {
		ApiUrl ApiUrl `json:"api_url"`
	}
	if err := w.call(ctx, http.MethodPatch, fmt.Sprintf("%s/api/secrets/%s/", w.url.String(), key.String()), body, &response); err != nil {
		return "", "", err
	}
	return key, response.ApiUrl, nil
}

func (w *remoteWriter) GeneratePassword(ctx context.Context) (Password, error) {
	var response struct {
		Password Password `json:"password"`
	}
	if err := w.call(ctx, http.MethodPost, fmt.Sprintf("%s/api/generate_password/", w.url.String()), nil, &response); err != nil {
		return "", err
	}
	return response.Password, nil
}

func (w *remoteWriter) call(ctx context.Context, method, url string, body any, response any) error {
	glog.V(4).Infof("rest %s to %s", method, url)
	start := w.currentDateTime.Now()
	defer glog.V(8).
		Infof("%s %s completed in %dms", method, url, w.currentDateTime.Now().Sub(start)/time.Millisecond)

	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return errors.Wrapf(ctx, err, "marshal request body failed")
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		return errors.Wrapf(ctx, err, "build request failed")
	}

	for key, values := range w.createHeader() {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := w.httpClient.Do(
		req,
	) // #nosec G704 -- URLs are constructed from configured base URL and API paths, not user input
	if err != nil {
		return errors.Wrapf(ctx, err, "execute request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		glog.V(4).Infof("request to %s failed with status: %d", url, resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return errors.Errorf(
				ctx,
				"request to %s failed with status: %d (authentication failed) — run `teamvault-cli login` to (re)store your TeamVault password in the Keychain",
				url,
				resp.StatusCode,
			)
		}
		// The server's validation body names the offending field and message;
		// without it a 400 is opaque. Only the response is read, never the
		// request, so no secret value can reach the error.
		detail, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorDetailBytes))
		detail = bytes.TrimSpace(detail)
		if readErr != nil || len(detail) == 0 {
			return errors.Errorf(ctx, "request to %s failed with status: %d", url, resp.StatusCode)
		}
		return errors.Errorf(
			ctx,
			"request to %s failed with status: %d: %s",
			url,
			resp.StatusCode,
			detail,
		)
	}

	if response != nil {
		if err = json.NewDecoder(resp.Body).Decode(response); err != nil {
			return errors.Wrapf(ctx, err, "decode response failed")
		}
	}
	return nil
}

func (w *remoteWriter) createHeader() http.Header {
	httpHeader := make(http.Header)
	httpHeader.Add(
		"Authorization",
		fmt.Sprintf(
			"Basic %s",
			base64.StdEncoding.EncodeToString(
				[]byte(fmt.Sprintf("%s:%s", w.user.String(), w.pass.String())),
			),
		),
	)
	httpHeader.Add("Content-Type", "application/json")
	return httpHeader
}
