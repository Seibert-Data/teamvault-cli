// Copyright (c) 2016-2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bborbe/errors"
	"github.com/bborbe/time"
	"github.com/golang/glog"
)

var (
	// ErrUserType is returned when a TeamVault username JSON value is neither a string nor a number.
	ErrUserType = stderrors.New("username must be string or number")
	// ErrPasswordType is returned when a TeamVault password JSON value is neither a string nor a number.
	ErrPasswordType = stderrors.New("password must be string or number")
)

// Url represents a TeamVault URL or secret URL value.
type Url string

// String returns the string representation of the Url.
func (u Url) String() string {
	return string(u)
}

// Normalize returns the Url with surrounding whitespace and trailing slashes
// removed. TeamVault API paths are built as "<url>/api/secrets/...", so a base
// URL that ends in a slash (e.g. the value copied from a browser,
// "https://teamvault.example.com/") would produce a double-slash path that
// 404s. It is also the key the Keychain stores the password under, so login
// (write) and fetch (read) must normalize identically or the lookup misses.
func (u Url) Normalize() Url {
	return Url(strings.TrimRight(strings.TrimSpace(string(u)), "/"))
}

// User represents a TeamVault username.
type User string

// String returns the string representation of the User.
func (u User) String() string {
	return string(u)
}

// UnmarshalJSON implements json.Unmarshaler to handle both string and number types.
func (u *User) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as string first
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*u = User(str)
		return nil
	}

	// If that fails, try as number and convert to string
	var num json.Number
	if err := json.Unmarshal(data, &num); err == nil {
		*u = User(num.String())
		return nil
	}

	return ErrUserType
}

// Password represents a TeamVault password.
type Password string

// String returns the string representation of the Password.
func (t Password) String() string {
	return string(t)
}

// UnmarshalJSON implements json.Unmarshaler to handle both string and number types.
func (t *Password) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as string first
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*t = Password(str)
		return nil
	}

	// If that fails, try as number and convert to string
	var num json.Number
	if err := json.Unmarshal(data, &num); err == nil {
		*t = Password(num.String())
		return nil
	}

	return ErrPasswordType
}

// NewRemoteConnector creates a new Connector that connects to a remote TeamVault instance.
func NewRemoteConnector(
	httpClient *http.Client,
	url Url,
	user User,
	pass Password,
	currentDateTime time.CurrentDateTime,
) Connector {
	return &remoteConnector{
		httpClient:      httpClient,
		url:             url.Normalize(),
		user:            user,
		pass:            pass,
		currentDateTime: currentDateTime,
	}
}

type remoteConnector struct {
	url             Url
	user            User
	pass            Password
	httpClient      *http.Client
	currentDateTime time.CurrentDateTime
}

func (r *remoteConnector) Password(ctx context.Context, key Key) (Password, error) {
	currentRevision, err := r.CurrentRevision(ctx, key)
	if err != nil {
		return "", err
	}
	var response struct {
		Password Password `json:"password"`
	}
	if err := r.call(ctx, fmt.Sprintf("%sdata", currentRevision.String()), nil, &response, r.createHeader()); err != nil {
		return "", err
	}
	return response.Password, nil
}

func (r *remoteConnector) User(ctx context.Context, key Key) (User, error) {
	var response struct {
		User User `json:"username"`
	}
	if err := r.call(ctx, r.url.String()+secretPath(key), nil, &response, r.createHeader()); err != nil {
		return "", err
	}
	return response.User, nil
}

func (r *remoteConnector) Url(ctx context.Context, key Key) (Url, error) {
	var response struct {
		Url Url `json:"url"`
	}
	if err := r.call(ctx, r.url.String()+secretPath(key), nil, &response, r.createHeader()); err != nil {
		return "", err
	}
	return response.Url, nil
}

func (r *remoteConnector) CurrentRevision(ctx context.Context, key Key) (CurrentRevision, error) {
	var response struct {
		CurrentRevision CurrentRevision `json:"current_revision"`
	}
	if err := r.call(ctx, r.url.String()+secretPath(key), nil, &response, r.createHeader()); err != nil {
		return "", err
	}
	return response.CurrentRevision, nil
}

func (r *remoteConnector) File(ctx context.Context, key Key) (File, error) {
	rev, err := r.CurrentRevision(ctx, key)
	if err != nil {
		return "", errors.Wrapf(ctx, err, "get current revision failed")
	}
	var response struct {
		File File `json:"file"`
	}
	if err := r.call(ctx, fmt.Sprintf("%sdata", rev.String()), nil, &response, r.createHeader()); err != nil {
		return "", err
	}
	return response.File, nil
}

func (r *remoteConnector) createHeader() http.Header {
	httpHeader := make(http.Header)
	httpHeader.Add(
		"Authorization",
		fmt.Sprintf(
			"Basic %s",
			base64.StdEncoding.EncodeToString(
				[]byte(fmt.Sprintf("%s:%s", r.user.String(), r.pass.String())),
			),
		),
	)
	httpHeader.Add("Content-Type", "application/json")
	return httpHeader
}

const maxSearchResults = 1000

func (r *remoteConnector) Search(ctx context.Context, search string) ([]SearchResult, error) {
	var result []SearchResult
	baseParsed, err := url.Parse(r.url.String())
	if err != nil {
		return nil, errors.Wrapf(ctx, err, "parse base url failed")
	}
	nextURL := fmt.Sprintf("%s/api/secrets/", r.url.String())
	values := url.Values{}
	values.Add("search", search)
	isFirstPage := true

	for len(result) < maxSearchResults {
		var response struct {
			Next    *string `json:"next"`
			Results []struct {
				Hashid   string `json:"hashid"`
				Name     string `json:"name"`
				Username string `json:"username"`
				Url      Url    `json:"url"`
			} `json:"results"`
		}

		var callErr error
		if isFirstPage {
			callErr = r.call(ctx, nextURL, values, &response, r.createHeader())
		} else {
			// Subsequent pages: the next URL already carries the query string.
			callErr = r.call(ctx, nextURL, nil, &response, r.createHeader())
		}
		if callErr != nil {
			return nil, errors.Wrapf(ctx, callErr, "search call failed")
		}
		isFirstPage = false

		for _, re := range response.Results {
			result = append(result, SearchResult{
				Key:      Key(re.Hashid),
				Name:     re.Name,
				Username: re.Username,
				Url:      re.Url,
			})
		}

		if response.Next == nil || *response.Next == "" {
			break
		}
		// Warn (don't silently drop) when the safety cap is reached while more
		// pages remain, so the caller knows the result set is incomplete.
		if len(result) >= maxSearchResults {
			glog.Warningf(
				"teamvault search: result cap (%d) reached; more matches exist but were not fetched",
				maxSearchResults,
			)
			break
		}
		// Same-host pagination only: the Basic-auth header is attached to every
		// request, so following a tampered `next` to a different host would leak
		// the TeamVault credentials. A relative next (no host) is same-origin by
		// definition and is resolved against the base; an absolute next must match
		// the configured host (host compared, not a raw prefix, so an http/https
		// difference behind a proxy doesn't break legitimate pagination).
		nextParsed, parseErr := url.Parse(*response.Next)
		if parseErr != nil {
			return nil, errors.Wrapf(ctx, parseErr, "parse next url %q failed", *response.Next)
		}
		// Hosts compare case-insensitively: DNS is case-insensitive and a proxy may
		// rewrite the casing, which would otherwise read as a different host.
		if nextParsed.Host != "" && !strings.EqualFold(nextParsed.Host, baseParsed.Host) {
			return nil, errors.Errorf(
				ctx,
				"refusing to follow search pagination to a different host %q (expected %q)",
				nextParsed.Host,
				baseParsed.Host,
			)
		}
		// A same-host downgrade still leaks the Basic-auth header in cleartext.
		if baseParsed.Scheme == "https" && nextParsed.Scheme == "http" {
			return nil, errors.Errorf(
				ctx,
				"refusing to follow search pagination from https to http (credentials would travel in cleartext)",
			)
		}
		nextURL = baseParsed.ResolveReference(nextParsed).String()
	}

	return result, nil
}

func (r *remoteConnector) call(
	ctx context.Context,
	url string,
	values url.Values,
	response interface{},
	headers http.Header,
) error {
	if values != nil {
		url = fmt.Sprintf("%s?%s", url, values.Encode())
	}
	glog.V(4).Infof("rest GET to %s", url)
	start := r.currentDateTime.Now()
	defer glog.V(8).
		Infof("create completed in %dms", r.currentDateTime.Now().Sub(start)/time.Millisecond)
	glog.V(8).Infof("send message to %s", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		glog.V(2).Infof("build request failed: %v", err)
		return errors.Wrapf(ctx, err, "build request failed")
	}
	req.Header.Set("ContentType", "application/json")
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := r.httpClient.Do(
		req,
	) // #nosec G704 -- the host comes from the configuration; the secret key is url.PathEscape'd into one path segment
	if err != nil {
		glog.V(2).Infof("execute request failed: %v", err)
		return errors.Wrapf(ctx, err, "execute request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// V(4): the URL path contains the lookup key; keep it out of the common V(2) log tier.
		glog.V(4).Infof("request to %s failed with status: %d", url, resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			// Keep "status: %d" (with colon) — isAuthError in login.go matches on it
			// to drive the login retry loop.
			return errors.Errorf(
				ctx,
				"request to %s failed with status: %d (authentication failed) — run `teamvault-cli login` to (re)store your TeamVault password in the Keychain",
				url,
				resp.StatusCode,
			)
		}
		return errors.Errorf(ctx, "request to %s failed with status: %d", url, resp.StatusCode)
	}
	if response != nil {
		if err = json.NewDecoder(resp.Body).Decode(response); err != nil {
			glog.V(2).Infof("decode response failed: %v", err)
			return errors.Wrapf(ctx, err, "decode response failed")
		}
	}
	glog.V(8).Infof("rest call successful")
	return nil
}
