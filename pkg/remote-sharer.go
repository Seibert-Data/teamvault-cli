// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bborbe/errors"
	"github.com/bborbe/time"
	"github.com/golang/glog"
)

// alreadySharedMarker identifies the server's duplicate-grant refusal. TeamVault
// raises a DRF ValidationError with code='unique' and the message "Secret … was
// already shared with …"; the response body carries the message, not the code,
// so the message is what the client can match on.
const alreadySharedMarker = "was already shared with"

// maxShareResults bounds how many grants Shares will page through, so a
// misbehaving server cannot make the list unbounded.
const maxShareResults = 1000

// NewRemoteSharer creates a Sharer that issues share calls to a remote TeamVault
// instance, reusing HTTP Basic auth identical to the read path.
func NewRemoteSharer(
	httpClient *http.Client,
	url Url,
	user User,
	pass Password,
	currentDateTime time.CurrentDateTime,
) Sharer {
	return &remoteSharer{
		httpClient:      httpClient,
		url:             url.Normalize(),
		user:            user,
		pass:            pass,
		currentDateTime: currentDateTime,
	}
}

type remoteSharer struct {
	httpClient      *http.Client
	url             Url
	user            User
	pass            Password
	currentDateTime time.CurrentDateTime
}

func (s *remoteSharer) Share(
	ctx context.Context,
	key Key,
	request ShareRequest,
) (ShareResult, error) {
	if err := request.Validate(ctx); err != nil {
		return ShareResult{}, err
	}

	// granted_until must be PRESENT even for a permanent grant. The server's
	// serializer declares it allow_null=True but not required=False, so DRF
	// treats an omitted key as a missing required field and answers
	// 400 {"granted_until":["This field is required."]}. null is the "permanent"
	// value. Found by the scenario-010 live round trip; the fake server does not
	// model this.
	var grantedUntil any
	if request.GrantedUntil != "" {
		grantedUntil = request.GrantedUntil
	}
	body := map[string]any{
		"grant_description": request.GrantDescription,
		"granted_until":     grantedUntil,
	}
	// BOTH user and group must be PRESENT, the unused one as an explicit null.
	// The server's validate() subscripts data['group'] and data['user'] directly,
	// so an omitted key is a KeyError and the endpoint answers 500 — not a 400.
	// (A bad username still returns a clean 400, because field-level validation
	// fails before validate() runs, which is what made this look like a server
	// fault rather than a request-shape bug.) Found by the scenario-010 live run.
	var user, group any
	if request.Group != "" {
		group = request.Group
	} else {
		user = request.User
	}
	body["user"] = user
	body["group"] = group

	var share Share
	status, detail, err := s.call(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/api/secrets/%s/shares/", s.url.String(), key.String()),
		body,
		&share,
	)
	if err != nil {
		return ShareResult{}, err
	}

	switch {
	case status/100 == 2:
		return ShareResult{Outcome: ShareCreated, Share: share}, nil
	case status == http.StatusBadRequest && strings.Contains(detail, alreadySharedMarker):
		// A duplicate is the outcome the caller asked for, not a failure: the
		// access exists either way, so re-running a grant stays idempotent.
		return ShareResult{Outcome: ShareAlreadyExists}, nil
	default:
		return ShareResult{}, &ShareError{Key: key, StatusCode: status, Detail: detail}
	}
}

func (s *remoteSharer) Shares(ctx context.Context, key Key) ([]Share, error) {
	baseParsed, err := url.Parse(s.url.String())
	if err != nil {
		return nil, errors.Wrapf(ctx, err, "parse base url failed")
	}
	nextURL := fmt.Sprintf("%s/api/secrets/%s/shares/", s.url.String(), key.String())

	var result []Share
	for len(result) < maxShareResults {
		// Each page is a round trip; stop between pages when the caller cancelled
		// rather than walking the rest of the pagination chain.
		if err := ctx.Err(); err != nil {
			return nil, errors.Wrapf(ctx, err, "list shares cancelled after %d grants", len(result))
		}
		var response struct {
			Next    *string `json:"next"`
			Results []Share `json:"results"`
		}

		status, detail, err := s.call(ctx, http.MethodGet, nextURL, nil, &response)
		if err != nil {
			return nil, err
		}
		if status/100 != 2 {
			return nil, &ShareError{Key: key, StatusCode: status, Detail: detail}
		}
		result = append(result, response.Results...)

		if response.Next == nil || *response.Next == "" {
			break
		}
		if len(result) >= maxShareResults {
			glog.Warningf(
				"teamvault shares: result cap (%d) reached; more grants exist but were not fetched",
				maxShareResults,
			)
			break
		}
		// Same-host pagination only: the Basic-auth header rides every request, so
		// following a tampered `next` to a different host would leak the TeamVault
		// credentials. A relative next is same-origin by definition; an absolute
		// one must match the configured host (host compared, not a raw prefix, so
		// an http/https difference behind a proxy does not break pagination).
		nextParsed, parseErr := url.Parse(*response.Next)
		if parseErr != nil {
			return nil, errors.Wrapf(ctx, parseErr, "parse next url %q failed", *response.Next)
		}
		if nextParsed.Host != "" && nextParsed.Host != baseParsed.Host {
			return nil, errors.Errorf(
				ctx,
				"refusing to follow share pagination to a different host %q (expected %q)",
				nextParsed.Host,
				baseParsed.Host,
			)
		}
		nextURL = baseParsed.ResolveReference(nextParsed).String()
	}

	return result, nil
}

// call issues one request and returns the HTTP status plus, for a non-2xx
// response, the body. A non-2xx is deliberately not an error here: Share maps
// some statuses to an outcome rather than a failure, so the caller decides.
// Transport and encoding failures are errors.
func (s *remoteSharer) call(
	ctx context.Context,
	method string,
	url string,
	body any,
	response any,
) (int, string, error) {
	glog.V(4).Infof("rest %s to %s", method, url)
	start := s.currentDateTime.Now()
	defer glog.V(8).
		Infof("%s %s completed in %dms", method, url, s.currentDateTime.Now().Sub(start)/time.Millisecond)

	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return 0, "", errors.Wrapf(ctx, err, "marshal request body failed")
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload))
	if err != nil {
		return 0, "", errors.Wrapf(ctx, err, "build request failed")
	}

	for key, values := range newBasicAuthHeader(s.user, s.pass) {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := s.httpClient.Do(
		req,
	) // #nosec G704 -- URLs are constructed from the configured base URL and API paths, not user input
	if err != nil {
		return 0, "", errors.Wrapf(ctx, err, "execute request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		glog.V(4).Infof("request to %s failed with status: %d", url, resp.StatusCode)
		return resp.StatusCode, readErrorDetail(resp), nil
	}

	if response != nil {
		if err = json.NewDecoder(resp.Body).Decode(response); err != nil {
			return resp.StatusCode, "", errors.Wrapf(ctx, err, "decode response failed")
		}
	}
	return resp.StatusCode, "", nil
}
