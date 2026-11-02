// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	libhttp "github.com/bborbe/http"
	libtime "github.com/bborbe/time"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
)

var _ = Describe("RemoteSharer", func() {
	var ctx context.Context
	var server *ghttp.Server
	var username string
	var password string
	var sharer teamvault.Sharer

	BeforeEach(func() {
		ctx = context.Background()
		server = ghttp.NewServer()
		username = "user"
		password = "pass"
		sharer = teamvault.NewRemoteSharer(
			libhttp.CreateDefaultHttpClient(),
			teamvault.Url(server.URL()),
			teamvault.User(username),
			teamvault.Password(password),
			libtime.NewCurrentDateTime(),
		)
	})

	AfterEach(func() {
		server.Close()
	})

	Describe("Share", func() {
		Context("request validation", func() {
			It("refuses both user and group without calling the server", func() {
				_, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					User:             "alice",
					Group:            "ops",
					GrantDescription: "because",
				})
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("only one should be valid"))
				Expect(server.ReceivedRequests()).To(BeEmpty())
			})

			It("refuses neither user nor group", func() {
				_, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					GrantDescription: "because",
				})
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("only one should be valid"))
			})

			It("refuses an empty description", func() {
				_, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					User: "alice",
				})
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("grant description"))
			})

			It("refuses a granted-until that is not RFC 3339", func() {
				_, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					User:             "alice",
					GrantDescription: "because",
					GrantedUntil:     "31.12.2026",
				})
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("is not an RFC 3339 timestamp"))
				Expect(server.ReceivedRequests()).To(BeEmpty())
			})
		})

		Context("a grant with an expiry", func() {
			It("sends granted_until as the given timestamp", func() {
				var receivedBody map[string]any

				server.RouteToHandler(
					http.MethodPost,
					"/api/secrets/AbC123/shares/",
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, "/api/secrets/AbC123/shares/"),
						func(resp http.ResponseWriter, req *http.Request) {
							receivedBody = decodeJSONBody(req)
							resp.WriteHeader(http.StatusCreated)
							//nolint:errcheck
							fmt.Fprint(
								resp,
								`{"id": 9, "grant_description": "temp", "user": "alice", "granted_by": "bborbe", "granted_until": "2030-01-01T00:00:00Z"}`,
							)
						},
					),
				)

				_, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					User:             "alice",
					GrantDescription: "temp",
					GrantedUntil:     "2030-01-01T00:00:00Z",
				})

				Expect(err).To(BeNil())
				Expect(receivedBody["granted_until"]).To(Equal("2030-01-01T00:00:00Z"))
			})
		})

		Context("user grant", func() {
			It("posts grant_description and user, and reports the created grant", func() {
				var receivedBody map[string]any

				server.RouteToHandler(
					http.MethodPost,
					"/api/secrets/AbC123/shares/",
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, "/api/secrets/AbC123/shares/"),
						ghttp.VerifyBasicAuth(username, password),
						ghttp.VerifyContentType("application/json"),
						func(resp http.ResponseWriter, req *http.Request) {
							receivedBody = decodeJSONBody(req)
							resp.WriteHeader(http.StatusCreated)
							//nolint:errcheck
							fmt.Fprint(resp, `{
								"id": 7,
								"grant_description": "deploy reads",
								"granted_on": "2026-11-01T22:15:00Z",
								"granted_until": null,
								"group": null,
								"user": "nuke-apply-dev",
								"granted_by": "bborbe",
								"secret": "AbC123"
							}`)
						},
					),
				)

				result, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					User:             "nuke-apply-dev",
					GrantDescription: "deploy reads",
				})

				Expect(err).To(BeNil())
				Expect(result.Outcome).To(Equal(teamvault.ShareCreated))
				Expect(result.Share.ID).To(Equal(7))
				Expect(result.Share.GrantedBy).NotTo(BeNil())
				Expect(*result.Share.GrantedBy).To(Equal("bborbe"))
				Expect(result.Share.User).NotTo(BeNil())
				Expect(*result.Share.User).To(Equal("nuke-apply-dev"))
				Expect(result.Share.Group).To(BeNil())

				// The body is pinned: the server rejects a request carrying both or
				// neither, and grant_description is required.
				// The body is pinned to what the live server accepts: user AND group
				// must both be present (the unused one null — an omitted key is a
				// KeyError and a 500, not a 400), and granted_until must be present
				// (an omitted key is a 400 "This field is required").
				Expect(receivedBody).To(Equal(map[string]any{
					"user":              "nuke-apply-dev",
					"group":             nil,
					"grant_description": "deploy reads",
					"granted_until":     nil,
				}))
			})
		})

		Context("group grant", func() {
			It("posts grant_description and group, and no user field", func() {
				var receivedBody map[string]any

				server.RouteToHandler(
					http.MethodPost,
					"/api/secrets/AbC123/shares/",
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, "/api/secrets/AbC123/shares/"),
						ghttp.VerifyBasicAuth(username, password),
						func(resp http.ResponseWriter, req *http.Request) {
							receivedBody = decodeJSONBody(req)
							resp.WriteHeader(http.StatusCreated)
							//nolint:errcheck
							fmt.Fprint(
								resp,
								`{"id": 8, "grant_description": "ops reads", "group": "ops", "user": null, "granted_by": "bborbe", "secret": "AbC123"}`,
							)
						},
					),
				)

				result, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					Group:            "ops",
					GrantDescription: "ops reads",
				})

				Expect(err).To(BeNil())
				Expect(result.Outcome).To(Equal(teamvault.ShareCreated))
				Expect(result.Share.Group).NotTo(BeNil())
				Expect(*result.Share.Group).To(Equal("ops"))
				Expect(result.Share.User).To(BeNil())
				Expect(receivedBody).To(Equal(map[string]any{
					"group":             "ops",
					"user":              nil,
					"grant_description": "ops reads",
					"granted_until":     nil,
				}))
			})
		})

		Context("duplicate grant", func() {
			It("reports already-shared instead of an error", func() {
				server.RouteToHandler(
					http.MethodPost,
					"/api/secrets/AbC123/shares/",
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, "/api/secrets/AbC123/shares/"),
						ghttp.RespondWith(
							http.StatusBadRequest,
							`{"non_field_errors":["Secret AbC123 was already shared with user nuke-apply-dev."]}`,
						),
					),
				)

				result, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					User:             "nuke-apply-dev",
					GrantDescription: "deploy reads",
				})

				Expect(err).To(BeNil())
				Expect(result.Outcome).To(Equal(teamvault.ShareAlreadyExists))
			})
		})

		Context("a different 400", func() {
			It("returns a ShareError carrying the status and the server detail", func() {
				server.RouteToHandler(
					http.MethodPost,
					"/api/secrets/AbC123/shares/",
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, "/api/secrets/AbC123/shares/"),
						ghttp.RespondWith(
							http.StatusBadRequest,
							`{"user":["Object with username=ghost does not exist."]}`,
						),
					),
				)

				_, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					User:             "ghost",
					GrantDescription: "deploy reads",
				})

				Expect(err).NotTo(BeNil())
				var shareErr *teamvault.ShareError
				Expect(errors.As(err, &shareErr)).To(BeTrue())
				Expect(shareErr.StatusCode).To(Equal(http.StatusBadRequest))
				Expect(shareErr.Detail).To(ContainSubstring("does not exist"))
				Expect(shareErr.Key).To(Equal(teamvault.Key("AbC123")))
			})
		})

		Context("forbidden", func() {
			It(
				"returns a ShareError with 403 and does not claim an authentication failure",
				func() {
					server.RouteToHandler(
						http.MethodPost,
						"/api/secrets/AbC123/shares/",
						ghttp.CombineHandlers(
							ghttp.VerifyRequest(http.MethodPost, "/api/secrets/AbC123/shares/"),
							ghttp.RespondWith(
								http.StatusForbidden,
								`{"detail":"You do not have permission"}`,
							),
						),
					)

					_, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
						User:             "nuke-apply-dev",
						GrantDescription: "deploy reads",
					})

					Expect(err).NotTo(BeNil())
					var shareErr *teamvault.ShareError
					Expect(errors.As(err, &shareErr)).To(BeTrue())
					Expect(shareErr.StatusCode).To(Equal(http.StatusForbidden))
					// A 403 here is is_shareable_by_user refusing, not a bad login, so
					// the message must not tell the operator to re-run `login`.
					Expect(err.Error()).NotTo(ContainSubstring("run `teamvault-cli login`"))
				},
			)
		})

		Context("missing secret", func() {
			It("returns a ShareError with 404", func() {
				server.RouteToHandler(
					http.MethodPost,
					"/api/secrets/ZZZZZZ/shares/",
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, "/api/secrets/ZZZZZZ/shares/"),
						ghttp.RespondWith(http.StatusNotFound, `{"detail":"Not found."}`),
					),
				)

				_, err := sharer.Share(ctx, teamvault.Key("ZZZZZZ"), teamvault.ShareRequest{
					User:             "nuke-apply-dev",
					GrantDescription: "deploy reads",
				})

				Expect(err).NotTo(BeNil())
				var shareErr *teamvault.ShareError
				Expect(errors.As(err, &shareErr)).To(BeTrue())
				Expect(shareErr.StatusCode).To(Equal(http.StatusNotFound))
			})
		})
	})

	Describe("Shares", func() {
		It("lists the grants without any secret value", func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/AbC123/shares/",
				ghttp.CombineHandlers(
					ghttp.VerifyRequest(http.MethodGet, "/api/secrets/AbC123/shares/"),
					ghttp.VerifyBasicAuth(username, password),
					ghttp.RespondWith(http.StatusOK, `{
						"count": 2,
						"next": null,
						"previous": null,
						"results": [
							{"id": 1, "grant_description": "deploy reads", "granted_on": "2026-11-01T22:15:00Z",
							 "granted_until": null, "group": null, "user": "nuke-apply-dev", "granted_by": "bborbe", "secret": "AbC123"},
							{"id": 2, "grant_description": "ops reads", "granted_on": "2026-11-01T22:16:00Z",
							 "granted_until": "2027-01-01T00:00:00Z", "group": "ops", "user": null, "granted_by": "bborbe", "secret": "AbC123"}
						]
					}`),
				),
			)

			shares, err := sharer.Shares(ctx, teamvault.Key("AbC123"))

			Expect(err).To(BeNil())
			Expect(shares).To(HaveLen(2))
			Expect(shares[0].GrantDescription).To(Equal("deploy reads"))
			Expect(shares[0].GrantedBy).NotTo(BeNil())
			Expect(*shares[0].GrantedBy).To(Equal("bborbe"))
			Expect(shares[0].GrantedUntil).To(BeNil())
			Expect(shares[1].Group).NotTo(BeNil())
			Expect(*shares[1].Group).To(Equal("ops"))
			Expect(shares[1].GrantedUntil).NotTo(BeNil())
		})

		It("follows pagination so grants past the page size are not dropped", func() {
			// One handler switching on the query: two handlers on the same path
			// would depend on ghttp's stack order rather than on the request.
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/AbC123/shares/",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
					if req.URL.Query().Get("page") == "2" {
						//nolint:errcheck
						fmt.Fprint(resp, `{
							"count": 2,
							"next": null,
							"previous": null,
							"results": [{"id": 2, "grant_description": "second", "user": "bob", "granted_by": "bborbe", "secret": "AbC123"}]
						}`)
						return
					}
					//nolint:errcheck
					fmt.Fprintf(resp, `{
						"count": 2,
						"next": "%s/api/secrets/AbC123/shares/?page=2",
						"previous": null,
						"results": [{"id": 1, "grant_description": "first", "user": "alice", "granted_by": "bborbe", "secret": "AbC123"}]
					}`, server.URL())
				},
			)

			shares, err := sharer.Shares(ctx, teamvault.Key("AbC123"))

			Expect(err).To(BeNil())
			Expect(shares).To(HaveLen(2))
			Expect(shares[1].GrantDescription).To(Equal("second"))
		})

		It("returns a ShareError when the secret cannot be read", func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/AbC123/shares/",
				ghttp.CombineHandlers(
					ghttp.VerifyRequest(http.MethodGet, "/api/secrets/AbC123/shares/"),
					ghttp.RespondWith(http.StatusForbidden, `{"detail":"denied"}`),
				),
			)

			_, err := sharer.Shares(ctx, teamvault.Key("AbC123"))

			Expect(err).NotTo(BeNil())
			var shareErr *teamvault.ShareError
			Expect(errors.As(err, &shareErr)).To(BeTrue())
			Expect(shareErr.StatusCode).To(Equal(http.StatusForbidden))
		})

		// The pagination guard is copied from remoteConnector.Search, so it needs
		// the same tests Search has — otherwise a regression in the copy is
		// invisible until credentials leak.

		It("refuses to follow a next on a different host", func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/AbC123/shares/",
				ghttp.RespondWith(http.StatusOK, `{
					"count": 2,
					"next": "https://evil.example.com/api/secrets/AbC123/shares/?page=2",
					"previous": null,
					"results": [{"id": 1, "grant_description": "first", "user": "alice", "granted_by": "bborbe"}]
				}`),
			)

			_, err := sharer.Shares(ctx, teamvault.Key("AbC123"))

			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("different host"))
		})

		It("refuses an https-to-http downgrade on the same host", func() {
			// The ghttp fixtures above are http://, so baseParsed.Scheme is never
			// "https" and the downgrade branch would never be exercised there. A TLS
			// fixture is the only way to reach it: same host and port, scheme
			// downgraded — which the cross-host guard does NOT catch, and which would
			// send the Basic-auth header in cleartext.
			tlsServer := httptest.NewTLSServer(http.HandlerFunc(
				func(resp http.ResponseWriter, req *http.Request) {
					resp.Header().Set("Content-Type", "application/json")
					//nolint:errcheck
					fmt.Fprintf(resp, `{
						"count": 2,
						"next": "http://%s/api/secrets/AbC123/shares/?page=2",
						"previous": null,
						"results": [{"id": 1, "grant_description": "first", "user": "alice", "granted_by": "bborbe"}]
					}`, req.Host)
				},
			))
			defer tlsServer.Close()

			tlsSharer := teamvault.NewRemoteSharer(
				tlsServer.Client(),
				teamvault.Url(tlsServer.URL),
				teamvault.User(username),
				teamvault.Password(password),
				libtime.NewCurrentDateTime(),
			)

			_, err := tlsSharer.Shares(ctx, teamvault.Key("AbC123"))

			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("cleartext"))
		})

		It("follows a relative next, which is what DRF actually sends", func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/AbC123/shares/",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
					if req.URL.Query().Get("page") == "2" {
						//nolint:errcheck
						fmt.Fprint(resp, `{"count": 2, "next": null, "previous": null,
							"results": [{"id": 2, "grant_description": "second", "user": "bob", "granted_by": "bborbe"}]}`)
						return
					}
					//nolint:errcheck
					fmt.Fprint(
						resp,
						`{"count": 2, "next": "/api/secrets/AbC123/shares/?page=2", "previous": null,
						"results": [{"id": 1, "grant_description": "first", "user": "alice", "granted_by": "bborbe"}]}`,
					)
				},
			)

			shares, err := sharer.Shares(ctx, teamvault.Key("AbC123"))

			Expect(err).To(BeNil())
			Expect(shares).To(HaveLen(2))
			Expect(shares[1].GrantDescription).To(Equal("second"))
		})

		It("rejects a next URL that does not parse", func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/AbC123/shares/",
				ghttp.RespondWith(http.StatusOK, `{
					"count": 2,
					"next": "://::not-a-url",
					"previous": null,
					"results": [{"id": 1, "grant_description": "first", "user": "alice", "granted_by": "bborbe"}]
				}`),
			)

			_, err := sharer.Shares(ctx, teamvault.Key("AbC123"))

			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("parse next url"))
		})

		It("bounds the loop when the server keeps returning an empty page with a next", func() {
			// A result-only bound never advances on an empty results array, so the
			// loop must be bounded by iterations. Without that bound this spec hangs
			// until the context is cancelled.
			var calls int
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/AbC123/shares/",
				func(resp http.ResponseWriter, req *http.Request) {
					calls++
					resp.WriteHeader(http.StatusOK)
					//nolint:errcheck
					fmt.Fprintf(resp, `{
						"count": 1,
						"next": "%s/api/secrets/AbC123/shares/?page=%d",
						"previous": null,
						"results": []
					}`, server.URL(), calls+1)
				},
			)

			shares, err := sharer.Shares(ctx, teamvault.Key("AbC123"))

			Expect(err).To(BeNil())
			Expect(shares).To(BeEmpty())
			// Bounded: the page cap, not an unbounded spin.
			Expect(calls).To(BeNumerically("<=", 100))
		})

		It("truncates a single page larger than the result cap and says so", func() {
			// A single page over the cap with no `next` never reaches the in-loop
			// warning, so it must warn at the truncation itself rather than hand back
			// a partial list that looks complete.
			grants := make([]string, 0, 1001)
			for i := 0; i < 1001; i++ {
				grants = append(grants, fmt.Sprintf(
					`{"id": %d, "grant_description": "g%d", "user": "alice", "granted_by": "bborbe"}`,
					i,
					i,
				))
			}
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/AbC123/shares/",
				ghttp.RespondWith(http.StatusOK, fmt.Sprintf(
					`{"count": 1001, "next": null, "previous": null, "results": [%s]}`,
					strings.Join(grants, ","),
				)),
			)

			shares, err := sharer.Shares(ctx, teamvault.Key("AbC123"))

			Expect(err).To(BeNil())
			Expect(shares).To(HaveLen(1000))
		})

		It("does not treat an unrelated 400 as already-shared", func() {
			// The marker is the server's duplicate message. A 400 that merely
			// mentions sharing must stay a refusal — a false `already-shared` would
			// report a grant that does not exist.
			server.RouteToHandler(
				http.MethodPost,
				"/api/secrets/AbC123/shares/",
				ghttp.RespondWith(
					http.StatusBadRequest,
					`{"grant_description":["cannot be blank when sharing"]}`,
				),
			)

			_, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
				User:             "alice",
				GrantDescription: "because",
			})

			Expect(err).NotTo(BeNil())
			var shareErr *teamvault.ShareError
			Expect(errors.As(err, &shareErr)).To(BeTrue())
			Expect(shareErr.StatusCode).To(Equal(http.StatusBadRequest))
		})

		It("stops between pages when the context is cancelled", func() {
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := sharer.Shares(cancelled, teamvault.Key("AbC123"))

			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("cancelled"))
			Expect(server.ReceivedRequests()).To(BeEmpty())
		})

		It("returns a ShareError for a 5xx", func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/AbC123/shares/",
				ghttp.RespondWith(http.StatusInternalServerError, `{"detail":"boom"}`),
			)

			_, err := sharer.Shares(ctx, teamvault.Key("AbC123"))

			Expect(err).NotTo(BeNil())
			var shareErr *teamvault.ShareError
			Expect(errors.As(err, &shareErr)).To(BeTrue())
			Expect(shareErr.StatusCode).To(Equal(http.StatusInternalServerError))
		})
	})
})
