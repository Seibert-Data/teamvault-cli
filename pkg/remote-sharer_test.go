// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"

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
				Expect(err.Error()).To(ContainSubstring("not both"))
				Expect(server.ReceivedRequests()).To(BeEmpty())
			})

			It("refuses neither user nor group", func() {
				_, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					GrantDescription: "because",
				})
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("one of user or group is required"))
			})

			It("refuses an empty description", func() {
				_, err := sharer.Share(ctx, teamvault.Key("AbC123"), teamvault.ShareRequest{
					User: "alice",
				})
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring("grant description is required"))
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
				Expect(result.Share.GrantedBy).To(Equal("bborbe"))
				Expect(result.Share.User).NotTo(BeNil())
				Expect(*result.Share.User).To(Equal("nuke-apply-dev"))
				Expect(result.Share.Group).To(BeNil())

				// The body is pinned: the server rejects a request carrying both or
				// neither, and grant_description is required.
				Expect(receivedBody).To(Equal(map[string]any{
					"user":              "nuke-apply-dev",
					"grant_description": "deploy reads",
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
					"grant_description": "ops reads",
				}))
				Expect(receivedBody).NotTo(HaveKey("user"))
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
			Expect(shares[0].GrantedBy).To(Equal("bborbe"))
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
	})
})
