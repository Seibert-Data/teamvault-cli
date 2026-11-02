// Copyright (c) 2016-2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	libhttp "github.com/bborbe/http"
	libtime "github.com/bborbe/time"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
)

var _ = Describe("RemoteConnector", func() {
	var ctx context.Context
	var err error
	var remoteConnector teamvault.Connector
	var key teamvault.Key
	var username string
	var password string
	var server *ghttp.Server
	BeforeEach(func() {
		ctx = context.Background()
		server = ghttp.NewServer()
		key = "key123"
		username = "user"
		password = "pass"
		remoteConnector = teamvault.NewRemoteConnector(
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
	Context("Username", func() {
		var result teamvault.User
		JustBeforeEach(func() {
			result, err = remoteConnector.User(ctx, key)
		})
		BeforeEach(func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/key123/",
				func(resp http.ResponseWriter, req *http.Request) {
					argUsername, argPassword, ok := req.BasicAuth()
					Expect(ok).To(BeTrue())
					Expect(argUsername).To(Equal(username))
					Expect(argPassword).To(Equal(password))
					resp.WriteHeader(http.StatusOK)
					fmt.Fprintf(resp, `{"username":"myuser"}`)
				},
			)
			server.RouteToHandler(
				http.MethodGet,
				"/api/method/login",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
				},
			)
		})
		It("returns no error", func() {
			Expect(err).To(BeNil())
		})
		It("returns user", func() {
			Expect(result).NotTo(BeNil())
			Expect(result.String()).To(Equal("myuser"))
		})
	})
	Context("Username as number", func() {
		var result teamvault.User
		JustBeforeEach(func() {
			result, err = remoteConnector.User(ctx, key)
		})
		BeforeEach(func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/key123/",
				func(resp http.ResponseWriter, req *http.Request) {
					argUsername, argPassword, ok := req.BasicAuth()
					Expect(ok).To(BeTrue())
					Expect(argUsername).To(Equal(username))
					Expect(argPassword).To(Equal(password))
					resp.WriteHeader(http.StatusOK)
					fmt.Fprintf(resp, `{"username":9876}`)
				},
			)
			server.RouteToHandler(
				http.MethodGet,
				"/api/method/login",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
				},
			)
		})
		It("returns no error", func() {
			Expect(err).To(BeNil())
		})
		It("returns username as string", func() {
			Expect(result).NotTo(BeNil())
			Expect(result.String()).To(Equal("9876"))
		})
	})
	Context("Password", func() {
		var result teamvault.Password
		JustBeforeEach(func() {
			result, err = remoteConnector.Password(ctx, key)
		})
		BeforeEach(func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/key123/",
				func(resp http.ResponseWriter, req *http.Request) {
					argUsername, argPassword, ok := req.BasicAuth()
					Expect(ok).To(BeTrue())
					Expect(argUsername).To(Equal(username))
					Expect(argPassword).To(Equal(password))
					resp.WriteHeader(http.StatusOK)
					fmt.Fprintf(
						resp,
						`{"current_revision":"%s/api/secret-revisions/ref123/"}`,
						server.URL(),
					)
				},
			)
			server.RouteToHandler(
				http.MethodGet,
				"/api/secret-revisions/ref123/data",
				func(resp http.ResponseWriter, req *http.Request) {
					argUsername, argPassword, ok := req.BasicAuth()
					Expect(ok).To(BeTrue())
					Expect(argUsername).To(Equal(username))
					Expect(argPassword).To(Equal(password))
					resp.WriteHeader(http.StatusOK)
					fmt.Fprintf(resp, `{"password":"S3CR3T"}`)
				},
			)
			server.RouteToHandler(
				http.MethodGet,
				"/api/method/login",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
				},
			)
		})
		It("returns no error", func() {
			Expect(err).To(BeNil())
		})
		It("returns password", func() {
			Expect(result).NotTo(BeNil())
			Expect(result.String()).To(Equal("S3CR3T"))
		})
	})
	Context("Password as number", func() {
		var result teamvault.Password
		JustBeforeEach(func() {
			result, err = remoteConnector.Password(ctx, key)
		})
		BeforeEach(func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/key123/",
				func(resp http.ResponseWriter, req *http.Request) {
					argUsername, argPassword, ok := req.BasicAuth()
					Expect(ok).To(BeTrue())
					Expect(argUsername).To(Equal(username))
					Expect(argPassword).To(Equal(password))
					resp.WriteHeader(http.StatusOK)
					fmt.Fprintf(
						resp,
						`{"current_revision":"%s/api/secret-revisions/ref123/"}`,
						server.URL(),
					)
				},
			)
			server.RouteToHandler(
				http.MethodGet,
				"/api/secret-revisions/ref123/data",
				func(resp http.ResponseWriter, req *http.Request) {
					argUsername, argPassword, ok := req.BasicAuth()
					Expect(ok).To(BeTrue())
					Expect(argUsername).To(Equal(username))
					Expect(argPassword).To(Equal(password))
					resp.WriteHeader(http.StatusOK)
					fmt.Fprintf(resp, `{"password":5784}`)
				},
			)
			server.RouteToHandler(
				http.MethodGet,
				"/api/method/login",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
				},
			)
		})
		It("returns no error", func() {
			Expect(err).To(BeNil())
		})
		It("returns password as string", func() {
			Expect(result).NotTo(BeNil())
			Expect(result.String()).To(Equal("5784"))
		})
	})
	Context("Url", func() {
		var result teamvault.Url
		JustBeforeEach(func() {
			result, err = remoteConnector.Url(ctx, key)
		})
		BeforeEach(func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/key123/",
				func(resp http.ResponseWriter, req *http.Request) {
					argUsername, argPassword, ok := req.BasicAuth()
					Expect(ok).To(BeTrue())
					Expect(argUsername).To(Equal(username))
					Expect(argPassword).To(Equal(password))
					resp.WriteHeader(http.StatusOK)
					fmt.Fprintf(resp, `{"url":"http://my.example.com"}`)
				},
			)
			server.RouteToHandler(
				http.MethodGet,
				"/api/method/login",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
				},
			)
		})
		It("returns no error", func() {
			Expect(err).To(BeNil())
		})
		It("returns url", func() {
			Expect(result).NotTo(BeNil())
			Expect(result.String()).To(Equal("http://my.example.com"))
		})
	})
	Context("Search", func() {
		var result []teamvault.SearchResult
		JustBeforeEach(func() {
			result, err = remoteConnector.Search(ctx, "searchString")
		})
		BeforeEach(func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/",
				func(resp http.ResponseWriter, req *http.Request) {
					argUsername, argPassword, ok := req.BasicAuth()
					Expect(ok).To(BeTrue())
					Expect(argUsername).To(Equal(username))
					Expect(argPassword).To(Equal(password))
					Expect(req.FormValue("search")).To(Equal("searchString"))
					resp.WriteHeader(http.StatusOK)
					fmt.Fprintf(resp, `
					{
						"count": 1,
						"next": null,
						"previous": null,
						"results": [
							{
								"access_policy": "request",
								"allowed_groups": [],
								"allowed_users": [],
								"api_url": "https://teamvault.example.com/api/secrets/key123/",
								"content_type": "password",
								"created": "2017-08-21T12:29:53.252282Z",
								"created_by": "skegel",
								"current_revision": "https://teamvault.example.com/api/secret-revisions/rKp1x5/",
								"data_readable": [],
								"description": "",
								"filename": null,
								"hashid": "key123",
								"last_read": "2017-08-30T08:37:02.189161Z",
								"name": "SearchString",
								"needs_changing_on_leave": true,
								"status": "ok",
								"url": "https://example.com",
								"username": "foo",
								"web_url": "https://teamvault.example.com/secrets/key123"
							}
						]
					}
				`)
				},
			)
			server.RouteToHandler(
				http.MethodGet,
				"/api/method/login",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
				},
			)
		})
		It("returns no error", func() {
			Expect(err).To(BeNil())
		})
		It("returns the key", func() {
			Expect(result).To(HaveLen(1))
			Expect(result[0].Key).To(Equal(teamvault.Key("key123")))
		})
		It("returns the name", func() {
			Expect(result[0].Name).To(Equal("SearchString"))
		})
		It("returns the username", func() {
			Expect(result[0].Username).To(Equal("foo"))
		})
		It("returns the url", func() {
			Expect(result[0].Url).To(Equal(teamvault.Url("https://example.com")))
		})
	})

	Context("Search with a cross-host next link", func() {
		BeforeEach(func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
					// next points at a DIFFERENT host — the client must refuse to
					// follow it (the Basic-auth header would leak to that host).
					fmt.Fprint(
						resp,
						`{"count":2,"next":"https://evil.example.com/api/secrets/?page=2","previous":null,"results":[{"hashid":"key1","name":"one","username":"u","url":"https://example.com"}]}`,
					)
				},
			)
		})
		It("refuses to follow the cross-host next and errors", func() {
			_, searchErr := remoteConnector.Search(ctx, "searchString")
			Expect(searchErr).NotTo(BeNil())
			Expect(searchErr.Error()).To(ContainSubstring("different host"))
		})
	})

	Context("Search with an https-to-http downgrade next link", func() {
		It("refuses to follow the downgrade and errors", func() {
			// The ghttp fixtures are all http://, so baseParsed.Scheme is never
			// "https" there and this branch would go untested. A TLS fixture with a
			// same-host http:// next is the only way to reach it — and the cross-host
			// guard does NOT catch it, since the host and port match.
			tlsServer := httptest.NewTLSServer(http.HandlerFunc(
				func(resp http.ResponseWriter, req *http.Request) {
					resp.Header().Set("Content-Type", "application/json")
					//nolint:errcheck
					fmt.Fprintf(
						resp,
						`{"count":2,"next":"http://%s/api/secrets/?page=2","previous":null,"results":[{"hashid":"key1","name":"one","username":"u","url":"https://example.com"}]}`,
						req.Host,
					)
				},
			))
			defer tlsServer.Close()

			tlsConnector := teamvault.NewRemoteConnector(
				tlsServer.Client(),
				teamvault.Url(tlsServer.URL),
				teamvault.User("user"),
				teamvault.Password("pass"),
				libtime.NewCurrentDateTime(),
			)

			_, searchErr := tlsConnector.Search(ctx, "searchString")

			Expect(searchErr).NotTo(BeNil())
			Expect(searchErr.Error()).To(ContainSubstring("cleartext"))
		})
	})

	Context("Search following a relative next link", func() {
		BeforeEach(func() {
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
					if req.URL.Query().Get("page") == "2" {
						fmt.Fprint(
							resp,
							`{"count":2,"next":null,"previous":null,"results":[{"hashid":"key2","name":"two","username":"u2","url":"https://two.example"}]}`,
						)
						return
					}
					// next is RELATIVE (no scheme/host) — must resolve against the base and be followed.
					fmt.Fprint(
						resp,
						`{"count":2,"next":"/api/secrets/?search=searchString&page=2","previous":null,"results":[{"hashid":"key1","name":"one","username":"u1","url":"https://one.example"}]}`,
					)
				},
			)
		})
		It("resolves the relative next and returns all results", func() {
			result, searchErr := remoteConnector.Search(ctx, "searchString")
			Expect(searchErr).To(BeNil())
			Expect(result).To(HaveLen(2))
			Expect(result[0].Key).To(Equal(teamvault.Key("key1")))
			Expect(result[1].Key).To(Equal(teamvault.Key("key2")))
		})
	})

	Context("Search with pagination", func() {
		var result []teamvault.SearchResult
		JustBeforeEach(func() {
			result, err = remoteConnector.Search(ctx, "searchString")
		})
		BeforeEach(func() {
			// Page 1
			server.RouteToHandler(
				http.MethodGet,
				"/api/secrets/",
				func(resp http.ResponseWriter, req *http.Request) {
					argUsername, argPassword, ok := req.BasicAuth()
					Expect(ok).To(BeTrue())
					Expect(argUsername).To(Equal(username))
					Expect(argPassword).To(Equal(password))
					page := req.URL.Query().Get("page")
					if page == "" {
						// First request
						Expect(req.FormValue("search")).To(Equal("searchString"))
						resp.WriteHeader(http.StatusOK)
						fmt.Fprintf(resp, `{
							"count": 2,
							"next": %q,
							"previous": null,
							"results": [
								{
									"hashid": "key123",
									"name": "SearchString",
									"username": "foo",
									"url": "https://example.com"
								}
							]
						}`, fmt.Sprintf("%s/api/secrets/?search=searchString&page=2", server.URL()))
						return
					}
					if page == "2" {
						resp.WriteHeader(http.StatusOK)
						fmt.Fprintf(resp, `{
							"count": 2,
							"next": null,
							"previous": %q,
							"results": [
								{
									"hashid": "key456",
									"name": "OtherSecret",
									"username": "bar",
									"url": "https://other.example"
								}
							]
						}`, fmt.Sprintf("%s/api/secrets/?search=searchString", server.URL()))
						return
					}
					http.NotFound(resp, req)
				},
			)
			server.RouteToHandler(
				http.MethodGet,
				"/api/method/login",
				func(resp http.ResponseWriter, req *http.Request) {
					resp.WriteHeader(http.StatusOK)
				},
			)
		})
		It("returns no error", func() {
			Expect(err).To(BeNil())
		})
		It("returns results from both pages", func() {
			Expect(result).To(HaveLen(2))
		})
		It("returns the first key", func() {
			Expect(result[0].Key).To(Equal(teamvault.Key("key123")))
		})
		It("returns the second key", func() {
			Expect(result[1].Key).To(Equal(teamvault.Key("key456")))
		})
		It("returns names from both pages", func() {
			Expect(result[0].Name).To(Equal("SearchString"))
			Expect(result[1].Name).To(Equal("OtherSecret"))
		})
	})
})

var _ = Describe("RemoteConnector key escaping", func() {
	var ctx context.Context
	var connector teamvault.Connector
	var escapedPath string
	var rawQuery string
	var fragment string

	BeforeEach(func() {
		ctx = context.Background()
		escapedPath = ""
		rawQuery = ""
		fragment = ""
	})

	JustBeforeEach(func() {
		server := httptest.NewServer(
			http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
				escapedPath = req.URL.EscapedPath()
				rawQuery = req.URL.RawQuery
				fragment = req.URL.Fragment
				resp.Header().Set("Content-Type", "application/json")
				//nolint:errcheck
				fmt.Fprint(
					resp,
					`{"username":"user","url":"https://example.com","current_revision":"rev1"}`,
				)
			}),
		)
		DeferCleanup(server.Close)
		connector = teamvault.NewRemoteConnector(
			libhttp.CreateDefaultHttpClient(),
			teamvault.Url(server.URL),
			teamvault.User("user"),
			teamvault.Password("pass"),
			libtime.NewCurrentDateTime(),
		)
	})

	It("keeps a query delimiter inside the path", func() {
		_, err := connector.User(ctx, teamvault.Key("weird?key#frag"))
		Expect(err).NotTo(HaveOccurred())
		Expect(escapedPath).To(Equal("/api/secrets/weird%3Fkey%23frag/"))
		Expect(rawQuery).To(BeEmpty())
		Expect(fragment).To(BeEmpty())
	})

	It("keeps a slash inside one path segment", func() {
		_, err := connector.User(ctx, teamvault.Key("a/b"))
		Expect(err).NotTo(HaveOccurred())
		Expect(escapedPath).To(Equal("/api/secrets/a%2Fb/"))
	})
})
