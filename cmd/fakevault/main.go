// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command fakevault is a minimal fake TeamVault HTTP server for hermetic,
// CI-runnable end-to-end tests of teamvault-cli. It implements the read
// endpoints the remote connector calls (see pkg/remote-connector.go) plus the
// write + search endpoints the remote writer / search command call (see
// pkg/remote-writer.go), all backed by an in-memory, mutex-guarded store
// seeded from a fixed fixture set. It is a test helper and is never shipped
// (goreleaser builds the root `main: .` only).
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// secret is one entry served by the fake — either a seeded fixture or a
// secret created/updated at runtime via the write endpoints.
type secret struct {
	ContentType string
	Name        string
	Username    string
	URL         string
	Description string
	Password    string
	File        string
}

// store is the in-memory, mutex-guarded secret set. It starts out seeded with
// the fixed fixtures below; POST /api/secrets/ adds entries and
// PATCH /api/secrets/{key}/ mutates them, so a created secret can be read
// back, searched, and updated within the same server lifetime.
type store struct {
	mu   sync.Mutex
	data map[string]secret
}

func newStore() *store {
	return &store{
		data: map[string]secret{
			"demo": {
				ContentType: "password",
				Name:        "demo",
				Username:    "demo-user",
				URL:         "https://demo.example/login",
				Password:    "demo-pass-123",
				File:        "demo-file-contents",
			},
			"AbC123": {
				ContentType: "password",
				Name:        "AbC123",
				Username:    "alice",
				URL:         "https://api.internal",
				Password:    "s3cr3t-value",
				File:        "certificate-bytes",
			},
			// Poisoned-username fixtures for the htpasswd render path. A seed
			// bypasses CLI validation, so these stay readable even after the
			// write-side check rejects such usernames.
			"newline-user": {
				ContentType: "password",
				Name:        "newline-user",
				Username:    "admin\nattacker",
				Password:    "newline-pass",
			},
			"blank-user": {
				ContentType: "password",
				Name:        "blank-user",
				Username:    "\n\n",
				Password:    "blank-pass",
			},
			"colon-user": {
				ContentType: "password",
				Name:        "colon-user",
				Username:    "evil:garbage",
				Password:    "colon-pass",
			},
		},
	}
}

func (s *store) get(key string) (secret, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	return v, ok
}

func (s *store) put(key string, v secret) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = v
}

// update atomically applies fn to the secret at key, holding the lock across the
// whole read-modify-write so concurrent updates to the same key can't lose each
// other's changes. Returns false (and does not call fn) if the key is absent.
func (s *store) update(key string, fn func(secret) secret) (secret, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return secret{}, false
	}
	v = fn(v)
	s.data[key] = v
	return v, true
}

// search returns keys of secrets whose key or username contains q
// (case-sensitive substring match, mirroring the pre-write fixture behavior).
func (s *store) search(q string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.data))
	for key, v := range s.data {
		if q == "" || strings.Contains(key, q) || strings.Contains(v.Username, q) ||
			strings.Contains(v.Name, q) {
			keys = append(keys, key)
		}
	}
	return keys
}

// wantUser / wantPass are the Basic-auth credentials the server accepts (set
// via flags). A request with any other credential gets 401 — so tests can
// exercise the CLI's auth-failure path.
var (
	wantUser = "test"
	wantPass = "test"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address (use :0 for an OS-assigned port)")
	flag.StringVar(&wantUser, "user", "test", "required Basic-auth username")
	flag.StringVar(&wantPass, "pass", "test", "required Basic-auth password")
	flag.Parse()

	st := newStore()
	mux := http.NewServeMux()

	// GET /api/secrets/{key}/ — secret metadata (username, url, current_revision).
	mux.HandleFunc("GET /api/secrets/{key}/", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		s, ok := st.get(r.PathValue("key"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{
			"username": s.Username,
			"url":      s.URL,
			"current_revision": fmt.Sprintf(
				"http://%s/api/secret-revisions/%s/",
				r.Host,
				r.PathValue("key"),
			),
		})
	})

	// PATCH /api/secrets/{key}/ — partial update of metadata and/or secret_data.
	// content_type is immutable and never read from the request body.
	mux.HandleFunc("PATCH /api/secrets/{key}/", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		key := r.PathValue("key")

		var req struct {
			Name        *string           `json:"name"`
			Username    *string           `json:"username"`
			Url         *string           `json:"url"`
			Description *string           `json:"description"`
			SecretData  map[string]string `json:"secret_data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "decode request failed", http.StatusBadRequest)
			return
		}
		// Read-modify-write under a single lock so concurrent PATCHes can't lose
		// updates. secret_data keys absent from the body leave the value untouched.
		_, ok := st.update(key, func(s secret) secret {
			if req.Name != nil {
				s.Name = *req.Name
			}
			if req.Username != nil {
				s.Username = *req.Username
			}
			if req.Url != nil {
				s.URL = *req.Url
			}
			if req.Description != nil {
				s.Description = *req.Description
			}
			if pw, ok := req.SecretData["password"]; ok {
				s.Password = pw
			}
			if fc, ok := req.SecretData["file_content"]; ok {
				s.File = fc
			}
			return s
		})
		if !ok {
			http.NotFound(w, r)
			return
		}

		writeJSON(w, map[string]any{
			"api_url": fmt.Sprintf("http://%s/api/secrets/%s/", r.Host, key),
		})
	})

	// GET /api/secret-revisions/{key}/data — revision data (password, file).
	mux.HandleFunc(
		"GET /api/secret-revisions/{key}/data",
		func(w http.ResponseWriter, r *http.Request) {
			if !authOK(w, r) {
				return
			}
			s, ok := st.get(r.PathValue("key"))
			if !ok {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, map[string]any{"password": s.Password, "file": s.File})
		},
	)

	// POST /api/secrets/ — create a new secret, returns {"api_url": "..."}.
	// GET  /api/secrets/?search=q — search (login probe + search command).
	mux.HandleFunc("/api/secrets/", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		switch r.Method {
		case http.MethodGet:
			q := r.URL.Query().Get("search")
			keys := st.search(q)
			results := make([]map[string]any, 0, len(keys))
			for _, key := range keys {
				s, _ := st.get(key)
				results = append(results, map[string]any{
					"hashid":   key,
					"name":     s.Name,
					"username": s.Username,
					"url":      s.URL,
					"api_url":  fmt.Sprintf("http://%s/api/secrets/%s/", r.Host, key),
				})
			}
			writeJSON(
				w,
				map[string]any{
					"count":    len(results),
					"next":     nil,
					"previous": nil,
					"results":  results,
				},
			)

		case http.MethodPost:
			var req struct {
				ContentType string            `json:"content_type"`
				Name        string            `json:"name"`
				Username    string            `json:"username"`
				Url         string            `json:"url"`
				Description string            `json:"description"`
				SecretData  map[string]string `json:"secret_data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "decode request failed", http.StatusBadRequest)
				return
			}
			key := genKey()
			st.put(key, secret{
				ContentType: req.ContentType,
				Name:        req.Name,
				Username:    req.Username,
				URL:         req.Url,
				Description: req.Description,
				Password:    req.SecretData["password"],
				File:        req.SecretData["file_content"],
			})
			writeJSON(w, map[string]any{
				"api_url": fmt.Sprintf("http://%s/api/secrets/%s/", r.Host, key),
			})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("fakevault: listen %s: %v", *addr, err)
	}
	fmt.Printf("fakevault listening on http://%s\n", ln.Addr())
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Fatal(srv.Serve(ln))
}

// authOK requires the configured Basic-auth credential so tests can exercise
// both the happy path (correct creds) and the CLI's auth-failure path (wrong
// creds → 401). It writes 401 and returns false on any mismatch.
func authOK(w http.ResponseWriter, r *http.Request) bool {
	if user, pass, ok := r.BasicAuth(); ok && user == wantUser && pass == wantPass {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="fakevault"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("fakevault: encode: %v", err)
	}
}

// keyAlphabet is deliberately alphanumeric-only, matching the shape of real
// TeamVault hashids well enough for the CLI's api_url parsing (Key.Validate
// only rejects empty keys, so the exact alphabet is not load-bearing).
const keyAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// genKey generates a short random key for a newly created secret, using
// crypto/rand so the fake never depends on wall-clock time.
func genKey() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("fakevault: generate key: %v", err)
	}
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = keyAlphabet[int(c)%len(keyAlphabet)]
	}
	return string(out)
}
