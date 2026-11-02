// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"

	"github.com/Seibert-Data/teamvault-cli/v5/pkg/cli"
)

// resolveCredentials decides which account a write command acts as. It is not
// exported, so these specs pin it through the `create` command, which is the
// thinnest public surface that builds a writer: whatever Basic-auth username the
// fake server receives IS the resolved credential.
//
// The precedence is per-field, not one global order — config overrides url/user
// unconditionally, but password only when the flag left it empty. That asymmetry
// is what let a malformed config hand the privileged share command the wrong
// account, so it is pinned here rather than left to the doc comment.
var _ = Describe("credential resolution", func() {
	var ctx context.Context
	var server *ghttp.Server
	var receivedUser string
	var receivedPass string

	BeforeEach(func() {
		ctx = context.Background()
		server = ghttp.NewServer()
		receivedUser, receivedPass = "", ""

		server.RouteToHandler(
			http.MethodPost,
			"/api/secrets/",
			func(resp http.ResponseWriter, req *http.Request) {
				receivedUser, receivedPass, _ = req.BasicAuth()
				resp.WriteHeader(http.StatusCreated)
				//nolint:errcheck
				fmt.Fprintf(resp, `{"api_url": "%s/api/secrets/AbC123/"}`, server.URL())
			},
		)

		os.Unsetenv("TEAMVAULT_URL")
		os.Unsetenv("TEAMVAULT_USER")
		os.Unsetenv("TEAMVAULT_PASS")
		os.Unsetenv("TEAMVAULT_CONFIG")
		os.Unsetenv("TEAMVAULT_TIMEOUT")
	})

	AfterEach(func() {
		server.Close()
		os.Unsetenv("TEAMVAULT_URL")
		os.Unsetenv("TEAMVAULT_USER")
		os.Unsetenv("TEAMVAULT_PASS")
		os.Unsetenv("TEAMVAULT_CONFIG")
	})

	// writeConfig writes a config file using the real key names — `pass`, not
	// `password`, which the unmarshal drops silently.
	writeConfig := func(url, user, pass string) string {
		path := filepath.Join(GinkgoT().TempDir(), "config.json")
		Expect(os.WriteFile(path, []byte(fmt.Sprintf(
			`{"url":%q,"user":%q,"pass":%q}`, url, user, pass,
		)), 0o600)).To(Succeed())
		return path
	}

	// noConfig is a path that does not exist, passed explicitly so a spec is not
	// silently driven by the operator's real ~/.config/teamvault-cli/config.json —
	// which, being present, would overwrite url and user and make every spec below
	// assert the wrong thing. (That is not hypothetical: these specs failed on the
	// first run for exactly this reason, which is the hazard they pin.)
	noConfig := func() string {
		return filepath.Join(GinkgoT().TempDir(), "absent.json")
	}

	runCreate := func(args ...string) {
		cmd := cli.NewRootCommand(ctx)
		cmd.SetArgs(append(
			[]string{"create", "--name", "x", "--password", "pw"},
			append([]string{"--teamvault-config", noConfig()}, args...)...,
		))
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		// The writer seam is deliberately NOT overridden: the point of these specs
		// is the real builder.
		_ = cmd.Execute()
	}

	It("uses the flags when nothing else is set", func() {
		runCreate(
			"--teamvault-url", server.URL(),
			"--teamvault-user", "flaguser",
			"--teamvault-pass", "flagpass",
		)
		Expect(receivedUser).To(Equal("flaguser"))
		Expect(receivedPass).To(Equal("flagpass"))
	})

	It("uses the environment when no flag is set", func() {
		os.Setenv("TEAMVAULT_URL", server.URL())
		os.Setenv("TEAMVAULT_USER", "envuser")
		os.Setenv("TEAMVAULT_PASS", "envpass")

		runCreate()
		Expect(receivedUser).To(Equal("envuser"))
		Expect(receivedPass).To(Equal("envpass"))
	})

	It("lets the config file overwrite url and user given on the flag", func() {
		// The asymmetry that matters: a config file wins over an explicit flag for
		// url and user. A per-stage apply user that ships a shared config file is
		// silently re-pointed at whatever account that file names.
		cfg := writeConfig(server.URL(), "cfguser", "cfgpass")

		runCreate(
			"--teamvault-config", cfg,
			"--teamvault-user", "flaguser",
			"--teamvault-pass", "flagpass",
		)
		Expect(receivedUser).To(Equal("cfguser"))
		// Password is the exception: the flag wins, the config only fills a gap.
		Expect(receivedPass).To(Equal("flagpass"))
	})

	It("falls back to the config password when no flag password is given", func() {
		cfg := writeConfig(server.URL(), "cfguser", "cfgpass")

		runCreate("--teamvault-config", cfg)
		Expect(receivedUser).To(Equal("cfguser"))
		Expect(receivedPass).To(Equal("cfgpass"))
	})

	It("fails before any request when no url can be resolved", func() {
		cmd := cli.NewRootCommand(ctx)
		cmd.SetArgs([]string{
			"create", "--name", "x", "--password", "pw",
			"--teamvault-config", noConfig(),
		})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})

		err := cmd.Execute()

		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(ContainSubstring("teamvault URL is required"))
		Expect(server.ReceivedRequests()).To(BeEmpty())
	})
})
