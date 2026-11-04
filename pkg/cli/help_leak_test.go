// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli_test

import (
	"bytes"
	"context"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/Seibert-Data/teamvault-cli/v5/pkg/cli"
)

var _ = Describe("teamvault-pass resolution", func() {
	const sentinel = "secret-sentinel"

	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
		os.Unsetenv("TEAMVAULT_URL")
		os.Unsetenv("TEAMVAULT_USER")
		os.Unsetenv("TEAMVAULT_PASS")
		os.Unsetenv("TEAMVAULT_CONFIG")
		os.Setenv("TEAMVAULT_PASS", sentinel)
		DeferCleanup(func() {
			os.Unsetenv("TEAMVAULT_PASS")
		})
	})

	It("does not use the environment value as the flag default", func() {
		rootCmd := cli.NewRootCommand(ctx)
		Expect(rootCmd.PersistentFlags().Lookup("teamvault-pass").Value.String()).To(BeEmpty())
	})

	It("keeps the environment value out of the root --help", func() {
		rootCmd := cli.NewRootCommand(ctx)
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		rootCmd.SetErr(&out)
		rootCmd.SetArgs([]string{"--help"})
		_, _ = rootCmd.ExecuteC()
		Expect(out.String()).NotTo(ContainSubstring(sentinel))
	})

	It("keeps the environment value out of a subcommand --help", func() {
		rootCmd := cli.NewRootCommand(ctx)
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		rootCmd.SetErr(&out)
		rootCmd.SetArgs([]string{"password", "--help"})
		_, _ = rootCmd.ExecuteC()
		Expect(out.String()).NotTo(ContainSubstring(sentinel))
	})

	It("still resolves the environment value when the flag is not given", func() {
		rootCmd := cli.NewRootCommand(ctx)
		rootCmd.SetArgs([]string{"password", "somekey"})
		// Without a reachable server this fails — the point is that the pre-run
		// hook ran and copied the environment value into the flag.
		_ = rootCmd.Execute()
		Expect(rootCmd.PersistentFlags().Lookup("teamvault-pass").Value.String()).
			To(Equal(sentinel))
	})

	It("lets an explicit flag win over the environment", func() {
		rootCmd := cli.NewRootCommand(ctx)
		rootCmd.SetArgs([]string{"--teamvault-pass", "from-flag", "password", "somekey"})
		_ = rootCmd.Execute()
		Expect(rootCmd.PersistentFlags().Lookup("teamvault-pass").Value.String()).
			To(Equal("from-flag"))
	})
})
