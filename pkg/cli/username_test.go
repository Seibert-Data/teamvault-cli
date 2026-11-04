// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli_test

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/Seibert-Data/teamvault-cli/v5/pkg/cli"
)

var _ = Describe("username validation", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
		os.Unsetenv("TEAMVAULT_URL")
		os.Unsetenv("TEAMVAULT_USER")
		os.Unsetenv("TEAMVAULT_PASS")
		os.Unsetenv("TEAMVAULT_CONFIG")
	})

	DescribeTable(
		"create refuses a username that would break the htpasswd line",
		func(username, expectedFragment string) {
			rootCmd := cli.NewRootCommand(ctx)
			rootCmd.SetArgs([]string{
				"create", "--name", "probe", "--username", username, "--generate",
			})
			err := rootCmd.Execute()
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring(expectedFragment))
		},
		Entry("newline", "a\nb", `'\n'`),
		Entry("carriage return", "a\rb", `'\r'`),
		Entry("tab", "a\tb", `'\t'`),
		Entry("colon", "a:b", "field separator"),
		// Apache skips surrounding whitespace, so a stored " admin" would
		// authenticate as "admin".
		Entry("leading space", " admin", "whitespace"),
		Entry("trailing space", "admin ", "whitespace"),
		Entry("whitespace only", "   ", "whitespace"),
	)

	DescribeTable(
		"update refuses a username that would break the htpasswd line",
		func(username, expectedFragment string) {
			rootCmd := cli.NewRootCommand(ctx)
			rootCmd.SetArgs([]string{"update", "somekey", "--username", username})
			err := rootCmd.Execute()
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring(expectedFragment))
		},
		Entry("newline", "a\nb", `'\n'`),
		Entry("carriage return", "a\rb", `'\r'`),
		Entry("tab", "a\tb", `'\t'`),
		Entry("colon", "a:b", "field separator"),
		Entry("leading space", " admin", "whitespace"),
	)

	It("lets a plain username past validation", func() {
		rootCmd := cli.NewRootCommand(ctx)
		rootCmd.SetArgs([]string{
			"create", "--name", "probe", "--username", "alice", "--generate",
		})
		// Without a reachable server this still fails — but never on the username.
		err := rootCmd.Execute()
		Expect(err).To(Or(BeNil(), MatchError(Not(ContainSubstring("must not")))))
	})
})
