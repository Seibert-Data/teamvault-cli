// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
	"github.com/Seibert-Data/teamvault-cli/v5/pkg/cli"
	"github.com/Seibert-Data/teamvault-cli/v5/pkg/mocks"
)

var _ = Describe("share", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
		os.Setenv("STAGING", "true")
		os.Unsetenv("TEAMVAULT_URL")
		os.Unsetenv("TEAMVAULT_USER")
		os.Unsetenv("TEAMVAULT_PASS")
		os.Unsetenv("TEAMVAULT_CONFIG")
		os.Unsetenv("TEAMVAULT_TIMEOUT")
	})

	AfterEach(func() {
		os.Unsetenv("STAGING")
	})

	// runWithSharer executes the root command with a mock sharer installed and
	// returns stdout plus the command's error.
	runWithSharer := func(
		mockSharer *mocks.Sharer,
		args []string,
		stdin string,
	) (string, error) {
		var outBuf bytes.Buffer
		cmd := cli.NewRootCommand(ctx)
		cmd.SetArgs(args)
		cmd.SetOut(&outBuf)
		cmd.SetErr(&bytes.Buffer{})
		if stdin != "" {
			cmd.SetIn(strings.NewReader(stdin))
		}
		cli.SetNewSharerForTest(
			func(sf *cli.SharedFlags) func(context.Context) (teamvault.Sharer, error) {
				return func(ctx context.Context) (teamvault.Sharer, error) {
					return mockSharer, nil
				}
			},
		)
		defer cli.ResetNewSharerForTest()
		err := cmd.Execute()
		return outBuf.String(), err
	}

	Describe("command registration", func() {
		It("NewRootCommand includes the share and shares subcommands", func() {
			rootCmd := cli.NewRootCommand(ctx)
			subNames := make([]string, len(rootCmd.Commands()))
			for i, c := range rootCmd.Commands() {
				subNames[i] = c.Name()
			}
			Expect(subNames).To(ContainElement("share"))
			Expect(subNames).To(ContainElement("shares"))
		})
	})

	Describe("validation", func() {
		It("refuses a request with neither --user nor --group", func() {
			_, err := runWithSharer(
				&mocks.Sharer{},
				[]string{"share", "AbC123", "--description", "why"},
				"",
			)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("only one should be valid"))
		})

		It("refuses a request with both --user and --group", func() {
			_, err := runWithSharer(
				&mocks.Sharer{},
				[]string{
					"share", "AbC123",
					"--user", "alice", "--group", "ops",
					"--description", "why",
				},
				"",
			)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("only one should be valid"))
		})

		It("refuses a request without --description", func() {
			_, err := runWithSharer(
				&mocks.Sharer{},
				[]string{"share", "AbC123", "--user", "alice"},
				"",
			)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("grant description"))
		})

		It("refuses a request with no key at all", func() {
			_, err := runWithSharer(
				&mocks.Sharer{},
				[]string{"share", "--user", "alice", "--description", "why"},
				"",
			)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("at least one key is required"))
		})
	})

	Describe("per-key result lines", func() {
		It("prints shared, already-shared and refused, and exits non-zero", func() {
			mockSharer := &mocks.Sharer{}
			mockSharer.ShareReturnsOnCall(
				0,
				teamvault.ShareResult{Outcome: teamvault.ShareCreated},
				nil,
			)
			mockSharer.ShareReturnsOnCall(
				1,
				teamvault.ShareResult{Outcome: teamvault.ShareAlreadyExists},
				nil,
			)
			mockSharer.ShareReturnsOnCall(
				2,
				teamvault.ShareResult{},
				&teamvault.ShareError{
					Key:        teamvault.Key("ZZZZZZ"),
					StatusCode: 404,
					Detail:     `{"detail":"Not found."}`,
				},
			)

			out, err := runWithSharer(
				mockSharer,
				[]string{
					"share", "AbC123", "AbC456", "ZZZZZZ",
					"--user", "nuke-apply-dev",
					"--description", "deploy reads",
				},
				"",
			)

			lines := strings.Split(strings.TrimSpace(out), "\n")
			Expect(lines).To(Equal([]string{
				"AbC123 shared",
				"AbC456 already-shared",
				`ZZZZZZ refused (404: {"detail":"Not found."})`,
			}))
			// A refused key must fail the command, so a script cannot read a
			// partial success as a success.
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("1 of 3 keys refused"))
		})

		It("exits zero when every key is shared or already shared", func() {
			mockSharer := &mocks.Sharer{}
			mockSharer.ShareReturns(
				teamvault.ShareResult{Outcome: teamvault.ShareAlreadyExists},
				nil,
			)

			out, err := runWithSharer(
				mockSharer,
				[]string{"share", "AbC123", "--user", "u", "--description", "d"},
				"",
			)

			Expect(err).To(BeNil())
			Expect(strings.TrimSpace(out)).To(Equal("AbC123 already-shared"))
		})

		It("reports a non-ShareError failure without losing it", func() {
			mockSharer := &mocks.Sharer{}
			mockSharer.ShareReturns(teamvault.ShareResult{}, errors.New("connection reset"))

			out, err := runWithSharer(
				mockSharer,
				[]string{"share", "AbC123", "--user", "u", "--description", "d"},
				"",
			)

			Expect(err).NotTo(BeNil())
			Expect(out).To(ContainSubstring("AbC123 refused (error: connection reset)"))
		})
	})

	Describe("key sources", func() {
		It("accepts repeated --teamvault-key", func() {
			mockSharer := &mocks.Sharer{}
			mockSharer.ShareReturns(teamvault.ShareResult{Outcome: teamvault.ShareCreated}, nil)

			out, err := runWithSharer(
				mockSharer,
				[]string{
					"share",
					"--teamvault-key", "AbC123",
					"--teamvault-key", "AbC456",
					"--user", "u", "--description", "d",
				},
				"",
			)

			Expect(err).To(BeNil())
			Expect(strings.Split(strings.TrimSpace(out), "\n")).To(HaveLen(2))
			Expect(mockSharer.ShareCallCount()).To(Equal(2))
		})

		It("reads one key per line from stdin when - is given", func() {
			mockSharer := &mocks.Sharer{}
			mockSharer.ShareReturns(teamvault.ShareResult{Outcome: teamvault.ShareCreated}, nil)

			out, err := runWithSharer(
				mockSharer,
				[]string{"share", "-", "--user", "u", "--description", "d"},
				"AbC123\nAbC456\n\nAbC789\n",
			)

			Expect(err).To(BeNil())
			Expect(strings.Split(strings.TrimSpace(out), "\n")).To(HaveLen(3))
		})

		It("does not report a duplicated key twice", func() {
			mockSharer := &mocks.Sharer{}
			mockSharer.ShareReturns(teamvault.ShareResult{Outcome: teamvault.ShareCreated}, nil)

			out, err := runWithSharer(
				mockSharer,
				[]string{
					"share", "AbC123",
					"--teamvault-key", "AbC123",
					"--user", "u", "--description", "d",
				},
				"",
			)

			Expect(err).To(BeNil())
			Expect(strings.Split(strings.TrimSpace(out), "\n")).To(HaveLen(1))
		})
	})

	Describe("group grants", func() {
		It("sends the group on the single invocation and prints shared", func() {
			mockSharer := &mocks.Sharer{}
			mockSharer.ShareReturns(teamvault.ShareResult{Outcome: teamvault.ShareCreated}, nil)

			out, err := runWithSharer(
				mockSharer,
				[]string{"share", "AbC123", "--group", "ops", "--description", "ops reads"},
				"",
			)

			Expect(err).To(BeNil())
			Expect(strings.TrimSpace(out)).To(Equal("AbC123 shared"))
			Expect(mockSharer.ShareCallCount()).To(Equal(1))
			_, key, request := mockSharer.ShareArgsForCall(0)
			Expect(key).To(Equal(teamvault.Key("AbC123")))
			Expect(request.Group).To(Equal("ops"))
			Expect(request.User).To(BeEmpty())
			Expect(request.GrantDescription).To(Equal("ops reads"))
		})
	})

	Describe("shares", func() {
		It("lists user, group, description, granted_by and granted_until", func() {
			userName := "nuke-apply-dev"
			groupName := "ops"
			until := "2027-01-01T00:00:00Z"
			bborbeName := "bborbe"
			mockSharer := &mocks.Sharer{}
			mockSharer.SharesReturns([]teamvault.Share{
				{
					ID:               1,
					GrantDescription: "deploy reads",
					User:             &userName,
					GrantedBy:        &bborbeName,
				},
				{
					ID:               2,
					GrantDescription: "ops reads",
					Group:            &groupName,
					GrantedBy:        &bborbeName,
					GrantedUntil:     &until,
				},
			}, nil)

			out, err := runWithSharer(mockSharer, []string{"shares", "AbC123"}, "")

			Expect(err).To(BeNil())
			Expect(out).To(ContainSubstring("DESCRIPTION"))
			Expect(out).To(ContainSubstring("nuke-apply-dev"))
			Expect(out).To(ContainSubstring("ops"))
			Expect(out).To(ContainSubstring("deploy reads"))
			Expect(out).To(ContainSubstring("bborbe"))
			Expect(out).To(ContainSubstring("2027-01-01T00:00:00Z"))
		})

		It("emits JSON with --json and never the server's secret field", func() {
			userName := "nuke-apply-dev"
			secretName := "AbC123"
			bborbeName := "bborbe"
			mockSharer := &mocks.Sharer{}
			mockSharer.SharesReturns([]teamvault.Share{
				{
					ID:               1,
					GrantDescription: "deploy reads",
					User:             &userName,
					GrantedBy:        &bborbeName,
					Secret:           secretName,
				},
			}, nil)

			out, err := runWithSharer(mockSharer, []string{"shares", "AbC123", "--json"}, "")

			Expect(err).To(BeNil())
			// The projection drops the server's `secret` hashid: the caller already
			// passed the key, and a JSON field named "secret" invites the reader (and
			// a scanner) to think a secret value is being emitted.
			Expect(out).NotTo(ContainSubstring(`"secret"`))
			Expect(out).To(ContainSubstring(`"grant_description":"deploy reads"`))
			Expect(out).To(ContainSubstring(`"granted_by":"bborbe"`))
		})

		It("says so plainly when the secret has no shares", func() {
			mockSharer := &mocks.Sharer{}
			mockSharer.SharesReturns(nil, nil)

			out, err := runWithSharer(mockSharer, []string{"shares", "AbC123"}, "")

			Expect(err).To(BeNil())
			Expect(strings.TrimSpace(out)).To(Equal("AbC123 has no shares"))
		})

		It("returns the sharer's error", func() {
			mockSharer := &mocks.Sharer{}
			mockSharer.SharesReturns(nil, &teamvault.ShareError{
				Key:        teamvault.Key("AbC123"),
				StatusCode: 403,
				Detail:     "denied",
			})

			_, err := runWithSharer(mockSharer, []string{"shares", "AbC123"}, "")

			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("denied"))
		})
	})
})
