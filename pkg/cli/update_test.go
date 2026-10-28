// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
	"github.com/Seibert-Data/teamvault-cli/v5/pkg/cli"
	"github.com/Seibert-Data/teamvault-cli/v5/pkg/mocks"
)

var _ = Describe("update", func() {
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

	Describe("command registration", func() {
		It("NewRootCommand includes the update subcommand", func() {
			rootCmd := cli.NewRootCommand(ctx)
			subNames := make([]string, len(rootCmd.Commands()))
			for i, c := range rootCmd.Commands() {
				subNames[i] = c.Name()
			}
			Expect(subNames).To(ContainElement("update"))
		})

		It("update --help shows 'update <key>'", func() {
			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "--help"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})
			_, _ = cmd.ExecuteC()
			output := outBuf.String()
			Expect(output).To(ContainSubstring("update <key>"))
		})
	})

	Describe("positional key", func() {
		It("passes the key from args[0] to writer.Update", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.UpdateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "mykey", "--description", "new desc"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			_, key, _ := mockWriter.UpdateArgsForCall(0)
			Expect(string(key)).To(Equal("mykey"))
		})
	})

	Describe("metadata-only update omits secret_data", func() {
		It(
			"sends only Description, no Password or FileContent, when only --description is passed",
			func() {
				mockWriter := &mocks.Writer{}
				mockWriter.UpdateReturns(
					teamvault.Key("K"),
					teamvault.ApiUrl("http://h/api/secrets/K/"),
					nil,
				)

				var outBuf bytes.Buffer
				cmd := cli.NewRootCommand(ctx)
				cmd.SetArgs([]string{"update", "K", "--description", "new desc"})
				cmd.SetOut(&outBuf)
				cmd.SetErr(&bytes.Buffer{})

				cli.SetNewWriterForTest(
					func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
						return func(ctx context.Context) (teamvault.Writer, error) {
							return mockWriter, nil
						}
					},
				)
				defer cli.ResetNewWriterForTest()

				_ = cmd.Execute()
				_, _, secret := mockWriter.UpdateArgsForCall(0)
				Expect(secret.Description).NotTo(BeNil())
				Expect(*secret.Description).To(Equal("new desc"))
				Expect(secret.Password).To(BeNil())
				Expect(secret.FileContent).To(BeNil())
			},
		)

		It("sends only Name when only --name is passed", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.UpdateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "K", "--name", "newname"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			_, _, secret := mockWriter.UpdateArgsForCall(0)
			Expect(secret.Name).NotTo(BeNil())
			Expect(*secret.Name).To(Equal("newname"))
			Expect(secret.Password).To(BeNil())
		})
	})

	Describe("value-source mutual exclusion", func() {
		It("returns an error when multiple value sources are provided", func() {
			var errBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "K", "--generate", "--password", "p"})
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&errBuf)
			err := cmd.Execute()
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("mutually exclusive"))
		})

		It("allows zero value sources (metadata-only)", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.UpdateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "K", "--description", "d"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			err := cmd.Execute()
			Expect(err).To(BeNil())
		})
	})

	Describe("--password-stdin", func() {
		It("reads password from stdin for update", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.UpdateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "K", "--password-stdin"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetIn(strings.NewReader("new-pw\n"))

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			_, _, secret := mockWriter.UpdateArgsForCall(0)
			Expect(secret.Password).NotTo(BeNil())
			Expect(string(*secret.Password)).To(Equal("new-pw"))
		})

		It("rejects empty stdin for update", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.UpdateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var errBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "K", "--password-stdin"})
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&errBuf)
			cmd.SetIn(strings.NewReader(""))

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			err := cmd.Execute()
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("empty"))
		})
	})

	Describe("output", func() {
		It("prints the bare key with no trailing newline by default", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.UpdateReturns(
				teamvault.Key("UPDKEY"),
				teamvault.ApiUrl("http://h/api/secrets/UPDKEY/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "K", "--name", "n"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			Expect(outBuf.String()).To(Equal("UPDKEY"))
			Expect(outBuf.String()).ToNot(HaveSuffix("\n"))
		})

		It("prints JSON with --json", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.UpdateReturns(
				teamvault.Key("UPDKEY"),
				teamvault.ApiUrl("http://h/api/secrets/UPDKEY/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "K", "--name", "n", "--json"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			output := strings.TrimSpace(outBuf.String())
			Expect(output).To(ContainSubstring(`"key":"UPDKEY"`))
			Expect(output).To(ContainSubstring(`"api_url"`))
		})
	})

	Describe("--file", func() {
		It("passes FileContent to writer.Update", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.UpdateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			tmpFile, err := os.CreateTemp("", "testfile")
			Expect(err).To(BeNil())
			defer os.Remove(tmpFile.Name())
			_, err = tmpFile.Write([]byte("file-content"))
			Expect(err).To(BeNil())
			tmpFile.Close()

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "K", "--file", tmpFile.Name()})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			_, _, secret := mockWriter.UpdateArgsForCall(0)
			Expect(secret.FileContent).To(Equal([]byte("file-content")))
			Expect(secret.Password).To(BeNil())
			// Same shape as create: the server rejects a file update without a
			// top-level filename.
			Expect(secret.Filename).To(Equal(filepath.Base(tmpFile.Name())))
		})
	})

	Describe("--generate", func() {
		It("calls GeneratePassword and passes result to Update", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.GeneratePasswordReturns(teamvault.Password("gen-pw"), nil)
			mockWriter.UpdateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "K", "--generate"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			_, _, secret := mockWriter.UpdateArgsForCall(0)
			Expect(secret.Password).NotTo(BeNil())
			Expect(string(*secret.Password)).To(Equal("gen-pw"))
		})
	})

	Describe("--password literal", func() {
		It("passes literal password to Update", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.UpdateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"update", "K", "--password", "literal-pw"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			_, _, secret := mockWriter.UpdateArgsForCall(0)
			Expect(secret.Password).NotTo(BeNil())
			Expect(string(*secret.Password)).To(Equal("literal-pw"))
		})
	})

	Describe("metadata flags", func() {
		It("sends username and url when passed", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.UpdateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs(
				[]string{"update", "K", "--username", "alice", "--url", "https://example.com"},
			)
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			_, _, secret := mockWriter.UpdateArgsForCall(0)
			Expect(secret.Username).NotTo(BeNil())
			Expect(*secret.Username).To(Equal("alice"))
			Expect(secret.Url).NotTo(BeNil())
			Expect(*secret.Url).To(Equal("https://example.com"))
		})
	})
})
