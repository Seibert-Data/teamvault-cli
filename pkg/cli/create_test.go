// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli_test

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
	"github.com/Seibert-Data/teamvault-cli/v5/pkg/cli"
	"github.com/Seibert-Data/teamvault-cli/v5/pkg/mocks"
)

var _ = Describe("create", func() {
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
		It("NewRootCommand includes the create subcommand", func() {
			rootCmd := cli.NewRootCommand(ctx)
			subNames := make([]string, len(rootCmd.Commands()))
			for i, c := range rootCmd.Commands() {
				subNames[i] = c.Name()
			}
			Expect(subNames).To(ContainElement("create"))
		})

		It("create --help shows the --password leak warning", func() {
			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--help"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})
			_, _ = cmd.ExecuteC()
			output := outBuf.String()
			Expect(output).To(ContainSubstring("--password"))
			Expect(strings.ToLower(output)).To(SatisfyAny(
				ContainSubstring("history"),
				ContainSubstring("ps"),
			))
		})
	})

	Describe("value-source validation", func() {
		It("returns an error when no value source is provided", func() {
			var errBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--name", "x"})
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&errBuf)
			err := cmd.Execute()
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("--password-stdin"))
		})

		It("returns an error when multiple value sources are provided", func() {
			var errBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--name", "x", "--generate", "--password", "p"})
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&errBuf)
			err := cmd.Execute()
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("mutually exclusive"))
		})
	})

	Describe("content-type inference", func() {
		It("sets ContentTypePassword when --password is given", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.CreateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--name", "x", "--password", "pw"})
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
			Expect(mockWriter.CreateCallCount()).To(BeNumerically(">=", 1))
			_, secret := mockWriter.CreateArgsForCall(0)
			Expect(secret.ContentType).To(Equal(teamvault.ContentTypePassword))
		})

		It("sets ContentTypePassword when --generate is given", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.GeneratePasswordReturns(teamvault.Password("gen-pw"), nil)
			mockWriter.CreateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--name", "x", "--generate"})
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
			_, secret := mockWriter.CreateArgsForCall(0)
			Expect(secret.ContentType).To(Equal(teamvault.ContentTypePassword))
		})

		It("sets ContentTypePassword when --password-stdin is given", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.CreateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--name", "x", "--password-stdin"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetIn(strings.NewReader("stdin-pw\n"))

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			_, secret := mockWriter.CreateArgsForCall(0)
			Expect(secret.ContentType).To(Equal(teamvault.ContentTypePassword))
			Expect(secret.Password).To(Equal(teamvault.Password("stdin-pw")))
		})

		It("sets ContentTypeFile when --file is given", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.CreateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			tmpFile, err := os.CreateTemp("", "testfile")
			Expect(err).To(BeNil())
			defer os.Remove(tmpFile.Name())
			_, err = tmpFile.Write([]byte("hello world"))
			Expect(err).To(BeNil())
			tmpFile.Close()

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--name", "x", "--file", tmpFile.Name()})
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
			_, secret := mockWriter.CreateArgsForCall(0)
			Expect(secret.ContentType).To(Equal(teamvault.ContentTypeFile))
			Expect(secret.FileContent).To(Equal([]byte("hello world")))
		})
	})

	Describe("--password-stdin", func() {
		It("reads password from stdin, not argv", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.CreateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--name", "x", "--password-stdin"})
			cmd.SetOut(&outBuf)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetIn(strings.NewReader("stdin-pw\n"))

			cli.SetNewWriterForTest(
				func(sf *cli.SharedFlags) func(context.Context) (teamvault.Writer, error) {
					return func(ctx context.Context) (teamvault.Writer, error) {
						return mockWriter, nil
					}
				},
			)
			defer cli.ResetNewWriterForTest()

			_ = cmd.Execute()
			_, secret := mockWriter.CreateArgsForCall(0)
			Expect(string(secret.Password)).To(Equal("stdin-pw"))
		})

		It("rejects empty stdin", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.CreateReturns(
				teamvault.Key("K"),
				teamvault.ApiUrl("http://h/api/secrets/K/"),
				nil,
			)

			var errBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--name", "x", "--password-stdin"})
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
			Expect(mockWriter.CreateCallCount()).To(Equal(0))
		})
	})

	Describe("output", func() {
		It("prints the bare key with no trailing newline by default", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.CreateReturns(
				teamvault.Key("NEWKEY"),
				teamvault.ApiUrl("http://h/api/secrets/NEWKEY/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--name", "x", "--password", "pw"})
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
			Expect(outBuf.String()).To(Equal("NEWKEY"))
			Expect(outBuf.String()).ToNot(HaveSuffix("\n"))
		})

		It("prints JSON with --json", func() {
			mockWriter := &mocks.Writer{}
			mockWriter.CreateReturns(
				teamvault.Key("NEWKEY"),
				teamvault.ApiUrl("http://h/api/secrets/NEWKEY/"),
				nil,
			)

			var outBuf bytes.Buffer
			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{"create", "--name", "x", "--password", "pw", "--json"})
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
			Expect(output).To(ContainSubstring(`"key":"NEWKEY"`))
			Expect(output).To(ContainSubstring(`"api_url"`))
			Expect(output).ToNot(ContainSubstring("pw"))
		})
	})

	Describe("server validation errors", func() {
		It("surfaces the server's field and message without leaking the payload", func() {
			server := ghttp.NewServer()
			defer server.Close()
			server.RouteToHandler(
				http.MethodPost,
				"/api/secrets/",
				ghttp.RespondWith(
					http.StatusBadRequest,
					`{"filename": ["This field is required."]}`,
				),
			)

			dir := GinkgoT().TempDir()
			filePath := filepath.Join(dir, "key.pem")
			Expect(
				os.WriteFile(filePath, []byte("-----BEGIN PRIVATE KEY-----"), 0o600),
			).To(Succeed())

			cmd := cli.NewRootCommand(ctx)
			cmd.SetArgs([]string{
				"create",
				"--name", "k",
				"--file", filePath,
				"--teamvault-url", server.URL(),
				"--teamvault-user", "u",
				"--teamvault-pass", "p",
				// Point at an absent config so the machine's real config file
				// cannot redirect the request away from the fake server.
				"--teamvault-config", filepath.Join(dir, "absent.json"),
			})
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})

			err := cmd.Execute()

			// Execute() writes a non-nil error to stderr and exits 1, so the
			// error text is exactly what the operator sees on stderr.
			Expect(err).NotTo(BeNil())
			stderr := err.Error()
			Expect(stderr).To(ContainSubstring("filename"))
			Expect(stderr).To(ContainSubstring("This field is required."))
			Expect(stderr).NotTo(MatchRegexp(`file_content|base64|BEGIN .*PRIVATE KEY`))
		})
	})
})
