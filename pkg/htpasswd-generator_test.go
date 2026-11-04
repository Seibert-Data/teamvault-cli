// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault_test

import (
	"context"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
)

// lineCount counts rendered lines the way `wc -l` does: a trailing newline
// terminates the last line rather than starting an empty one.
func lineCount(content []byte) int {
	trimmed := strings.TrimRight(string(content), "\n")
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "\n") + 1
}

var _ = Describe("HtpasswdGenerator", func() {
	var ctx context.Context
	var generator teamvault.HtpasswdGenerator
	var key teamvault.Key
	var content []byte
	var err error

	BeforeEach(func() {
		ctx = context.Background()
		generator = teamvault.NewHtpasswdGenerator(teamvault.NewDummyConnector())
	})

	// The dummy connector returns the key as the username, so the key is the
	// stored username under test.
	JustBeforeEach(func() {
		content, err = generator.Generate(ctx, key)
	})

	Context("with a plain username", func() {
		BeforeEach(func() { key = teamvault.Key("alice") })
		It("returns no error", func() {
			Expect(err).To(BeNil())
		})
		It("renders exactly one line", func() {
			Expect(lineCount(content)).To(Equal(1))
		})
		It("renders the username as the principal", func() {
			Expect(string(content)).To(HavePrefix("alice:$2"))
		})
	})

	Context("with a username carrying a newline", func() {
		BeforeEach(func() { key = teamvault.Key("admin\nattacker") })
		It("returns no error", func() {
			Expect(err).To(BeNil())
		})
		It("renders exactly one line", func() {
			Expect(lineCount(content)).To(Equal(1))
		})
		It("renders the newline as a space, not a second principal", func() {
			Expect(string(content)).To(HavePrefix("admin attacker:$2"))
		})
		It("does not render the injected principal", func() {
			Expect(string(content)).NotTo(ContainSubstring("\nattacker:"))
		})
	})

	Context("with a username carrying a carriage return", func() {
		BeforeEach(func() { key = teamvault.Key("admin\rattacker") })
		It("renders exactly one line", func() {
			Expect(lineCount(content)).To(Equal(1))
		})
		It("renders the carriage return as a space", func() {
			Expect(string(content)).To(HavePrefix("admin attacker:$2"))
		})
	})

	Context("with a username carrying a colon", func() {
		BeforeEach(func() { key = teamvault.Key("evil:garbage") })
		It("returns no error", func() {
			Expect(err).To(BeNil())
		})
		It("strips the colon so the principal is not corrupted", func() {
			Expect(string(content)).To(HavePrefix("evilgarbage:$2"))
		})
		It("renders exactly two colon-separated fields", func() {
			Expect(strings.Split(strings.TrimRight(string(content), "\n"), ":")).To(HaveLen(2))
		})
	})

	Context("with a username carrying only control characters", func() {
		BeforeEach(func() { key = teamvault.Key("\n\n") })
		It("returns an error naming the key", func() {
			Expect(err).NotTo(BeNil())
			// The key is named in its escaped form, so the message stays one line.
			Expect(err.Error()).To(ContainSubstring(`\n\n`))
		})
		It("renders nothing", func() {
			Expect(content).To(BeNil())
		})
	})

	Context("with an empty username", func() {
		BeforeEach(func() { key = teamvault.Key("") })
		It("returns an error rather than a file Apache would reject", func() {
			Expect(err).NotTo(BeNil())
		})
		It("renders nothing", func() {
			Expect(content).To(BeNil())
		})
	})
})
