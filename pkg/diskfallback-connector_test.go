// Copyright (c) 2016-2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
	"github.com/Seibert-Data/teamvault-cli/v5/pkg/mocks"
)

var _ = Describe("DiskFallbackConnector", func() {
	var ctx context.Context
	var home string
	var fakeConnector *mocks.Connector
	var connector teamvault.Connector
	var key teamvault.Key

	BeforeEach(func() {
		ctx = context.Background()
		home = GinkgoT().TempDir()
		GinkgoT().Setenv("HOME", home)
		fakeConnector = &mocks.Connector{}
		connector = teamvault.NewDiskFallbackConnector(fakeConnector)
		key = teamvault.Key("AbC123")
	})

	cacheFile := func(segment string) string {
		return filepath.Join(home, ".teamvault-cache", segment, "password")
	}

	Context("successful fetch", func() {
		BeforeEach(func() {
			fakeConnector.PasswordReturns("secret", nil)
		})
		It("returns the fetched value", func() {
			result, err := connector.Password(ctx, key)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(teamvault.Password("secret")))
		})
		It("writes the fetched value to the cache", func() {
			_, err := connector.Password(ctx, key)
			Expect(err).NotTo(HaveOccurred())
			content, err := os.ReadFile(cacheFile("AbC123"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(content)).To(Equal("secret"))
		})
	})

	Context("failing fetch", func() {
		var fetchErr error
		BeforeEach(func() {
			fetchErr = errors.New("teamvault unreachable")
			fakeConnector.PasswordReturns("", fetchErr)
		})
		It("falls back to a cached value", func() {
			Expect(os.MkdirAll(filepath.Dir(cacheFile("AbC123")), 0700)).To(Succeed())
			Expect(os.WriteFile(cacheFile("AbC123"), []byte("cached"), 0600)).To(Succeed())
			result, err := connector.Password(ctx, key)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(teamvault.Password("cached")))
		})
		It("does not write an empty cache entry when none exists", func() {
			_, err := connector.Password(ctx, key)
			Expect(err).To(HaveOccurred())
			_, statErr := os.Stat(cacheFile("AbC123"))
			Expect(
				os.IsNotExist(statErr),
			).To(BeTrue(), "a failed fetch must not create a cache entry")
		})
		It("keeps failing instead of returning a poisoned empty cache entry", func() {
			// Regression: the first failed fetch used to write an empty file,
			// so the second call returned "" with a nil error.
			_, firstErr := connector.Password(ctx, key)
			Expect(firstErr).To(HaveOccurred())
			_, secondErr := connector.Password(ctx, key)
			Expect(secondErr).To(HaveOccurred())
		})
		It("treats an empty cache entry as a miss", func() {
			Expect(os.MkdirAll(filepath.Dir(cacheFile("AbC123")), 0700)).To(Succeed())
			Expect(os.WriteFile(cacheFile("AbC123"), []byte(""), 0600)).To(Succeed())
			result, err := connector.Password(ctx, key)
			Expect(err).To(HaveOccurred())
			Expect(result).To(Equal(teamvault.Password("")))
		})
	})

	Context("key with path separators", func() {
		BeforeEach(func() {
			fakeConnector.PasswordReturns("secret", nil)
			key = teamvault.Key("../../escaped")
		})
		It("keeps the cache entry inside the cache directory", func() {
			_, err := connector.Password(ctx, key)
			Expect(err).NotTo(HaveOccurred())
			entries, err := os.ReadDir(filepath.Join(home, ".teamvault-cache"))
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Name()).NotTo(ContainSubstring(".."))
			Expect(entries[0].Name()).NotTo(ContainSubstring("/"))
			_, err = os.Stat(filepath.Join(home, ".teamvault-cache", entries[0].Name(), "password"))
			Expect(err).NotTo(HaveOccurred())
		})
		It("does not collide with a key that looks like an escaped one", func() {
			// The sanitized branch is hex behind "=", so no pass-through key can
			// name the same directory as an escaped key.
			_, err := connector.Password(ctx, key)
			Expect(err).NotTo(HaveOccurred())
			_, err = connector.Password(ctx, teamvault.Key("a_b-1a2b3c4d"))
			Expect(err).NotTo(HaveOccurred())
			entries, err := os.ReadDir(filepath.Join(home, ".teamvault-cache"))
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(2))
		})
		It("maps the same key to the same directory every time", func() {
			_, err := connector.Password(ctx, key)
			Expect(err).NotTo(HaveOccurred())
			_, err = connector.Password(ctx, key)
			Expect(err).NotTo(HaveOccurred())
			entries, err := os.ReadDir(filepath.Join(home, ".teamvault-cache"))
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
		})
	})

	Context("home directory unknown", func() {
		BeforeEach(func() {
			GinkgoT().Setenv("HOME", "")
			fakeConnector.PasswordReturns("secret", nil)
		})
		It("does not write a cache file relative to the working directory", func() {
			result, err := connector.Password(ctx, key)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(teamvault.Password("secret")))
			_, statErr := os.Stat(".teamvault-cache")
			Expect(os.IsNotExist(statErr)).To(BeTrue())
		})
		It("reports an error instead of an empty value when the fetch fails", func() {
			fakeConnector.PasswordReturns("", errors.New("offline"))
			_, err := connector.Password(ctx, key)
			Expect(err).To(HaveOccurred())
		})
	})
})
