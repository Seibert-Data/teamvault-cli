// Copyright (c) 2016-2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/bborbe/errors"
	"github.com/golang/glog"
)

// unsafeCacheChars matches every character a cache directory name may not
// contain. A key is not validated beyond "not empty" (see Key.Validate), so
// the cache path has to sanitize it itself: a key such as "../../.ssh" would
// otherwise resolve to a directory outside the cache root.
var unsafeCacheChars = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// NewDiskFallbackConnector creates a new Connector that uses disk cache as fallback when the underlying connector fails.
func NewDiskFallbackConnector(connector Connector) Connector {
	return &diskFallback{
		connector: connector,
	}

}

type diskFallback struct {
	connector Connector
}

func (d *diskFallback) Password(ctx context.Context, key Key) (Password, error) {
	return fetchWithFallback(ctx, key, "password", func() (Password, error) {
		return d.connector.Password(ctx, key)
	})
}

func (d *diskFallback) User(ctx context.Context, key Key) (User, error) {
	return fetchWithFallback(ctx, key, "user", func() (User, error) {
		return d.connector.User(ctx, key)
	})
}

func (d *diskFallback) Url(ctx context.Context, key Key) (Url, error) {
	return fetchWithFallback(ctx, key, "url", func() (Url, error) {
		return d.connector.Url(ctx, key)
	})
}

func (d *diskFallback) File(ctx context.Context, key Key) (File, error) {
	return fetchWithFallback(ctx, key, "file", func() (File, error) {
		return d.connector.File(ctx, key)
	})
}

func (d *diskFallback) Search(ctx context.Context, key string) ([]SearchResult, error) {
	return d.connector.Search(ctx, key)
}

// fetchWithFallback reads one value from the underlying connector and falls
// back to the disk cache when that read fails. The cache is written only from
// a successful read: an earlier version wrote the zero value of a failed read,
// which left an empty file behind, and the next offline call then returned an
// empty value with a nil error — a silently blank credential in a rendered
// config. A cached empty value is treated as a miss for the same reason.
func fetchWithFallback[T ~string](
	ctx context.Context,
	key Key,
	kind string,
	fetch func() (T, error),
) (T, error) {
	content, err := fetch()
	if err != nil {
		if cached, cacheErr := read(key, kind); cacheErr == nil && len(cached) > 0 {
			glog.V(2).Infof("teamvault %s fetch for key %v failed, using cache", kind, key)
			return T(cached), nil
		}
		return "", err
	}
	if writeErr := write(ctx, key, kind, []byte(content)); writeErr != nil {
		glog.Warningf("write teamvault diskfallback failed")
	}
	return content, nil
}

func cachefile(key Key, kind string) string {
	return filepath.Join(cachedir(key), kind)
}

func cachedir(key Key) string {
	return filepath.Join(os.Getenv("HOME"), ".teamvault-cache", cacheSegment(key))
}

// cacheSegment maps a key onto one directory name below the cache root. Keys
// are hashids, so an ordinary key passes through unchanged and existing caches
// keep working; a key carrying path separators, "." or ".." is replaced and
// disambiguated with a short hash of the original so two such keys cannot
// collide on one directory.
func cacheSegment(key Key) string {
	raw := key.String()
	segment := unsafeCacheChars.ReplaceAllString(raw, "_")
	if segment == raw && segment != "" && segment != "." && segment != ".." {
		return segment
	}
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s-%x", segment, sum[:4])
}

func read(key Key, kind string) ([]byte, error) {
	return os.ReadFile(cachefile(key, kind))
}

func write(ctx context.Context, key Key, kind string, content []byte) error {
	err := os.MkdirAll(cachedir(key), 0700)
	if err != nil {
		return errors.Wrap(ctx, err, "mkdir failed")
	}
	// #nosec G703 -- the directory name is sanitized by cacheSegment, so the
	// path cannot leave the cache root
	return errors.Wrap(
		ctx,
		os.WriteFile(cachefile(key, kind), content, 0600),
		"write cache file failed",
	)
}
