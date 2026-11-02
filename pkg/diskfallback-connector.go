// Copyright (c) 2016-2026 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package teamvault

import (
	"context"
	"encoding/hex"
	stderrors "errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/bborbe/errors"
	"github.com/golang/glog"
)

// ErrCacheUnavailable is returned when the cache root cannot be resolved, for
// example because the home directory is unknown. The cache then fails closed
// instead of resolving relative to the process working directory, where a
// caller-supplied key could place files.
var ErrCacheUnavailable = stderrors.New("teamvault cache directory unavailable")

// safeCacheChars matches a key that can be used unchanged as a cache directory
// name. A key is not validated beyond "not empty" (see Key.Validate), so the
// cache path has to sanitize it itself: a key such as "../../.ssh" would
// otherwise resolve to a directory outside the cache root.
var safeCacheChars = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

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
		if cached, cacheErr := read(ctx, key, kind); cacheErr == nil && len(cached) > 0 {
			glog.V(4).Infof("teamvault %s fetch for key %v failed, using cache", kind, key)
			return T(cached), nil
		}
		return "", err
	}
	if writeErr := write(ctx, key, kind, []byte(content)); writeErr != nil {
		glog.Warningf("write teamvault diskfallback failed")
	}
	return content, nil
}

// cacheRoot returns the disk-fallback cache root below the home directory.
func cacheRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", ErrCacheUnavailable
	}
	return filepath.Join(home, ".teamvault-cache"), nil
}

// cacheSegment maps a key onto one directory name below the cache root. An
// ordinary hashid key passes through unchanged, so existing caches keep
// working. Every other key is hex-encoded behind a "=" prefix: no pass-through
// key can contain "=", so the two branches cannot collide, and hex is
// reversible, so distinct keys stay distinct.
func cacheSegment(key Key) string {
	raw := key.String()
	if safeCacheChars.MatchString(raw) && raw != "." && raw != ".." {
		return raw
	}
	return "=" + hex.EncodeToString([]byte(raw))
}

func cachefile(key Key, kind string) (string, error) {
	root, err := cacheRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, cacheSegment(key), kind), nil
}

func read(ctx context.Context, key Key, kind string) ([]byte, error) {
	path, err := cachefile(key, kind)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "cache file unavailable")
	}
	return os.ReadFile(path)
}

func write(ctx context.Context, key Key, kind string, content []byte) error {
	root, err := cacheRoot()
	if err != nil {
		return errors.Wrap(ctx, err, "cache file unavailable")
	}
	dir := filepath.Join(root, cacheSegment(key))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.Wrap(ctx, err, "mkdir failed")
	}
	// #nosec G703 -- the directory name is produced by cacheSegment and cannot
	// leave the cache root
	return errors.Wrap(
		ctx,
		os.WriteFile(filepath.Join(dir, kind), content, 0600),
		"write cache file failed",
	)
}
