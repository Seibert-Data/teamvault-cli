// Copyright (c) 2016-2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package factory

import (
	"context"
	"net/http"
	"time"

	"github.com/bborbe/errors"
	libhttp "github.com/bborbe/http"
	libtime "github.com/bborbe/time"

	teamvault "github.com/Seibert-Data/teamvault-cli/v5/pkg"
)

// CreateConnectorWithConfig creates a new TeamVault Connector using configuration from a file or parameters.
// If the config file exists, it takes precedence over the individual parameters.
// Delegates to CreateConnectorWithConfigAndKeychain using the real OS Keychain.
func CreateConnectorWithConfig(
	ctx context.Context,
	httpClient *http.Client,
	configPath teamvault.TeamvaultConfigPath,
	apiURL teamvault.Url,
	apiUser teamvault.User,
	apiPassword teamvault.Password,
	staging teamvault.Staging,
	cacheEnabled bool,
	currentDateTime libtime.CurrentDateTime,
) (teamvault.Connector, error) {
	return CreateConnectorWithConfigAndKeychain(
		ctx,
		httpClient,
		configPath,
		apiURL,
		apiUser,
		apiPassword,
		staging,
		cacheEnabled,
		currentDateTime,
		teamvault.NewKeychain(),
	)
}

// CreateConnectorWithConfigAndTimeout is like CreateConnectorWithConfigAndKeychain
// but also accepts a CLI-supplied timeout. Resolution order: cliTimeout > config.Timeout > 5s default.
// Negative cliTimeout returns a wrapped error.
func CreateConnectorWithConfigAndTimeout(
	ctx context.Context,
	httpClient *http.Client,
	configPath teamvault.TeamvaultConfigPath,
	apiURL teamvault.Url,
	apiUser teamvault.User,
	apiPassword teamvault.Password,
	staging teamvault.Staging,
	cacheEnabled bool,
	currentDateTime libtime.CurrentDateTime,
	keychain teamvault.Keychain,
	cliTimeout libtime.Duration,
) (teamvault.Connector, error) {
	var config *teamvault.Config
	if configPath.Exists() {
		var err error
		config, err = configPath.Parse()
		if err != nil {
			return nil, errors.Wrapf(ctx, err, "parse teamvault config failed")
		}
		apiURL = config.Url
		apiUser = config.User
		apiPassword = config.Password
		cacheEnabled = cacheEnabled || config.CacheEnabled
	}
	if cliTimeout.Duration() < 0 {
		return nil, errors.Errorf(ctx, "invalid timeout %v: must be >= 0", cliTimeout.Duration())
	}
	if config != nil && config.Timeout.Duration() < 0 {
		return nil, errors.Errorf(
			ctx,
			"invalid timeout %v: must be >= 0",
			config.Timeout.Duration(),
		)
	}
	effective := cliTimeout.Duration()
	if effective == 0 {
		if config != nil {
			effective = config.Timeout.Duration()
		}
		if effective == 0 {
			effective = 5 * time.Second
		}
	}
	httpClient.Timeout = effective
	if apiPassword == "" && apiURL != "" {
		pwd, err := keychain.ReadPassword(ctx, apiURL)
		if err != nil {
			return nil, errors.Wrapf(
				ctx,
				err,
				"read password from keychain for url %q failed — run `teamvault-cli login` to store your TeamVault password",
				apiURL,
			)
		}
		if pwd != "" {
			apiPassword = pwd
		}
	}
	return CreateConnector(
		httpClient,
		apiURL,
		apiUser,
		apiPassword,
		staging,
		cacheEnabled,
		currentDateTime,
	), nil
}

// CreateConnectorWithConfigAndKeychain is the dependency-injected variant of
// CreateConnectorWithConfig. Production callers use CreateConnectorWithConfig,
// which delegates to this with teamvault.NewKeychain(). Tests inject a fake
// Keychain to drive resolution-chain scenarios.
func CreateConnectorWithConfigAndKeychain(
	ctx context.Context,
	httpClient *http.Client,
	configPath teamvault.TeamvaultConfigPath,
	apiURL teamvault.Url,
	apiUser teamvault.User,
	apiPassword teamvault.Password,
	staging teamvault.Staging,
	cacheEnabled bool,
	currentDateTime libtime.CurrentDateTime,
	keychain teamvault.Keychain,
) (teamvault.Connector, error) {
	return CreateConnectorWithConfigAndTimeout(
		ctx,
		httpClient,
		configPath,
		apiURL,
		apiUser,
		apiPassword,
		staging,
		cacheEnabled,
		currentDateTime,
		keychain,
		libtime.Duration(0),
	)
}

// CreateConnector creates a new TeamVault Connector based on staging and cache settings.
// Returns a dummy connector for staging environments, or a disk fallback connector when cache is enabled.
func CreateConnector(
	httpClient *http.Client,
	apiURL teamvault.Url,
	apiUser teamvault.User,
	apiPassword teamvault.Password,
	staging teamvault.Staging,
	cacheEnabled bool,
	currentDateTime libtime.CurrentDateTime,
) teamvault.Connector {
	if staging {
		return teamvault.NewDummyConnector()
	}
	if cacheEnabled {
		return teamvault.NewDiskFallbackConnector(
			CreateRemoteConnector(httpClient, apiURL, apiUser, apiPassword, currentDateTime),
		)
	}
	return CreateRemoteConnector(httpClient, apiURL, apiUser, apiPassword, currentDateTime)
}

// CreateRemoteConnector creates a new Connector that communicates directly with a remote TeamVault API.
func CreateRemoteConnector(
	httpClient *http.Client,
	apiURL teamvault.Url,
	apiUser teamvault.User,
	apiPassword teamvault.Password,
	currentDateTime libtime.CurrentDateTime,
) teamvault.Connector {
	return teamvault.NewRemoteConnector(
		httpClient,
		apiURL,
		apiUser,
		apiPassword,
		currentDateTime,
	)
}

// CreateRemoteWriter creates a Writer that communicates directly with a remote TeamVault API.
func CreateRemoteWriter(
	httpClient *http.Client,
	apiURL teamvault.Url,
	apiUser teamvault.User,
	apiPassword teamvault.Password,
	currentDateTime libtime.CurrentDateTime,
) teamvault.Writer {
	return teamvault.NewRemoteWriter(httpClient, apiURL, apiUser, apiPassword, currentDateTime)
}

// CreateRemoteSharer creates a Sharer that communicates directly with a remote TeamVault API.
func CreateRemoteSharer(
	httpClient *http.Client,
	apiURL teamvault.Url,
	apiUser teamvault.User,
	apiPassword teamvault.Password,
	currentDateTime libtime.CurrentDateTime,
) teamvault.Sharer {
	return teamvault.NewRemoteSharer(httpClient, apiURL, apiUser, apiPassword, currentDateTime)
}

// CreateHttpClient creates a new HTTP client configured for TeamVault API communication.
// The client has a default timeout of 5 seconds.
func CreateHttpClient(ctx context.Context) (*http.Client, error) {
	return libhttp.NewClientBuilder().WithTimeout(5 * time.Second).Build(ctx)
}
