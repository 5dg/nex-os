package model

import "errors"

// ConfiguredGenerator admits only the two synthetic runtime profiles. The SDK
// adapter remains testable with a stub; no currently supported server profile
// constructs a live SDK client, regardless of ambient AWS configuration.
func ConfiguredGenerator(profile, provider string) (Generator, error) {
	if profile != "development" && profile != qualificationProfile {
		return nil, errors.New("unsupported execution profile")
	}
	if provider != "development" {
		return nil, errors.New("synthetic runtime requires development provider; live inference remains deferred")
	}
	return SyntheticGenerator{}, nil
}
