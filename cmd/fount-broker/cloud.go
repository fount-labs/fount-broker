package main

import (
	"github.com/fount-labs/fount-broker/internal/broker"
	"github.com/fount-labs/fount-broker/internal/channel"
	"github.com/fount-labs/fount-broker/internal/policy"
)

// newCloud is the client end of the coordinator's channel, proving the
// account with the vault's license and cloud_session credentials, or nil
// when this build pins no coordinator.
func newCloud(vault *broker.Vault) (broker.CloudService, error) {
	origin, repo := coordinator()
	if origin == "" {
		return nil, nil
	}
	check, err := coordinatorCheck(repo)
	if err != nil {
		return nil, err
	}
	c := &channel.Client{Origin: origin, Check: check, Identity: func() (channel.Identity, error) {
		license, _ := vault.Get(policy.CredentialLicense)
		session, _ := vault.Get(policy.CredentialCloudSession)
		return channel.ParseIdentity(license, session)
	}}
	// A channel keeps the proof it opened with until it expires; new
	// credentials, or none after signing out, apply from the next.
	vault.OnChange(policy.CredentialLicense, c.Reset)
	vault.OnChange(policy.CredentialCloudSession, c.Reset)
	return c, nil
}
