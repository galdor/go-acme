package acme

import (
	"context"
	"fmt"
)

// RFC 8555 7.1.1. Directory
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	NewAuthz   string `json:"newAuthz,omitempty"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`

	Meta DirectoryMetadata `json:"meta"`
}

type DirectoryMetadata struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CAAIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

func (c *Client) updateDirectory(ctx context.Context) error {
	c.Log.Debug(1, "updating directory from %q", c.Cfg.DirectoryURI)

	var d Directory

	_, err := c.sendRequestWithNonce(ctx, "GET", c.Cfg.DirectoryURI,
		nil, &d, "")
	if err != nil {
		return fmt.Errorf("cannot fetch %q: %w", c.Cfg.DirectoryURI, err)
	}

	c.Directory = &d

	return nil
}
