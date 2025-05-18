package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
)

type NewAccount struct {
	Contact                []string        `json:"contact,omitempty"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting,omitempty"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
}

type Account struct {
	Status                 string          `json:"status"`
	Contact                []string        `json:"contact,omitempty"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed,omitempty"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
	Orders                 string          `json:"orders"`
}

func (c *Client) createAccount(ctx context.Context) (*AccountData, error) {
	c.Log.Debug(1, "creating account")

	privateKey, err := c.Cfg.GenerateAccountPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("cannot generate private key: %w", err)
	}

	accountData := AccountData{
		PrivateKey: privateKey,
	}

	c.accountData = &accountData

	newAccount := NewAccount{
		Contact:              c.Cfg.ContactURIs,
		TermsOfServiceAgreed: true,
	}

	res, err := c.sendRequest(ctx, "POST", c.Directory.NewAccount,
		&newAccount, nil)
	if err != nil {
		return nil, err
	}

	location := res.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("missing or empty Location header field")
	}

	accountData.URI = location

	return &accountData, nil
}

func GenerateECDSAP256PrivateKey() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
