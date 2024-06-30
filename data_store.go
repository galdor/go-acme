package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrNoAccount = errors.New("no account found in data store")

type DataStore interface {
	LoadAccountData() (*AccountData, error)
	StoreAccountData(*AccountData) error
}

type AccountData struct {
	URI            string        `json:"uri"`
	PrivateKey     crypto.Signer `json:"-"`
	PrivateKeyData []byte        `json:"private_key_data"`
}

func (a *AccountData) MarshalJSON() ([]byte, error) {
	type AccountData2 AccountData
	a2 := AccountData2(*a)

	privateKeyData, err := x509.MarshalPKCS8PrivateKey(a2.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot encode private key: %w", err)
	}
	a2.PrivateKeyData = privateKeyData

	return json.Marshal(a2)
}

func (a *AccountData) UnmarshalJSON(data []byte) error {
	type AccountData2 AccountData
	var a2 AccountData2

	if err := json.Unmarshal(data, &a2); err != nil {
		return err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(a2.PrivateKeyData)
	if err != nil {
		return fmt.Errorf("cannot parse PKCS #8 data: %w", err)
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key of type %T cannot be used to sign data",
			privateKey)
	}

	a2.PrivateKey = signer

	*a = AccountData(a2)
	return nil
}
