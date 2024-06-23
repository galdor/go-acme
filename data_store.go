package acme

import (
	"crypto"
	"errors"
)

var ErrNoAccount = errors.New("no account found in data store")

type DataStore interface {
	LoadAccountData() (*AccountData, error)
	StoreAccountData(*AccountData) error
}

type AccountData struct {
	URI        string
	PrivateKey crypto.Signer
}
