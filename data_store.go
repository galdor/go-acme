package acme

import (
	"errors"
)

var (
	ErrAccountNotFound     = errors.New("account not found in data store")
	ErrCertificateNotFound = errors.New("certificate not found in data store")
)

type DataStore interface {
	LoadAccountData() (*AccountData, error)
	StoreAccountData(*AccountData) error

	LoadCertificateData(string) (*CertificateData, error)
	StoreCertificateData(*CertificateData) error
}
