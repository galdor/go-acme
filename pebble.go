package acme

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
)

// The CA certificate is part of the Pebble repository
// (https://github.com/letsencrypt/pebble/tree/main/test/certs) and has not
// changed in 7+ years.

const (
	PebbleDirectoryURI               = "https://localhost:14000/dir"
	PebbleHTTPChallengeSolverAddress = ":5002"
)

//go:embed data/pebble-ca.crt
var PebbleCACertificateData []byte

func PebbleCACertificate() *x509.Certificate {
	block, _ := pem.Decode(PebbleCACertificateData)
	if block == nil {
		panic("no PEM block found in Pebble CA certificate data")
	}

	if block.Type != "CERTIFICATE" {
		panic(fmt.Sprintf("invalid PEM block %q in Pebble CA certificate data",
			block.Type))
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("cannot parse Pebble CA certificate: %v", err))
	}

	return cert
}

func PebbleCACertificatePool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(PebbleCACertificate())
	return pool
}
