package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
)

type CertificateData struct {
	Name string `json:"name"`

	Identifiers []Identifier `json:"identifiers"`
	Validity    int          `json:"validity"` // days

	PrivateKey      crypto.Signer       `json:"-"`
	PrivateKeyData  []byte              `json:"private_key"`
	Certificate     []*x509.Certificate `json:"-"`
	CertificateData string              `json:"certificate"`
}

func (c *CertificateData) MarshalJSON() ([]byte, error) {
	type CertificateData2 CertificateData
	c2 := CertificateData2(*c)

	privateKeyData, err := x509.MarshalPKCS8PrivateKey(c2.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot encode private key: %w", err)
	}
	c2.PrivateKeyData = privateKeyData

	certData, err := encodePEMCertificateChain(c2.Certificate)
	if err != nil {
		return nil, fmt.Errorf("cannot encode certificate chain: %w", err)
	}
	c2.CertificateData = certData

	return json.Marshal(c2)
}

func (c *CertificateData) UnmarshalJSON(data []byte) error {
	type CertificateData2 CertificateData

	var c2 CertificateData2
	if err := json.Unmarshal(data, &c2); err != nil {
		return err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(c2.PrivateKeyData)
	if err != nil {
		return fmt.Errorf("cannot parse PKCS #8 data: %w", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key of type %T cannot be used to sign data",
			privateKey)
	}
	c2.PrivateKey = signer

	cert, err := decodePEMCertificateChain([]byte(c2.CertificateData))
	if err != nil {
		return fmt.Errorf("cannot decode PEM certificate chain: %w", err)
	}
	c2.Certificate = cert

	*c = CertificateData(c2)
	return nil
}
