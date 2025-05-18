package acme

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

type CertificateData struct {
	Name string `json:"name"`

	Identifiers []Identifier `json:"identifiers"`
	Validity    int          `json:"validity,omitempty"` // days [1]

	PrivateKey      crypto.Signer       `json:"-"`
	PrivateKeyData  []byte              `json:"private_key"`
	Certificate     []*x509.Certificate `json:"-"`
	CertificateData string              `json:"certificate"`

	// [1] The validity period is optional because even though ACME and Pebble
	// support it, Let's Encrypt will reject all orders setting NotBefore or
	// NotAfter.
}

func (c *CertificateData) LeafCertificate() *x509.Certificate {
	if len(c.Certificate) == 0 {
		return nil
	}

	return c.Certificate[0]
}

func (c *CertificateData) ContainsCertificate() bool {
	return c.PrivateKey != nil && len(c.Certificate) > 0
}

func (c *CertificateData) LeafCertificateFingerprint(hash crypto.Hash) string {
	cert := c.LeafCertificate()

	h := hash.New()
	h.Write(cert.Raw)
	checksum := h.Sum(nil)

	var buf bytes.Buffer
	for i, b := range checksum {
		if i > 0 {
			buf.WriteByte(':')
		}

		s := strconv.FormatInt(int64(b), 16)
		buf.WriteString(strings.ToUpper(s))
	}

	return buf.String()
}

func (c *CertificateData) TLSCertificate() *tls.Certificate {
	certsData := make([][]byte, len(c.Certificate))
	for i, cert := range c.Certificate {
		certsData[i] = cert.Raw
	}

	cert := tls.Certificate{
		PrivateKey:  c.PrivateKey,
		Certificate: certsData,
		Leaf:        c.LeafCertificate(),
	}

	return &cert
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

func (c *CertificateData) extractCopy() *CertificateData {
	// This function is very specialized: it is used by a certificate worker to
	// create a copy of its internal CertificateData structure that will be used
	// by consumers of the library.
	//
	// Obviously we do not want any shared access to the same structure. The
	// private key is generated once and never modified afterward, so we can
	// include it in the copy. The certificate chain is included in the copy and
	// cleared in the original since the worker will not need it again (it will
	// obtain a new chain on renewal).

	c2 := CertificateData{
		Name: c.Name,

		Identifiers: slices.Clone(c.Identifiers),
		Validity:    c.Validity,

		PrivateKey:  c.PrivateKey,
		Certificate: c.Certificate,
	}

	c.Certificate = nil
	c.CertificateData = ""

	return &c2
}

func CertificateRenewalTime(data *CertificateData) time.Time {
	cert := data.LeafCertificate()
	now := time.Now()

	// Renew right now if the certificates expires in less than 12h
	validityLeft := cert.NotAfter.Sub(now)
	if validityLeft.Hours() < 12.0 {
		return now
	}

	// We want to renew regularly even if the certificate is valid for a very
	// long time because it helps catching operational issues. But we also do
	// not want to spam the ACME provider. Half of the validity period is a fair
	// compromise.
	halfValidity := cert.NotAfter.Sub(cert.NotBefore) / 2.0
	return cert.NotBefore.Add(halfValidity)
}
