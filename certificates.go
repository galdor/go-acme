package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"

	"golang.org/x/net/idna"
)

type CertificateRequestResult struct {
	CertificateData *CertificateData
	Error           error
}

func (c *Client) RequestCertificate(ctx context.Context, name string, identifiers []Identifier, validity int) (<-chan *CertificateRequestResult, error) {
	certData := CertificateData{
		Name: name,

		Identifiers: slices.Clone(identifiers),
		Validity:    validity,
	}

	resultChan := make(chan *CertificateRequestResult)

	c.startCertificateWorker(ctx, &certData, resultChan)

	return resultChan, nil
}

func (c *Client) generateCSR(ids []Identifier, privateKey crypto.Signer) ([]byte, error) {
	var tpl x509.CertificateRequest

	for _, id := range ids {
		switch id.Type {
		case IdentifierTypeDNS:
			encodedName, err := idna.ToASCII(id.Value)
			if err != nil {
				return nil, fmt.Errorf("cannot encode dns name %q: %w",
					id.Value, err)
			}

			tpl.DNSNames = append(tpl.DNSNames, encodedName)

		default:
			return nil, fmt.Errorf("unhandled identifier type %q", id.Type)
		}
	}

	return x509.CreateCertificateRequest(rand.Reader, &tpl, privateKey)
}

func encodePEMCertificateChain(chain []*x509.Certificate) (string, error) {
	var buf bytes.Buffer

	for _, cert := range chain {
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		buf.Write(pem.EncodeToMemory(&block))
		buf.WriteByte('\n')
	}

	return buf.String(), nil
}

func decodePEMCertificateChain(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unknown PEM block %q", block.Type)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cannot parse certificate: %w", err)
		}

		chain = append(chain, cert)

		data = rest
	}

	return chain, nil
}
