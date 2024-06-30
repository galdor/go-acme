package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

func (c *Client) signPayload(data []byte, uri, nonce string) ([]byte, error) {
	// RFC 8555 6.2. Request Authentication

	algorithm, err := c.signatureAlgorithm()
	if err != nil {
		return nil, fmt.Errorf("cannot identify signature algorithm: %w", err)
	}

	jwk := jose.JSONWebKey{
		Key: c.accountData.PrivateKey,
	}

	if uri := c.accountData.URI; uri != "" {
		jwk.KeyID = uri
	}

	signingKey := jose.SigningKey{
		Algorithm: algorithm,
		Key:       &jwk,
	}

	options := jose.SignerOptions{
		NonceSource:  &staticNonceSource{nonce: nonce},
		ExtraHeaders: make(map[jose.HeaderKey]any),
	}

	options.ExtraHeaders["url"] = uri

	if jwk.KeyID == "" {
		options.EmbedJWK = true // set the "jwk" claim
	}

	signer, err := jose.NewSigner(signingKey, &options)
	if err != nil {
		return nil, fmt.Errorf("cannot create signer: %w", err)
	}

	signedData, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}

	return []byte(signedData.FullSerialize()), nil
}

func (c *Client) signatureAlgorithm() (jose.SignatureAlgorithm, error) {
	var algorithm jose.SignatureAlgorithm

	switch key := c.accountData.PrivateKey.(type) {
	case *rsa.PrivateKey:
		algorithm = jose.RS256

	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256():
			algorithm = jose.ES256
		case elliptic.P384():
			algorithm = jose.ES384
		case elliptic.P521():
			algorithm = jose.ES512
		default:
			return "", fmt.Errorf("unknown elliptic curve %#v (%T)", key, key)
		}

	default:
		return "", fmt.Errorf("unknown private key type %T", key)
	}

	return algorithm, nil
}

type staticNonceSource struct {
	nonce string
}

func (s *staticNonceSource) Nonce() (string, error) {
	if s.nonce == "" {
		return "", fmt.Errorf("nonce already used")
	}

	nonce := s.nonce
	s.nonce = ""

	return nonce, nil
}
