package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type ErrorType string

const (
	ErrorTypeAccountDoesNotExist     ErrorType = "urn:ietf:params:acme:error:accountDoesNotExist"
	ErrorTypeAlreadyRevoked          ErrorType = "urn:ietf:params:acme:error:alreadyRevoked"
	ErrorTypeBadCSR                  ErrorType = "urn:ietf:params:acme:error:badCSR"
	ErrorTypeBadNonce                ErrorType = "urn:ietf:params:acme:error:badNonce"
	ErrorTypeBadPublicKey            ErrorType = "urn:ietf:params:acme:error:badPublicKey"
	ErrorTypeBadRevocationReason     ErrorType = "urn:ietf:params:acme:error:badRevocationReason"
	ErrorTypeBadSignatureAlgorithm   ErrorType = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	ErrorTypeCAA                     ErrorType = "urn:ietf:params:acme:error:caa"
	ErrorTypeCompound                ErrorType = "urn:ietf:params:acme:error:compound"
	ErrorTypeConnection              ErrorType = "urn:ietf:params:acme:error:connection"
	ErrorTypeDNS                     ErrorType = "urn:ietf:params:acme:error:dns"
	ErrorTypeExternalAccountRequired ErrorType = "urn:ietf:params:acme:error:externalAccountRequired"
	ErrorTypeIncorrectResponse       ErrorType = "urn:ietf:params:acme:error:incorrectResponse"
	ErrorTypeInvalidContact          ErrorType = "urn:ietf:params:acme:error:invalidContact"
	ErrorTypeMalformed               ErrorType = "urn:ietf:params:acme:error:malformed"
	ErrorTypeOrderNotReady           ErrorType = "urn:ietf:params:acme:error:orderNotReady"
	ErrorTypeRateLimited             ErrorType = "urn:ietf:params:acme:error:rateLimited"
	ErrorTypeRejectedIdentifier      ErrorType = "urn:ietf:params:acme:error:rejectedIdentifier"
	ErrorTypeServerInternal          ErrorType = "urn:ietf:params:acme:error:serverInternal"
	ErrorTypeTLS                     ErrorType = "urn:ietf:params:acme:error:tls"
	ErrorTypeUnauthorized            ErrorType = "urn:ietf:params:acme:error:unauthorized"
	ErrorTypeUnsupportedContact      ErrorType = "urn:ietf:params:acme:error:unsupportedContact"
	ErrorTypeUnsupportedIdentifier   ErrorType = "urn:ietf:params:acme:error:unsupportedIdentifier"
	ErrorTypeUserActionRequired      ErrorType = "urn:ietf:params:acme:error:userActionRequired"
)

type ProblemDetails struct {
	// RFC 7807 3.1. Members of a Problem Details Object
	Type     ErrorType `json:"type,omitempty"`
	Title    string    `json:"title,omitempty"`
	Status   int       `json:"status,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Instance string    `json:"instance,omitempty"`

	// RFC 8555 6.7.1. Subproblems
	Subproblems []ProblemDetails `json:"subproblems,omitempty"`
}

func (err *ProblemDetails) FormatErrorString(buf *bytes.Buffer, indent string) {
	if err.Type != "" {
		buf.WriteString(indent)
		buf.WriteString(string(err.Type))
	}

	if err.Title != "" {
		buf.WriteString(": ")
		buf.WriteString(err.Title)
	}

	indent = indent + "  "

	if err.Detail != "" {
		buf.WriteByte('\n')
		buf.WriteString(indent)
		buf.WriteString(err.Detail)
	}

	if len(err.Subproblems) > 0 {
		buf.WriteByte('\n')
		buf.WriteString(indent)

		for i, err2 := range err.Subproblems {
			err2.FormatErrorString(buf, indent+"  ")

			if i < len(err.Subproblems)-1 {
				buf.WriteByte('\n')
				buf.WriteString(indent)
			}
		}
	}
}

func (err *ProblemDetails) Error() string {
	var buf bytes.Buffer
	err.FormatErrorString(&buf, "")
	return buf.String()
}

func NewHTTPClient(caCertPool *x509.CertPool) *http.Client {
	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tlsCfg := tls.Config{
		RootCAs: caCertPool,
	}

	tlsDialer := tls.Dialer{
		NetDialer: &dialer,
		Config:    &tlsCfg,
	}

	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,

		DialContext:    dialer.DialContext,
		DialTLSContext: tlsDialer.DialContext,

		MaxIdleConns: 10,

		IdleConnTimeout: 60 * time.Second,
	}

	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: &transport,
	}

	return &client
}

func (c *Client) sendRequest(ctx context.Context, method, uri string, reqBody, resBody any) (*http.Response, error) {
	nbAttempts := 3
	if c.Cfg.DirectoryURI == PebbleDirectoryURI {
		nbAttempts = 100
	}

	var lastBadNonceError error

	for i := 0; i < nbAttempts; i++ {
		nonce, err := c.nextNonce(ctx)
		if err != nil {
			return nil, fmt.Errorf("cannot obtain nonce: %w", err)
		}

		res, err := c.sendRequestWithNonce(ctx, method, uri, reqBody, resBody, nonce)
		if err == nil {
			return res, nil
		} else {
			var details *ProblemDetails

			if !errors.As(err, &details) || details.Type != ErrorTypeBadNonce {
				return nil, err
			}

			lastBadNonceError = err
		}
	}

	return nil, lastBadNonceError
}

func (c *Client) sendRequestWithNonce(ctx context.Context, method, uri string, reqBody, resBody any, nonce string) (*http.Response, error) {
	var reqBodyData []byte
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("cannot encode request body: %w", err)
		}

		reqBodyData = data
	}

	var reqBodyReader io.Reader

	if method != "HEAD" && uri != c.Cfg.DirectoryURI {
		if nonce == "" {
			return nil, fmt.Errorf("cannot sign request without a nonce")
		}

		signedData, err := c.signPayload(reqBodyData, uri, nonce)
		if err != nil {
			return nil, fmt.Errorf("cannot sign request body data: %w", err)
		}

		reqBodyReader = bytes.NewReader(signedData)
	}

	req, err := http.NewRequestWithContext(ctx, method, uri, reqBodyReader)
	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}

	req.Header.Set("User-Agent", c.Cfg.UserAgent)
	req.Header.Set("Content-Type", "application/jose+json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot send request: %w", err)
	}
	defer res.Body.Close()

	c.Log.Debug(2, "%s %s %d", method, uri, res.StatusCode)

	// When sending a request without a nonce (i.e. a request to the newNonce
	// endpoint), we do not want to store it since we are going to use it
	// immediately.
	if nonce != "" {
		if nonce := res.Header.Get("Replay-Nonce"); nonce != "" {
			c.storeNonce(nonce)
		}
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		err = UnwrapOpError(err, "read")
		return res, fmt.Errorf("cannot read response body: %w", err)
	}

	if status := res.StatusCode; status < 200 || status > 300 {
		var details ProblemDetails
		if err := json.Unmarshal(data, &details); err == nil {
			return res, &details
		}

		return res, fmt.Errorf("request failed with status %d: %s",
			status, data)
	}

	if resBody != nil {
		switch dest := resBody.(type) {
		case *[]byte:
			*dest = data

		default:
			if err := json.Unmarshal(data, dest); err != nil {
				return res, fmt.Errorf("cannot decode response body: %w", err)
			}
		}
	}

	return res, nil
}

func (c *Client) fetchNonce(ctx context.Context) (string, error) {
	res, err := c.sendRequestWithNonce(ctx, "HEAD", c.Directory.NewNonce,
		nil, nil, "")
	if err != nil {
		return "", fmt.Errorf("cannot send request: %w", err)
	}

	nonce := res.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("missing or empty Replay-Nonce header field")
	}

	return nonce, nil
}
