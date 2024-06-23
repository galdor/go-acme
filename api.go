package acme

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

type APIError struct {
	// RFC 7807 3.1. Members of a Problem Details Object
	Type     string `json:"type,omitempty"`
	Title    string `json:"title,omitempty"`
	Status   int    `json:"status,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`

	// RFC 8555 6.7.1. Subproblems
	Subproblems []APIError `json:"subproblems,omitempty"`
}

func (err *APIError) FormatErrorString(buf *bytes.Buffer, indent string) {
	if err.Type != "" {
		buf.WriteString(indent)
		buf.WriteString(err.Type)
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

func (err *APIError) Error() string {
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

func (c *Client) sendRequest(method string, uri string, reqBody, resBody any) (*http.Response, error) {
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
		signedData, err := c.signPayload(reqBodyData)
		if err != nil {
			return nil, fmt.Errorf("cannot sign request body data: %w", err)
		}

		reqBodyReader = bytes.NewReader(signedData)
	}

	req, err := http.NewRequest(method, uri, reqBodyReader)
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

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return res, fmt.Errorf("cannot read response body: %w", err)
	}

	status := res.StatusCode

	if status < 200 || status > 300 {
		var apiErr APIError
		if err := json.Unmarshal(data, &apiErr); err == nil {
			return res, &apiErr
		}

		return res, fmt.Errorf("request failed with status %d: %s",
			status, data)
	}

	if resBody != nil {
		if err := json.Unmarshal(data, resBody); err != nil {
			return res, fmt.Errorf("cannot decode response body: %w", err)
		}
	}

	return res, nil
}

func (c *Client) fetchNonce() (string, error) {
	res, err := c.sendRequest("HEAD", c.Directory.NewNonce, nil, nil)
	if err != nil {
		return "", fmt.Errorf("cannot send request: %w", err)
	}

	// XXX Soon will be unecessary: we want sendRequest to call storeNonce on
	// its own. That means that Client.nextOnce should call fetchNonce in a loop
	// until a nonce is available in the slice (there could be multiple
	// concurrent calls consuming nonces).

	nonce := res.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("missing or empty Replay-Nonce header field")
	}

	return nonce, nil
}
