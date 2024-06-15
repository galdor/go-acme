package acme

import "bytes"

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
	Title    string `json:"title"`
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
		buf.WriteString(": ")
	}

	buf.WriteString(err.Title)

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
