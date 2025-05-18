package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type OrderStatus string

const (
	OrderStatusPending    OrderStatus = "pending"
	OrderStatusReady      OrderStatus = "ready"
	OrderStatusProcessing OrderStatus = "processing"
	OrderStatusValid      OrderStatus = "valid"
	OrderStatusInvalid    OrderStatus = "invalid"
)

type IdentifierType string

const (
	IdentifierTypeDNS IdentifierType = "dns"
)

type Identifier struct {
	Type  IdentifierType `json:"type"`
	Value string         `json:"value"`
}

func DNSIdentifier(value string) Identifier {
	return Identifier{Type: IdentifierTypeDNS, Value: value}
}

func (id Identifier) String() string {
	return fmt.Sprintf("%s:%s", id.Type, id.Value)
}

type NewOrder struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   *time.Time   `json:"notBefore,omitempty"`
	NotAfter    *time.Time   `json:"notAfter,omitempty"`
}

type Order struct {
	Status         OrderStatus     `json:"status"`
	Expires        time.Time       `json:"expires"`
	Identifiers    []Identifier    `json:"identifiers"`
	NotBefore      *time.Time      `json:"notBefore,omitempty"`
	NotAfter       *time.Time      `json:"notAfter,omitempty"`
	Error          *ProblemDetails `json:"error,omitempty"`
	Authorizations []string        `json:"authorizations"`
	Finalize       string          `json:"finalize"`
	Certificate    *string         `json:"certificate,omitempty"`
}

type OrderFinalization struct {
	CSR string `json:"csr"`
}

func (c *Client) submitOrder(ctx context.Context, newOrder *NewOrder) (string, error) {
	c.Log.Debug(1, "creating order")

	res, err := c.sendRequest(ctx, "POST", c.Directory.NewOrder, &newOrder, nil)
	if err != nil {
		return "", err
	}

	location := res.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("missing or empty Location header field")
	}

	return location, nil
}

func (c *Client) fetchOrder(ctx context.Context, uri string) (*Order, *http.Response, error) {
	var order Order

	res, err := c.sendRequest(ctx, "POST", uri, nil, &order)
	if err != nil {
		return nil, nil, err
	}

	return &order, res, nil
}

func (c *Client) waitForOrderReady(ctx context.Context, uri string) (*Order, error) {
	for {
		order, res, err := c.fetchOrder(ctx, uri)
		if err != nil {
			return nil, fmt.Errorf("cannot fetch order: %w", err)
		}

		delay := c.waitDelay(res)

		switch order.Status {
		case OrderStatusPending:

		case OrderStatusReady:
			return order, nil

		case OrderStatusProcessing:
			return nil, fmt.Errorf("unexpected order status %q", order.Status)

		case OrderStatusValid:
			return nil, fmt.Errorf("unexpected order status %q", order.Status)

		case OrderStatusInvalid:
			if order.Error != nil {
				return nil, order.Error
			}
			return nil, errors.New("unknown error")

		default:
			return nil, fmt.Errorf("unknown order status %q", order.Status)
		}

		if err := c.waitForVerification(ctx, delay); err != nil {
			return nil, err
		}
	}
}

func (c *Client) waitForOrderValid(ctx context.Context, uri string) (*Order, error) {
	for {
		order, res, err := c.fetchOrder(ctx, uri)
		if err != nil {
			return nil, fmt.Errorf("cannot fetch order: %w", err)
		}

		delay := c.waitDelay(res)

		switch order.Status {
		case OrderStatusPending:
			return nil, fmt.Errorf("unexpected order status %q", order.Status)

		case OrderStatusReady:

		case OrderStatusProcessing:

		case OrderStatusValid:
			return order, nil

		case OrderStatusInvalid:
			if order.Error != nil {
				return nil, order.Error
			}
			return nil, errors.New("unknown error")

		default:
			return nil, fmt.Errorf("unknown order status %q", order.Status)
		}

		if err := c.waitForVerification(ctx, delay); err != nil {
			return nil, err
		}
	}
}

func (c *Client) finalizeOrder(ctx context.Context, uri string, csr []byte) (*Order, error) {
	encodedCSR := base64.RawURLEncoding.EncodeToString(csr)

	payload := OrderFinalization{
		CSR: encodedCSR,
	}

	var order Order
	if _, err := c.sendRequest(ctx, "POST", uri, &payload, &order); err != nil {
		return nil, err
	}

	return &order, nil
}

func (c *Client) downloadCertificate(ctx context.Context, uri string) ([]*x509.Certificate, error) {
	var data []byte
	if _, err := c.sendRequest(ctx, "POST", uri, nil, &data); err != nil {
		return nil, err
	}

	chain, err := decodePEMCertificateChain(data)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate chain: %w", err)
	}

	return chain, nil
}
