package acme

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type AuthorizationStatus string

const (
	AuthorizationStatusPending     AuthorizationStatus = "pending"
	AuthorizationStatusValid       AuthorizationStatus = "valid"
	AuthorizationStatusInvalid     AuthorizationStatus = "invalid"
	AuthorizationStatusDeactivated AuthorizationStatus = "deactivated"
	AuthorizationStatusExpired     AuthorizationStatus = "expired"
	AuthorizationStatusRevoked     AuthorizationStatus = "revoked"
)

type Authorization struct {
	Identifier Identifier          `json:"identifier"`
	Status     AuthorizationStatus `json:"status"`
	Expires    *time.Time          `json:"expires,omitempty"`
	Challenges []*Challenge        `json:"challenges"`
	Wildcard   bool                `json:"wildcard,omitempty"`
}

func (a *Authorization) findChallenge(cType ChallengeType) *Challenge {
	for _, c := range a.Challenges {
		if c.Type == cType {
			return c
		}
	}

	return nil
}

func (c *Client) fetchAuthorization(ctx context.Context, uri string) (*Authorization, *http.Response, error) {
	var auth Authorization

	res, err := c.sendRequest(ctx, "POST", uri, nil, &auth)
	if err != nil {
		return nil, nil, err
	}

	return &auth, res, nil
}

func (c *Client) selectAuthorizationChallenge(auth *Authorization) *Challenge {
	if c.httpChallengeSolver != nil {
		if ch := auth.findChallenge(ChallengeTypeHTTP01); ch != nil {
			return ch
		}
	}

	return auth.findChallenge(ChallengeTypeDNS01)
}

func (c *Client) waitForAuthorizationValid(ctx context.Context, uri string) error {
	for {
		auth, res, err := c.fetchAuthorization(ctx, uri)
		if err != nil {
			return fmt.Errorf("cannot fetch authorization: %w", err)
		}

		delay := c.waitDelay(res)

		switch auth.Status {
		case AuthorizationStatusPending:

		case AuthorizationStatusValid:
			return nil

		case AuthorizationStatusInvalid:
			return errors.New("authorization failure")

		case AuthorizationStatusDeactivated:
			return errors.New("authorization deactivated")

		case AuthorizationStatusExpired:
			return errors.New("authorization expired")

		case AuthorizationStatusRevoked:
			return errors.New("authorization revoked")

		default:
			return fmt.Errorf("unknown authorization status %q", auth.Status)
		}

		if err := c.waitForVerification(ctx, delay); err != nil {
			return err
		}
	}
}
