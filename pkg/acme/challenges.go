package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var ErrVerificationInterrupted = errors.New("verification interrupted")
var ErrVerificationTimeout = errors.New("verification timeout")

type ChallengeType string

const (
	ChallengeTypeHTTP01 ChallengeType = "http-01"
	ChallengeTypeDNS01  ChallengeType = "dns-01"
)

type ChallengeStatus string

const (
	ChallengeStatusPending    ChallengeStatus = "pending"
	ChallengeStatusProcessing ChallengeStatus = "processing"
	ChallengeStatusValid      ChallengeStatus = "valid"
	ChallengeStatusInvalid    ChallengeStatus = "invalid"
)

type Challenge struct {
	Type      ChallengeType   `json:"type"`
	URL       string          `json:"url"`
	Status    ChallengeStatus `json:"status"`
	Validated *time.Time      `json:"validated,omitempty"`
	Error     *ProblemDetails `json:"error,omitempty"`

	Data any `json:"-"`
}

type ChallengeDataHTTP01 struct {
	Token string `json:"token"`
}

type ChallengeDataDNS01 struct {
	Token string `json:"token"`
}

func (c *Challenge) UnmarshalJSON(data []byte) error {
	type Challenge2 Challenge

	var c2 Challenge2
	if err := json.Unmarshal(data, &c2); err != nil {
		return err
	}

	switch c2.Type {
	case ChallengeTypeHTTP01:
		c2.Data = &ChallengeDataHTTP01{}
	case ChallengeTypeDNS01:
		c2.Data = &ChallengeDataDNS01{}
	}

	if c2.Data != nil {
		if err := json.Unmarshal(data, &c2.Data); err != nil {
			return err
		}
	}

	*c = Challenge(c2)
	return nil
}

func (c *Client) setupChallenge(ctx context.Context, challenge *Challenge) error {
	var err error

	switch challenge.Type {
	case ChallengeTypeHTTP01:
		err = c.setupChallengeHTTP01(ctx, challenge)
	case ChallengeTypeDNS01:
		err = c.setupChallengeDNS01(ctx, challenge)
	default:
		err = fmt.Errorf("unknown challenge type %q", challenge.Type)
	}

	return err
}

func (c *Client) teardownChallenge(ctx context.Context, challenge *Challenge) error {
	var err error

	switch challenge.Type {
	case ChallengeTypeHTTP01:
		err = c.teardownChallengeHTTP01(ctx, challenge)
	case ChallengeTypeDNS01:
		err = c.teardownChallengeDNS01(ctx, challenge)
	default:
		err = fmt.Errorf("unknown challenge type %q", challenge.Type)
	}

	return err
}

func (c *Client) setupChallengeHTTP01(ctx context.Context, challenge *Challenge) error {
	data := challenge.Data.(*ChallengeDataHTTP01)
	c.httpChallengeSolver.addToken(data.Token)
	return nil
}

func (c *Client) teardownChallengeHTTP01(ctx context.Context, challenge *Challenge) error {
	data := challenge.Data.(*ChallengeDataHTTP01)
	c.httpChallengeSolver.discardToken(data.Token)
	return nil
}

func (c *Client) setupChallengeDNS01(ctx context.Context, challenge *Challenge) error {
	// TODO Solve DNS-01 challenges
	return errors.New("not implemented yet")
}

func (c *Client) teardownChallengeDNS01(ctx context.Context, challenge *Challenge) error {
	// TODO Solve DNS-01 challenges
	return errors.New("not implemented yet")
}

func (c *Client) submitChallenge(ctx context.Context, uri string) error {
	// Yes we want to send an empty JSON object. Yes this is a ridiculously
	// unintuitive interface.
	_, err := c.sendRequest(ctx, "POST", uri, struct{}{}, nil)
	return err
}

func (c *Client) fetchChallenge(ctx context.Context, uri string) (*Challenge, *http.Response, error) {
	var challenge Challenge

	res, err := c.sendRequest(ctx, "POST", uri, nil, &challenge)
	if err != nil {
		return nil, nil, err
	}

	return &challenge, res, nil
}

func (c *Client) waitForChallengeValid(ctx context.Context, uri string) error {
	for {
		challenge, res, err := c.fetchChallenge(ctx, uri)
		if err != nil {
			return fmt.Errorf("cannot fetch challenge: %w", err)
		}

		delay := c.waitDelay(res)

		switch challenge.Status {
		case ChallengeStatusPending:

		case ChallengeStatusProcessing:

		case ChallengeStatusValid:
			return nil

		case ChallengeStatusInvalid:
			if challenge.Error != nil {
				return challenge.Error
			}
			return errors.New("unknown error")

		default:
			return fmt.Errorf("unknown challenge status %q", challenge.Status)
		}

		if err := c.waitForVerification(ctx, delay); err != nil {
			return err
		}
	}
}
