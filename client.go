package acme

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.n16f.net/log"
)

type AccountPrivateKeyGenerationFunc func() (crypto.Signer, error)
type CertificatePrivateKeyGenerationFunc func() (crypto.Signer, error)
type CertificateRenewalTimeFunc func(*CertificateData) time.Time

type ClientCfg struct {
	Log                           *log.Logger                         `json:"-"`
	HTTPClient                    *http.Client                        `json:"-"`
	DataStore                     DataStore                           `json:"-"`
	GenerateAccountPrivateKey     AccountPrivateKeyGenerationFunc     `json:"-"`
	GenerateCertificatePrivateKey CertificatePrivateKeyGenerationFunc `json:"-"`
	CertificateRenewalTime        CertificateRenewalTimeFunc          `json:"-"`

	UserAgent    string   `json:"user_agent"`
	DirectoryURI string   `json:"directory_uri"`
	ContactURIs  []string `json:"contact_uris"`

	HTTPChallengeSolver *HTTPChallengeSolverCfg `json:"http_challenge_solver,omitempty"`
}

type Client struct {
	Cfg       ClientCfg
	Log       *log.Logger
	Directory *Directory

	httpClient          *http.Client
	httpChallengeSolver *HTTPChallengeSolver
	dataStore           DataStore
	accountData         *AccountData

	nonces      []string
	noncesMutex sync.Mutex

	certificates      map[string]*CertificateData
	certificatesMutex sync.RWMutex

	certificateWaiters      map[string][]chan *CertificateData
	certificateWaitersMutex sync.Mutex

	stopChan chan struct{}
	wg       sync.WaitGroup
}

func NewClient(cfg ClientCfg) (*Client, error) {
	if cfg.Log == nil {
		cfg.Log = log.DefaultLogger("acme")
	}

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = NewHTTPClient(nil)
	}

	if cfg.DataStore == nil {
		return nil, fmt.Errorf("missing data store")
	}

	if cfg.GenerateAccountPrivateKey == nil {
		cfg.GenerateAccountPrivateKey = GenerateECDSAP256PrivateKey
	}

	if cfg.GenerateCertificatePrivateKey == nil {
		cfg.GenerateCertificatePrivateKey = GenerateECDSAP256PrivateKey
	}

	if cfg.CertificateRenewalTime == nil {
		cfg.CertificateRenewalTime = CertificateRenewalTime
	}

	if cfg.UserAgent == "" {
		cfg.UserAgent = "go-acme (https://github.com/galdor/go-acme)"
	}

	c := Client{
		Log: cfg.Log,
		Cfg: cfg,

		httpClient: cfg.HTTPClient,
		dataStore:  cfg.DataStore,

		certificates: make(map[string]*CertificateData),

		certificateWaiters: make(map[string][]chan *CertificateData),

		stopChan: make(chan struct{}),
	}

	if sCfg := cfg.HTTPChallengeSolver; sCfg != nil {
		if sCfg.Log == nil {
			sCfg.Log = cfg.Log
		}

		c.httpChallengeSolver = NewHTTPChallengeSolver(*sCfg)
	}

	return &c, nil
}

func (c *Client) Start(ctx context.Context) error {
	if err := c.updateDirectory(ctx); err != nil {
		return fmt.Errorf("cannot update directory: %w", err)
	}

	c.Log.Debug(1, "loading account data")

	accountData, err := c.dataStore.LoadAccountData()
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			accountData, err = c.createAccount(ctx)
			if err != nil {
				return fmt.Errorf("cannot create account: %w", err)
			}

			if err := c.dataStore.StoreAccountData(accountData); err != nil {
				return fmt.Errorf("cannot store account data: %w", err)
			}
		} else {
			return fmt.Errorf("cannot load account data: %w", err)
		}
	}

	c.Log.Data["account"] = accountData.URI
	c.Log.Info("using account %q", accountData.URI)

	c.accountData = accountData

	if c.httpChallengeSolver != nil {
		accountThumbprint, err := accountData.Thumbprint()
		if err != nil {
			return fmt.Errorf("cannot compute account thumbprint: %w", err)
		}

		if err := c.httpChallengeSolver.Start(accountThumbprint); err != nil {
			return fmt.Errorf("cannot start HTTP challenge solver: %w", err)
		}
	}

	return nil
}

func (c *Client) Stop() {
	if c.httpChallengeSolver != nil {
		c.httpChallengeSolver.Stop()
	}

	close(c.stopChan)
	c.wg.Wait()

	c.httpClient.CloseIdleConnections()
}

func (c *Client) storeNonce(nonce string) {
	c.noncesMutex.Lock()
	c.nonces = append(c.nonces, nonce)
	c.noncesMutex.Unlock()
}

func (c *Client) nextNonce(ctx context.Context) (string, error) {
	c.noncesMutex.Lock()
	if len(c.nonces) > 0 {
		nonce := c.nonces[0]
		c.nonces = c.nonces[1:]
		c.noncesMutex.Unlock()
		return nonce, nil
	}
	c.noncesMutex.Unlock()

	nonce, err := c.fetchNonce(ctx)
	if err != nil {
		return "", fmt.Errorf("cannot fetch nonce: %w", err)
	}

	return nonce, nil
}

func (c *Client) waitDelay(res *http.Response) time.Duration {
	defaultDelay := time.Second

	s := res.Header.Get("Retry-After")
	if s == "" {
		return defaultDelay
	}

	// RFC 7231 7.1.3. Retry-After

	i, err := strconv.ParseInt(s, 10, 64)
	if err == nil && i >= 0 {
		return time.Duration(i) * time.Second
	}

	t, err := time.Parse(http.TimeFormat, s)
	if err == nil {
		return time.Until(t)
	}

	return defaultDelay
}

func (c *Client) waitForVerification(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil

	case <-c.stopChan:
		return ErrVerificationInterrupted

	case <-ctx.Done():
		if err := ctx.Err(); errors.Is(err, context.DeadlineExceeded) {
			return ErrVerificationTimeout
		} else {
			return err
		}
	}
}
