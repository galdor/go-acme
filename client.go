package acme

import (
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

type PrivateKeyGenerationFunc func() (crypto.Signer, error)

type ClientCfg struct {
	HTTPClient         *http.Client             `json:"-"`
	DataStore          DataStore                `json:"-"`
	GeneratePrivateKey PrivateKeyGenerationFunc `json:"-"`

	UserAgent    string   `json:"user_agent"`
	DirectoryURI string   `json:"directory_uri"`
	ContactURIs  []string `json:"contact_uris"`
}

type Client struct {
	Cfg       ClientCfg
	Directory *Directory

	nonces      []string
	noncesMutex sync.Mutex

	httpClient  *http.Client
	dataStore   DataStore
	accountData *AccountData
	nonceSource *joseNonceSource
}

func NewClient(cfg ClientCfg) (*Client, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = NewHTTPClient(nil)
	}

	if cfg.DataStore == nil {
		return nil, fmt.Errorf("missing data store")
	}

	if cfg.GeneratePrivateKey == nil {
		cfg.GeneratePrivateKey = GenerateECDSAP256PrivateKey
	}

	if cfg.UserAgent == "" {
		cfg.UserAgent = "go-acme"
	}

	c := Client{
		Cfg: cfg,

		httpClient: cfg.HTTPClient,
		dataStore:  cfg.DataStore,
	}

	c.nonceSource = &joseNonceSource{Client: &c}

	if err := c.updateDirectory(); err != nil {
		return nil, fmt.Errorf("cannot update directory: %w", err)
	}

	accountData, err := c.dataStore.LoadAccountData()
	if err != nil {
		if errors.Is(err, ErrNoAccount) {
			accountData, err = c.createAccount()
			if err != nil {
				return nil, fmt.Errorf("cannot create account: %w", err)
			}

			if err := c.dataStore.StoreAccountData(accountData); err != nil {
				return nil, fmt.Errorf("cannot store account data: %w", err)
			}
		} else {
			return nil, fmt.Errorf("cannot load account data: %w", err)
		}
	}
	c.accountData = accountData

	return &c, nil
}

func (c *Client) Stop() {
	c.httpClient.CloseIdleConnections()
}

func (c *Client) storeNonce(nonce string) {
	c.noncesMutex.Lock()
	c.nonces = append(c.nonces, nonce)
	c.noncesMutex.Unlock()
}

func (c *Client) nextNonce() (string, error) {
	c.noncesMutex.Lock()
	if len(c.nonces) > 0 {
		nonce := c.nonces[0]
		c.nonces = c.nonces[1:]
		return nonce, nil
	}
	c.noncesMutex.Unlock()

	nonce, err := c.fetchNonce()
	if err != nil {
		return "", fmt.Errorf("cannot fetch nonce: %w", err)
	}

	return nonce, nil
}
