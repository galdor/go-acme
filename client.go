package acme

import (
	"fmt"
	"net/http"
)

type ClientCfg struct {
	HTTPClient *http.Client `json:"-"`

	DirectoryURI string `json:"directory_uri"`
}

type Client struct {
	Cfg ClientCfg

	Directory *Directory

	httpClient *http.Client
}

func NewClient(cfg ClientCfg) (*Client, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = NewHTTPClient(nil)
	}

	c := Client{
		Cfg: cfg,

		httpClient: cfg.HTTPClient,
	}

	if err := c.updateDirectory(); err != nil {
		return nil, fmt.Errorf("cannot update directory: %w", err)
	}

	return &c, nil
}

func (c *Client) Stop() {
	c.httpClient.CloseIdleConnections()
}
