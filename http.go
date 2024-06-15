package acme

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

func newHTTPClient() *http.Client {
	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,

		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		MaxIdleConns: 10,

		IdleConnTimeout: 60 * time.Second,
	}

	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: &transport,
	}

	return &client
}

func (c *Client) sendHTTPRequest(method string, uri string, reqBody, resBody any) (*http.Response, error) {
	var reqBodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("cannot encode request body: %w", err)
		}

		reqBodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, uri, reqBodyReader)
	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}

	req.Header.Set("User-Agent", "go-acme")

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
