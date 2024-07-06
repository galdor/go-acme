package acme

import (
	"context"
	"testing"
)

func withTestClient(t *testing.T, fn func(c *Client)) {
	withTestClientWithDataStorePath(t, t.TempDir(), fn)
}

func withTestClientWithDataStorePath(t *testing.T, dataStorePath string, fn func(c *Client)) {
	dataStore, err := NewFileSystemDataStore(dataStorePath)
	if err != nil {
		t.Fatalf("cannot create data store: %v", err)
	}

	clientCfg := ClientCfg{
		DataStore:    dataStore,
		DirectoryURI: PebbleDirectoryURI,
		ContactURIs:  []string{"mailto:test@example.com"},
	}

	clientCfg.HTTPClient = NewHTTPClient(PebbleCACertificatePool())

	client, err := NewClient(clientCfg)
	if err != nil {
		t.Fatalf("cannot create client: %v", err)
	}

	if err := client.Start(context.Background()); err != nil {
		t.Fatalf("cannot start client: %v", err)
	}

	defer client.Stop()

	fn(client)
}
