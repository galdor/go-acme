package acme

import "testing"

func newTestClient(t *testing.T) *Client {
	return newTestClientWithDataStorePath(t, t.TempDir())
}

func newTestClientWithDataStorePath(t *testing.T, dataStorePath string) *Client {
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

	return client
}
