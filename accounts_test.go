package acme

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccountManagement(t *testing.T) {
	require := require.New(t)

	var client *Client
	var accountData *AccountData

	dataStorePath := t.TempDir()

	// Create a client, automatically creating a new account.
	client = newTestClientWithDataStorePath(t, dataStorePath)
	accountData = client.accountData

	// Create a new client on the same data store, loading the account
	// referenced in it.
	client = newTestClientWithDataStorePath(t, dataStorePath)
	require.Equal(accountData.URI, client.accountData.URI)
}
