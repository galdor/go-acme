package acme

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccountManagement(t *testing.T) {
	require := require.New(t)

	var accountData *AccountData

	dataStorePath := t.TempDir()

	// Create a client, automatically creating a new account.
	withTestClientWithDataStorePath(t, dataStorePath,
		func(c *Client) {
			accountData = c.accountData
		})

	// Create a new client on the same data store, loading the account
	// referenced in it.
	withTestClientWithDataStorePath(t, dataStorePath,
		func(c *Client) {
			require.Equal(accountData.URI, c.accountData.URI)
		})
}
