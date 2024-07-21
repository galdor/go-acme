package acme

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateCreation(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	withTestClient(t,
		func(c *Client) {
			ctx := context.Background()

			name := "test"
			ids := []Identifier{DNSIdentifier("localhost")}
			validity := 1

			eventChan, err := c.RequestCertificate(ctx, name, ids, validity)
			require.NoError(err)

			ev := <-eventChan

			require.NotNil(ev)
			require.NoError(ev.Error)

			data := ev.CertificateData

			assert.Equal(name, data.Name)
			assert.Equal(ids, data.Identifiers)
			assert.Equal(validity, data.Validity)
			assert.Greater(len(data.Certificate), 0)
			assert.NotNil(data.PrivateKey)
		})
}
