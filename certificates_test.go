package acme

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestCertificate(t *testing.T) {
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

func TestRequestCertificateNoValidity(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	withTestClient(t,
		func(c *Client) {
			ctx := context.Background()

			name := "test"
			ids := []Identifier{DNSIdentifier("localhost")}
			validity := 0

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

func TestWaitForCertificate(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	dataStorePath := t.TempDir()

	name := "test"
	ids := []Identifier{DNSIdentifier("localhost")}
	validity := 1

	checkEvents := func(eventChan <-chan *CertificateEvent) {
		for ev := range eventChan {
			require.NotNil(ev)
			require.NoError(ev.Error)
		}
	}

	// The first time the certificate is not in the data store.
	withTestClientWithDataStorePath(t, dataStorePath,
		func(c *Client) {
			ctx := context.Background()

			eventChan, err := c.RequestCertificate(ctx, name, ids, validity)
			require.NoError(err)

			go checkEvents(eventChan)

			data := c.WaitForCertificate(ctx, "test")
			require.NotNil(data)

			assert.Equal(name, data.Name)
		})

	// The second time the certificate is already in the data store.
	withTestClientWithDataStorePath(t, dataStorePath,
		func(c *Client) {
			ctx := context.Background()

			eventChan, err := c.RequestCertificate(ctx, name, ids, validity)
			require.NoError(err)

			go checkEvents(eventChan)

			data := c.WaitForCertificate(ctx, "test")
			require.NotNil(data)

			assert.Equal(name, data.Name)
		})
}
