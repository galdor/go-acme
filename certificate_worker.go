package acme

import (
	"context"
	"fmt"
	"time"

	"go.n16f.net/log"
)

type CertificateWorker struct {
	Log    *log.Logger
	Client *Client

	ctx            context.Context
	certData       *CertificateData
	orderURI       string
	certificateURI string
	eventChan      chan *CertificateEvent
}

func (c *Client) startCertificateWorker(ctx context.Context, certData *CertificateData, eventChan chan *CertificateEvent) {
	logData := log.Data{
		"certificate": certData.Name,
	}

	log := c.Log.Child("cert_worker", logData)

	w := CertificateWorker{
		Log:    log,
		Client: c,

		ctx:       ctx,
		certData:  certData,
		eventChan: eventChan,
	}

	c.wg.Add(1)
	go w.main()
}

func (w *CertificateWorker) main() {
	defer w.Client.wg.Done()
	defer close(w.eventChan)

	defer func() {
		if v := recover(); v != nil {
			msg := recoverValueString(v)
			trace := stackTrace(2, 20)

			w.Log.Error("panic: %s\n%s", msg, trace)
			err := fmt.Errorf("panic: %s", msg)

			w.sendEvent(&CertificateEvent{Error: err})
		}
	}()

	renewalTime := time.Now()

	if w.certData.ContainsCertificate() {
		renewalTime = w.Client.Cfg.CertificateRenewalTime(w.certData)

		// If we already have a certificate (loaded from the data store), signal
		// its existence immediately.
		w.onCertificateDataReady()
	}

	for {
		now := time.Now()
		if renewalTime.After(now) {
			w.Log.Info("waiting until %v for renewal",
				renewalTime.Format(time.RFC3339))

			if !w.wait(renewalTime.Sub(now)) {
				return
			}
		}

		// Order a new certificate, retrying regularly if something goes wrong.
		retryDelay := time.Second

	retryLoop:
		for {
			if err := w.orderCertificate(); err != nil {
				// If we cannot obtain a certificate and we do not have one,
				// stop right now: if we are trying to start a server, we cannot
				// do anything until we have this first certificate.
				if !w.certData.ContainsCertificate() {
					w.sendError(err)
					return
				}

				w.Log.Debug(1, "retrying in %v", retryDelay)
				if !w.wait(retryDelay) {
					return
				}

				retryDelay = min(retryDelay*2, 60*time.Second)
				continue retryLoop
			}

			break
		}

		renewalTime = w.Client.Cfg.CertificateRenewalTime(w.certData)

		w.onCertificateDataReady()
	}
}

func (w *CertificateWorker) wait(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-t.C:
		return true
	case <-w.Client.stopChan:
		return false
	case <-w.ctx.Done():
		return false
	}
}

func (w *CertificateWorker) sendEvent(res *CertificateEvent) {
	select {
	case w.eventChan <- res:
	case <-w.Client.stopChan:
	case <-w.ctx.Done():
	}
}

func (w *CertificateWorker) sendError(err error) {
	w.Log.Error("%v", err)
	w.sendEvent(&CertificateEvent{Error: err})
}

func (w *CertificateWorker) onCertificateDataReady() {
	// Create the final certificate data structure, store in the client and send
	// it as an event.
	//
	// Remember that once we have called extractCopy(), w.certData does not
	// contain a certificate chain anymore.

	certData := w.certData.extractCopy()

	w.Client.storeCertificate(certData)
	w.sendEvent(&CertificateEvent{CertificateData: certData})
}

func (w *CertificateWorker) orderCertificate() error {
	w.Log.Info("submitting order")

	newOrder := NewOrder{
		Identifiers: w.certData.Identifiers,
	}

	if w.certData.Validity != 0 {
		now := time.Now()

		notBefore := now
		newOrder.NotBefore = &notBefore

		notAfter := now.AddDate(0, 0, w.certData.Validity)
		newOrder.NotAfter = &notAfter
	}

	orderURI, err := w.Client.submitOrder(w.ctx, &newOrder)
	if err != nil {
		return err
	}

	w.orderURI = orderURI

	w.Log.Debug(1, "created order %q", w.orderURI)

	return w.validateAuthorizations()
}

func (w *CertificateWorker) validateAuthorizations() error {
	order, _, err := w.Client.fetchOrder(w.ctx, w.orderURI)
	if err != nil {
		return fmt.Errorf("cannot fetch order: %w", err)
	}

	for _, authURI := range order.Authorizations {
		auth, _, err := w.Client.fetchAuthorization(w.ctx, authURI)
		if err != nil {
			return fmt.Errorf("cannot fetch authorization: %w", err)
		}

		if err := w.validateAuthorization(authURI, auth); err != nil {
			return fmt.Errorf("cannot validate authorization %q: %w",
				auth.Identifier, err)
		}
	}

	return w.finalizeOrder()
}

func (w *CertificateWorker) validateAuthorization(authURI string, auth *Authorization) error {
	w.Log.Info("validating authorization %q", auth.Identifier)

	challenge := w.Client.selectAuthorizationChallenge(auth)
	if challenge == nil {
		return fmt.Errorf("no supported challenge available")
	}

	if challenge.Status == ChallengeStatusValid {
		// If the challenge has already been validated with a previous order,
		// there is no need to go through it again.
		return nil
	}

	if err := w.solveChallenge(challenge, auth); err != nil {
		return fmt.Errorf("cannot solve challenge: %w", err)
	}

	if err := w.Client.waitForAuthorizationValid(w.ctx, authURI); err != nil {
		return err
	}

	w.Log.Debug(1, "authorization %q ready", auth.Identifier)

	return nil
}

func (w *CertificateWorker) solveChallenge(challenge *Challenge, auth *Authorization) error {
	w.Log.Info("solving challenge %q for authorization %q",
		challenge.Type, auth.Identifier)

	if err := w.Client.setupChallenge(w.ctx, challenge); err != nil {
		return err
	}

	defer func() {
		if err := w.Client.teardownChallenge(w.ctx, challenge); err != nil {
			w.Log.Error("cannot teardown challenge: %v", err)
		}
	}()

	if err := w.Client.submitChallenge(w.ctx, challenge.URL); err != nil {
		return fmt.Errorf("cannot submit challenge: %w", err)
	}

	if err := w.Client.waitForChallengeValid(w.ctx, challenge.URL); err != nil {
		return err
	}

	w.Log.Debug(1, "challenge %q solved", challenge.Type)

	return nil
}

func (w *CertificateWorker) finalizeOrder() error {
	w.Log.Info("finalizing order")

	order, err := w.Client.waitForOrderReady(w.ctx, w.orderURI)
	if err != nil {
		return err
	}

	w.Log.Debug(1, "order ready")

	if w.certData.PrivateKey == nil {
		privateKey, err := w.Client.Cfg.GenerateCertificatePrivateKey()
		if err != nil {
			return fmt.Errorf("cannot generate private key: %w", err)
		}
		w.certData.PrivateKey = privateKey
	}

	csr, err := w.Client.generateCSR(w.certData.Identifiers,
		w.certData.PrivateKey)
	if err != nil {
		return fmt.Errorf("cannot generate certificate request: %w", err)
	}

	order, err = w.Client.finalizeOrder(w.ctx, order.Finalize, csr)
	if err != nil {
		return err
	}

	w.Log.Debug(1, "order finalized")

	order, err = w.Client.waitForOrderValid(w.ctx, w.orderURI)
	if err != nil {
		return err
	}

	w.Log.Debug(1, "order valid")

	if order.Certificate == nil {
		return fmt.Errorf("valid order does not contain a certificate URI")
	}

	w.certificateURI = *order.Certificate

	return w.downloadCertificate()
}

func (w *CertificateWorker) downloadCertificate() error {
	w.Log.Info("downloading certificate")

	cert, err := w.Client.downloadCertificate(w.ctx, w.certificateURI)
	if err != nil {
		return err
	}

	w.certData.Certificate = cert

	dataStore := w.Client.Cfg.DataStore
	if err := dataStore.StoreCertificateData(w.certData); err != nil {
		return fmt.Errorf("cannot store certificate data: %w", err)
	}

	return nil
}
