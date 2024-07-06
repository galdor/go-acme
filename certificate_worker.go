package acme

import (
	"context"
	"fmt"
	"time"
)

type OrderWorker struct {
	Log    Logger
	Client *Client

	ctx            context.Context
	certData       *CertificateData
	orderURI       string
	certificateURI string
	resultChan     chan *CertificateRequestResult
}

func newCertificateRequestError(err error) *CertificateRequestResult {
	return &CertificateRequestResult{Error: err}
}

func (c *Client) startOrderWorker(ctx context.Context, certData *CertificateData, resultChan chan *CertificateRequestResult) {
	w := OrderWorker{
		Log:    c.Log,
		Client: c,

		ctx:        ctx,
		certData:   certData,
		resultChan: resultChan,
	}

	c.wg.Add(1)
	go w.main()
}

func (w *OrderWorker) main() {
	defer w.Client.wg.Done()
	defer close(w.resultChan)

	defer func() {
		if v := recover(); v != nil {
			msg := recoverValueString(v)
			trace := stackTrace(2, 20)

			w.Log.Error("panic: %s\n%s", msg, trace)
			err := fmt.Errorf("panic: %s", msg)

			w.sendResult(newCertificateRequestError(err))
		}
	}()

	if err := w.submitOrder(); err != nil {
	}

	if err := w.validateAuthorizations(); err != nil {
		w.fatalError(err)
		return
	}

	if err := w.finalizeOrder(); err != nil {
		w.fatalError(err)
		return
	}

	if err := w.downloadCertificate(); err != nil {
		w.fatalError(err)
		return
	}

	res := CertificateRequestResult{CertificateData: w.certData}
	w.sendResult(&res)
}

func (w *OrderWorker) sendResult(res *CertificateRequestResult) {
	w.resultChan <- res
}

func (w *OrderWorker) fatalError(err error) {
	w.Log.Error("%v", err)
	w.sendResult(newCertificateRequestError(err))
}

func (w *OrderWorker) submitOrder() error {
	now := time.Now()
	notBefore := now
	notAfter := now.AddDate(0, 0, w.certData.Validity)

	newOrder := NewOrder{
		Identifiers: w.certData.Identifiers,
		NotBefore:   &notBefore,
		NotAfter:    &notAfter,
	}

	orderURI, err := w.Client.submitOrder(w.ctx, &newOrder)
	if err != nil {
		return err
	}

	w.orderURI = orderURI
	return nil
}

func (w *OrderWorker) validateAuthorizations() error {
	order, err := w.Client.fetchOrder(w.ctx, w.orderURI)
	if err != nil {
		return fmt.Errorf("cannot fetch order: %w", err)
	}

	for _, authURI := range order.Authorizations {
		auth, err := w.Client.fetchAuthorization(w.ctx, authURI)
		if err != nil {
			return fmt.Errorf("cannot fetch authorization: %w", err)
		}

		if err := w.validateAuthorization(authURI, auth); err != nil {
			return fmt.Errorf("cannot validate authorization %q: %w",
				auth.Identifier, err)
		}
	}

	return nil
}

func (w *OrderWorker) validateAuthorization(authURI string, auth *Authorization) error {
	w.Log.Info("validating authorization %q", auth.Identifier)

	challenge := w.Client.selectAuthorizationChallenge(auth)
	if challenge == nil {
		return fmt.Errorf("no supported challenge available")
	}

	if err := w.solveChallenge(challenge, auth); err != nil {
		return fmt.Errorf("cannot solve challenge: %w", err)
	}

	if err := w.Client.waitForAuthorizationValid(w.ctx, authURI); err != nil {
		return err
	}

	w.Log.Info("authorization %q ready", auth.Identifier)

	return nil
}

func (w *OrderWorker) solveChallenge(challenge *Challenge, auth *Authorization) error {
	w.Log.Info("solving challenge %q for authorization %q",
		challenge.Type, auth.Identifier)

	if err := w.Client.setupChallenge(w.ctx, challenge); err != nil {
		return err
	}

	defer func() {
		if err := w.Client.cleanupChallenge(w.ctx, challenge); err != nil {
			w.Log.Error("cannot cleanup challenge: %v", err)
		}
	}()

	if err := w.Client.submitChallenge(w.ctx, challenge.URL); err != nil {
		return fmt.Errorf("cannot submit challenge: %w", err)
	}

	if err := w.Client.waitForChallengeValid(w.ctx, challenge.URL); err != nil {
		return err
	}

	w.Log.Info("challenge %q solved", challenge.Type)

	return nil
}

func (w *OrderWorker) finalizeOrder() error {
	w.Log.Info("finalizing order")

	order, err := w.Client.waitForOrderReady(w.ctx, w.orderURI)
	if err != nil {
		return err
	}

	w.Log.Info("order ready")

	privateKey, err := w.Client.Cfg.GenerateCertificatePrivateKey()
	if err != nil {
		return fmt.Errorf("cannot generate private key: %w", err)
	}
	w.certData.PrivateKey = privateKey

	csr, err := w.Client.generateCSR(w.certData.Identifiers, privateKey)
	if err != nil {
		return fmt.Errorf("cannot generate certificate request: %w", err)
	}

	order, err = w.Client.finalizeOrder(w.ctx, order.Finalize, csr)
	if err != nil {
		return err
	}

	w.Log.Info("order finalized")

	order, err = w.Client.waitForOrderValid(w.ctx, w.orderURI)
	if err != nil {
		return err
	}

	if order.Certificate == nil {
		return fmt.Errorf("valid order does not contain a certificate URI")
	}

	w.certificateURI = *order.Certificate

	return nil
}

func (w *OrderWorker) downloadCertificate() error {
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
