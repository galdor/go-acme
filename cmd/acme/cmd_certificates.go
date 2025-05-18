package main

import (
	"context"
	"crypto"
	"math"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"go.n16f.net/acme/pkg/acme"
	"go.n16f.net/program"
)

func addCertificateCommands() {
	var c *program.Command

	c = p.AddCommand("order-certificate", "order a new certificate",
		cmdOrderCertificate)

	c.AddOption("v", "validity", "duration", "30",
		"the validity duration of the certificate in days")

	c.AddArgument("name", "the name of the certificate")
	c.AddTrailingArgument("domain",
		"a domain identifier the certificate will be associated with")
}

func cmdOrderCertificate(p *program.Program) {
	name := p.ArgumentValue("name")
	domainIds := p.TrailingArgumentValues("domain")

	validityString := p.OptionValue("validity")
	i64, err := strconv.ParseInt(validityString, 10, 64)
	if err != nil || i64 < 1 || i64 > math.MaxInt32 {
		p.Fatal("invalid validity duration %q", validityString)
	}
	validity := int(i64)

	ids := make([]acme.Identifier, len(domainIds))
	for i, domainId := range domainIds {
		ids[i] = acme.Identifier{
			Type:  acme.IdentifierTypeDNS,
			Value: domainId,
		}
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	eventChan, err := client.RequestCertificate(ctx, name, ids, validity)
	if err != nil {
		p.Fatal("cannot order certificate: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case ev := <-eventChan:
		if ev.Error == nil {
			certData := ev.CertificateData
			p.Info("certificate %q (%s) ready", name,
				certData.LeafCertificateFingerprint(crypto.MD5))
		} else {
			p.Fatal("cannot order certificate: %v", ev.Error)
		}

	case signo := <-sigChan:
		p.Info("\nreceived signal %d (%v)", signo, signo)
		client.Stop()
	}
}
