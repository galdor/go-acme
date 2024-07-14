package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"go.n16f.net/acme"
	"go.n16f.net/log"
	"go.n16f.net/program"
)

func addDemoCommand() {
	var c *program.Command

	c = p.AddCommand("demo", "start an HTTP server acting as demonstration",
		cmdDemo)

	c.AddOption("a", "address", "address", ":8080",
		"the address to listen on formatted as \"<host>:<port>\"")
	c.AddOption("", "hostname", "hostname", "localhost",
		"the DNS name of the server")
}

func cmdDemo(p *program.Program) {
	addr := p.OptionValue("address")
	hostname := p.OptionValue("hostname")

	// Request a certificate
	ctx := context.Background()

	ids := []acme.Identifier{{Type: acme.IdentifierTypeDNS, Value: hostname}}

	eventChan, err := client.RequestCertificate(ctx, "demo", ids, 1)
	if err != nil {
		p.Fatal("cannot order certificate: %v", err)
	}

	var certValue atomic.Value // *acme.CertificateData

	var readyWg sync.WaitGroup
	readyWg.Add(1)

	go func() {
		for ev := range eventChan {
			if ev.Error != nil {
				p.Fatal("cannot order certificate: %v", ev.Error)
			}

			if certValue.Swap(ev.CertificateData) == nil {
				readyWg.Done()
			}
		}
	}()

	getCertificate := func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		certData := certValue.Load().(*acme.CertificateData)
		return certData.TLSCertificate(), nil
	}

	// Create an HTTP server
	tlsCfg := tls.Config{
		GetCertificate: getCertificate,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, "Hello world!\n")
	})

	logger := log.DefaultLogger("http_server")

	server := http.Server{
		Addr:      addr,
		TLSConfig: &tlsCfg,
		Handler:   mux,
		ErrorLog:  logger.StdLogger(log.LevelError),
	}

	// Wait for a certificate and start the HTTP server
	readyWg.Wait()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		p.Fatal("cannot listen on %q: %v", addr, err)
	}

	p.Info("listening on %q", addr)

	go func() {
		if err := server.ServeTLS(listener, "", ""); err != http.ErrServerClosed {
			p.Fatal("cannot run HTTP server: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	signo := <-sigChan
	p.Info("\nreceived signal %d (%v)", signo, signo)

	client.Stop()
	server.Shutdown(ctx)
}
