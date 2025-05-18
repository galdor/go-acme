package main

import (
	"context"

	"go.n16f.net/acme/pkg/acme"
	"go.n16f.net/log"
	"go.n16f.net/program"
)

var (
	p      *program.Program
	client *acme.Client
)

func main() {
	// Program
	p = program.NewProgram("acme", "ACME client")

	p.AddOption("s", "server", "uri", acme.LetsEncryptStagingDirectoryURI,
		"the directory URI of the ACME server")
	p.AddOption("d", "data-store", "path", "acme",
		"the path of the data store directory")
	p.AddOption("c", "contact", "URI", "",
		"the contact URI for the ACME account")
	p.AddOption("u", "upstream-uri", "uri", "",
		"the URI of the server handling non-ACME requests received by the "+
			"HTTP challenge solver")
	p.AddFlag("", "pebble", "use Pebble as ACME server")

	addDirectoryCommand()
	addCertificateCommands()
	addDemoCommand()

	p.ParseCommandLine()

	if p.CommandName() != "help" {
		// Logger
		logger := log.DefaultLogger("acme")
		logger.DebugLevel = p.DebugLevel

		// Data store
		dataStorePath := p.OptionValue("data-store")
		logger.Info("using file system data store at %q", dataStorePath)

		dataStore, err := acme.NewFileSystemDataStore(dataStorePath)
		if err != nil {
			p.Fatal("cannot create data store: %v", err)
		}

		// ACME client
		usePebble := p.IsOptionSet("pebble")

		directoryURI := p.OptionValue("server")
		if usePebble && !p.IsOptionSet("server") {
			directoryURI = acme.PebbleDirectoryURI
		}

		contactURI := p.OptionValue("contact")
		if usePebble && !p.IsOptionSet("contact") {
			contactURI = "mailto:test@example.com"
		}

		clientCfg := acme.ClientCfg{
			Log:          logger,
			DataStore:    dataStore,
			DirectoryURI: directoryURI,
			ContactURIs:  []string{contactURI},
		}

		if usePebble {
			clientCfg.HTTPClient =
				acme.NewHTTPClient(acme.PebbleCACertificatePool())

			clientCfg.HTTPChallengeSolver = &acme.HTTPChallengeSolverCfg{
				Address:     acme.PebbleHTTPChallengeSolverAddress,
				UpstreamURI: p.OptionValue("upstream-uri"),
			}
		}

		client, err = acme.NewClient(clientCfg)
		if err != nil {
			p.Fatal("cannot create client: %v", err)
		}

		if err := client.Start(context.Background()); err != nil {
			p.Fatal("cannot start client: %v", err)
		}
	}

	// Main
	p.Run()
}
