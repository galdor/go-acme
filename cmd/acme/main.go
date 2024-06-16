package main

import (
	"github.com/galdor/go-acme"
	"github.com/galdor/go-program"
)

var (
	p      *program.Program
	client *acme.Client
)

func main() {
	// Program
	p = program.NewProgram("acme", "ACME client")

	p.AddOption("d", "directory", "uri", acme.LetsEncryptStagingDirectoryURI,
		"the URI of the ACME directory")
	p.AddFlag("", "pebble", "use Pebble as ACME server")

	p.AddCommand("directory", "print the content of an ACME directory",
		cmdDirectory)

	p.ParseCommandLine()

	// ACME client
	usePebble := p.IsOptionSet("pebble")

	directoryURI := p.OptionValue("directory")
	if usePebble && !p.IsOptionSet("directory") {
		directoryURI = acme.PebbleDirectoryURI
	}

	p.Info("using ACME directory %q", directoryURI)

	clientCfg := acme.ClientCfg{
		DirectoryURI: directoryURI,
	}

	if usePebble {
		clientCfg.HTTPClient =
			acme.NewHTTPClient(acme.PebbleCACertificatePool())
	}

	var err error
	client, err = acme.NewClient(clientCfg)
	if err != nil {
		p.Fatal("cannot create client: %v", err)
	}

	// Main
	p.Run()
}
