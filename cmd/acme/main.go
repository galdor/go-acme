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

	p.AddCommand("directory", "print the content of an ACME directory",
		cmdDirectory)

	p.ParseCommandLine()

	// ACME client
	directoryURI := p.OptionValue("directory")

	clientCfg := acme.ClientCfg{
		DirectoryURI: directoryURI,
	}

	var err error
	client, err = acme.NewClient(clientCfg)
	if err != nil {
		p.Fatal("cannot create client: %v", err)
	}

	// Main
	p.Run()
}
