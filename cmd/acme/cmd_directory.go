package main

import (
	"strings"

	"go.n16f.net/program"
)

func addDirectoryCommand() {
	p.AddCommand("directory", "print the content of an ACME directory",
		cmdDirectory)
}

func cmdDirectory(p *program.Program) {
	d := client.Directory

	t := program.NewKeyValueTable()

	t.AddRow("new nonce URI", d.NewNonce)
	t.AddRow("new account URI", d.NewAccount)
	t.AddRow("new order URI", d.NewOrder)
	t.AddRow("new authorization URI", d.NewAuthz)
	t.AddRow("revoke certificate URI", d.RevokeCert)
	t.AddRow("key change URI", d.KeyChange)
	t.AddRow("terms of service URI", d.Meta.TermsOfService)
	t.AddRow("website", d.Meta.Website)
	t.AddRow("CAA identities", strings.Join(d.Meta.CAAIdentities, "\n"))
	t.AddRow("external account required", d.Meta.ExternalAccountRequired)

	t.Print()
}
