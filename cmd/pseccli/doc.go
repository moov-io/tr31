package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/moov-io/psec"
)

func help() {
	fmt.Printf(strings.TrimSpace(`
pseccli is a tool for two convenient functions to wrap and unwrap TR-31 key block.

USAGE
   pseccli [-v] [-algorithm] [-ik] [-tk] [-ep] [-dp] [-gm] [-en] [-de]

EXAMPLES
  pseccli -v          Print the version of dukptcli (Example: %s)
  pseccli -algorithm  Data encryption algorithm (options: des, aes)
  pseccli -ik         Derive initial key from base derivative key and key serial number (or initial key id)
  pseccli -tk         Derive transaction key (current transaction key) from initial key and key serial number
  pseccli -ep         Encrypt pin block using dukpt transaction key
  pseccli -dp         Decrypt pin block using dukpt transaction key
  pseccli -gm         Generate mac using dukpt transaction key
  pseccli -en         Encrypt data using dukpt transaction key
  pseccli -de         Decrypt data using dukpt transaction key

FLAGS
`), dukpt.Version)
	fmt.Println("")
	flag.PrintDefaults()
}
