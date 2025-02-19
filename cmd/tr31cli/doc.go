package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/moov-io/tr31"
)

func help() {
	fmt.Printf(strings.TrimSpace(`
tr31cli is a Go library implementing the TR-31 (ANSI X9.143) key block standard for secure cryptographic key exchange.

USAGE
   tr31cli [-v] [-algorithm] [-ik] [-tk] [-ep] [-dp] [-gm] [-en] [-de]

EXAMPLES
  tr31cli -v          Print the version of tr31cli (Example: %s)
  tr31cli -algorithm  Data encryption algorithm (options: des, aes)
  tr31cli -ik         Derive initial key from base derivative key and key serial number (or initial key id)
  tr31cli -tk         Derive transaction key (current transaction key) from initial key and key serial number
  tr31cli -ep         Encrypt pin block using dukpt transaction key
  tr31cli -dp         Decrypt pin block using dukpt transaction key
  tr31cli -gm         Generate mac using dukpt transaction key
  tr31cli -en         Encrypt data using dukpt transaction key
  tr31cli -de         Decrypt data using dukpt transaction key

FLAGS
`), tr31.Version)
	fmt.Println("")
	flag.PrintDefaults()
}
