package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/moov-io/tr31"
)

func help() {
	fmt.Printf(strings.TrimSpace(`
tr31 is a Go library implementing the TR-31 (ANSI X9.143) key block standard for secure cryptographic key exchange.

USAGE
   tr31 [-v] [-algorithm] [-ik] [-tk] [-ep] [-dp] [-gm] [-en] [-de]

EXAMPLES
  tr31 -v          Print the version of tr31 (Example: %s)
  tr31 -algorithm  Data encryption algorithm (options: des, aes)
  tr31 -ik         Derive initial key from base derivative key and key serial number (or initial key id)
  tr31 -tk         Derive transaction key (current transaction key) from initial key and key serial number
  tr31 -ep         Encrypt pin block using dukpt transaction key
  tr31 -dp         Decrypt pin block using dukpt transaction key
  tr31 -gm         Generate mac using dukpt transaction key
  tr31 -en         Encrypt data using dukpt transaction key
  tr31 -de         Decrypt data using dukpt transaction key

FLAGS
`), tr31.Version)
	fmt.Println("")
	flag.PrintDefaults()
}
