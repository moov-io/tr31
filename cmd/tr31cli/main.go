package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/moov-io/tr31"
	"github.com/moov-io/tr31/pkg/server"
)

var (
	flagVersion = flag.Bool("v", false, "Print tr31 cli version")

	flagEncrypt             = flag.Bool("e", false, "encrypt card data block using tr31 transaction key")
	flagEncryptVaultAddress = flag.String("e_va", "", "key stored vault address")
	flagEncryptVaultToken   = flag.String("e_tk", "", "key stored vault token")
	flagEncryptKeyPath      = flag.String("e_kp", "", "key stored vault key path")
	flagEncryptKeyName      = flag.String("e_kn", "", "key stored vault key name")
	flagEncryptEncKey       = flag.String("e_ek", "", "encrypt key")

	flagDecrypt             = flag.Bool("d", false, "decrypt card data block using tr31 transaction key")
	flagDecryptVaultAddress = flag.String("d_va", "", "key stored vault address")
	flagDecryptVaultToken   = flag.String("d_tk", "", "key stored vault token")
	flagDecryptKeyPath      = flag.String("d_kp", "", "key stored vault key path")
	flagDecryptKeyName      = flag.String("d_kn", "", "key stored vault key name")
	flagDecryptKeyBlock     = flag.String("d_kb", "", "wrapped key block for decryption")
)

func main() {
	flag.Usage = help
	flag.Parse()
	params := server.UnifiedParams{}

	switch {
	case *flagVersion:
		fmt.Printf("moov-io/tr31:%s cli tool\n", tr31.Version)
		return
	}

	// wrap
	if *flagEncrypt {
		if *flagEncryptVaultAddress == "" {
			fmt.Printf("please select vault address key with e_va flag\n")
			os.Exit(1)
		}
		if *flagEncryptVaultToken == "" {
			fmt.Printf("please select vault token with e_tk flag\n")
			os.Exit(1)
		}
		if *flagEncryptKeyPath == "" {
			fmt.Printf("please select vault key path with e_kp flag\n")
			os.Exit(1)
		}
		if *flagEncryptKeyName == "" {
			fmt.Printf("please select vault key name with e_kn flag\n")
			os.Exit(1)
		}
		if *flagEncryptEncKey == "" {
			fmt.Printf("please select vault block with e_ek flag\n")
			os.Exit(1)
		}
		params.VaultAddr = *flagDecryptVaultAddress
		params.VaultToken = *flagDecryptVaultToken
		params.KeyPath = *flagDecryptKeyPath
		params.KeyName = *flagDecryptKeyName
		params.EncKey = *flagEncryptEncKey
		makeFuncCall(server.Encrypt, params)
	}

	// unwrap
	if *flagDecrypt {
		if *flagDecryptVaultAddress == "" {
			fmt.Printf("please select vault address key with d_va flag\n")
			os.Exit(1)
		}
		if *flagDecryptVaultToken == "" {
			fmt.Printf("please select vault token with d_tk flag\n")
			os.Exit(1)
		}
		if *flagDecryptKeyPath == "" {
			fmt.Printf("please select vault key path with d_kp flag\n")
			os.Exit(1)
		}
		if *flagDecryptKeyName == "" {
			fmt.Printf("please select vault key name with d_kn flag\n")
			os.Exit(1)
		}
		if *flagDecryptKeyBlock == "" {
			fmt.Printf("please select vault block with d_kb flag\n")
			os.Exit(1)
		}
		params.VaultAddr = *flagDecryptVaultAddress
		params.VaultToken = *flagDecryptVaultToken
		params.KeyPath = *flagDecryptKeyPath
		params.KeyName = *flagDecryptKeyName
		params.KeyBlock = *flagDecryptKeyBlock
		makeFuncCall(server.Decrypt, params)
	}
}

func makeFuncCall(f server.WrapperCall, params server.UnifiedParams) {
	result, err := f(params)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		os.Exit(2)
	}

	fmt.Printf("RESULT: %s\n", result)
}

func help() {
	fmt.Printf(strings.TrimSpace(`
tr31 is a Go library implementing the TR-31 (ANSI X9.143) key block standard for secure cryptographic key exchange.

USAGE
   tr31 [-v] [-e] [-d]

EXAMPLES
  tr31 -v           Print the version of tr31 (Example: %s)
  tr31 -e			Encrypt card data block using tr31 kbkp key
  tr31 -d           Decrypt card data block using tr31 kbkp key

FLAGS
`), tr31.Version)
	fmt.Println("")
	flag.PrintDefaults()
}
