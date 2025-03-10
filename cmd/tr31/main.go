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

	flagEncrypt         = flag.Bool("e", false, "encrypt card data block using tr31 transaction key")
	flagDecrypt         = flag.Bool("d", false, "decrypt card data block using tr31 transaction key")
	flagVaultAddress    = flag.String("vault_address", "", "key stored vault address")
	flagVaultToken      = flag.String("vault_token", "", "key stored vault token")
	flagKeyPath         = flag.String("key_path", "", "key stored vault key path")
	flagKeyName         = flag.String("key_name", "", "key stored vault key name")
	flagEncKey          = flag.String("enc_key", "", "encrypt key")
	flagDecryptKeyBlock = flag.String("key_block", "", "wrapped key block for decryption")
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
		if *flagVaultAddress == "" {
			fmt.Printf("please select vault address key with vault_address flag\n")
			os.Exit(1)
		}
		if *flagVaultToken == "" {
			fmt.Printf("please select vault token with vault_token flag\n")
			os.Exit(1)
		}
		if *flagKeyPath == "" {
			fmt.Printf("please select vault key path with key_path flag\n")
			os.Exit(1)
		}
		if *flagKeyName == "" {
			fmt.Printf("please select vault key name with key_name flag\n")
			os.Exit(1)
		}
		if *flagEncKey == "" {
			fmt.Printf("please select vault block with enc_key flag\n")
			os.Exit(1)
		}
		params.VaultAddr = *flagVaultAddress
		params.VaultToken = *flagVaultToken
		params.KeyPath = *flagKeyPath
		params.KeyName = *flagKeyName
		params.EncKey = *flagEncKey
		makeFuncCall(server.Encrypt, params)
	}

	// unwrap
	if *flagDecrypt {
		if *flagVaultAddress == "" {
			fmt.Printf("please select vault address key with vault_address flag\n")
			os.Exit(1)
		}
		if *flagVaultToken == "" {
			fmt.Printf("please select vault token with vault_token flag\n")
			os.Exit(1)
		}
		if *flagKeyPath == "" {
			fmt.Printf("please select vault key path with key_path flag\n")
			os.Exit(1)
		}
		if *flagKeyName == "" {
			fmt.Printf("please select vault key name with key_name flag\n")
			os.Exit(1)
		}
		if *flagDecryptKeyBlock == "" {
			fmt.Printf("please select vault block with key_block flag\n")
			os.Exit(1)
		}
		params.VaultAddr = *flagVaultAddress
		params.VaultToken = *flagVaultToken
		params.KeyPath = *flagKeyPath
		params.KeyName = *flagKeyName
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
tr31 is a CLI implementing the TR-31 (ANSI X9.143) key block standard for secure cryptographic key exchange.

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
