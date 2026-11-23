package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/moov-io/tr31"
	"github.com/moov-io/tr31/pkg/server"
)

var (
	flagVersion = flag.Bool("v", false, "Print tr31 cli version")

	flagEncrypt         = flag.Bool("e", false, "Wrap a key (-wrapper_key) under the KBPK stored in Vault")
	flagDecrypt         = flag.Bool("d", false, "Unwrap a key block (-key_block) with the KBPK stored in Vault")
	flagVaultAddress    = flag.String("vault_address", "", "Vault address, for example http://127.0.0.1:8200")
	flagVaultToken      = flag.String("vault_token", "", "Vault token for authentication")
	flagKeyPath         = flag.String("key_path", "", "Vault KV v2 API path of the secret that holds the KBPK, for example secret/data/tr31")
	flagKeyName         = flag.String("key_name", "", "Field in the Vault secret that holds the hex-encoded KBPK, for example kbpk")
	flagWrapperKey      = flag.String("wrapper_key", "", "Hex-encoded key to wrap (used with -e)")
	flagDecryptKeyBlock = flag.String("key_block", "", "TR-31 key block to unwrap (used with -d)")

	// Key block header flags (used with -e)
	flagVersionID     = flag.String("version_id", "", "Key block version ID: A, B, C or D (used with -e)")
	flagKeyUsage      = flag.String("key_usage", "", "Key usage, for example P0, D0, K0 or B0 (used with -e)")
	flagAlgorithm     = flag.String("algorithm", "", "Algorithm of the wrapped key: T (TDES), D (DES) or A (AES) (used with -e)")
	flagModeOfUse     = flag.String("mode_of_use", "", "Mode of use, for example E, D, B, N or X (used with -e)")
	flagKeyVersion    = flag.String("key_version", "00", "Key version number (used with -e)")
	flagExportability = flag.String("exportability", "N", "Exportability: E, N or S (used with -e)")
)

func main() {
	flag.Usage = help
	flag.Parse()

	if *flagVersion {
		fmt.Printf("moov-io/tr31:%s cli tool\n", tr31.Version)
		return
	}

	params, err := buildParams()
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	switch {
	case *flagEncrypt:
		makeFuncCall(server.Encrypt, params)
	case *flagDecrypt:
		makeFuncCall(server.Decrypt, params)
	default:
		flag.Usage()
		os.Exit(1)
	}
}

// buildParams checks the flags and returns the parameters for the selected action.
func buildParams() (server.UnifiedParams, error) {
	params := server.UnifiedParams{}

	if *flagEncrypt && *flagDecrypt {
		return params, errors.New("use only one of -e or -d")
	}
	if !*flagEncrypt && !*flagDecrypt {
		return params, nil
	}

	if *flagVaultAddress == "" {
		return params, errors.New("please select vault address with vault_address flag")
	}
	if *flagVaultToken == "" {
		return params, errors.New("please select vault token with vault_token flag")
	}
	if *flagKeyPath == "" {
		return params, errors.New("please select vault key path with key_path flag")
	}
	if *flagKeyName == "" {
		return params, errors.New("please select vault key name with key_name flag")
	}
	params.VaultAddr = *flagVaultAddress
	params.VaultToken = *flagVaultToken
	params.KeyPath = *flagKeyPath
	params.KeyName = *flagKeyName

	if *flagEncrypt {
		if *flagWrapperKey == "" {
			return params, errors.New("please select the key to wrap with wrapper_key flag")
		}
		header := server.HeaderParams{
			VersionId:     *flagVersionID,
			KeyUsage:      *flagKeyUsage,
			Algorithm:     *flagAlgorithm,
			ModeOfUse:     *flagModeOfUse,
			KeyVersion:    *flagKeyVersion,
			Exportability: *flagExportability,
		}
		var missing []string
		if header.VersionId == "" {
			missing = append(missing, "-version_id")
		}
		if header.KeyUsage == "" {
			missing = append(missing, "-key_usage")
		}
		if header.Algorithm == "" {
			missing = append(missing, "-algorithm")
		}
		if header.ModeOfUse == "" {
			missing = append(missing, "-mode_of_use")
		}
		if header.KeyVersion == "" {
			missing = append(missing, "-key_version")
		}
		if header.Exportability == "" {
			missing = append(missing, "-exportability")
		}
		if len(missing) > 0 {
			return params, fmt.Errorf("please set the key block header with %s", strings.Join(missing, ", "))
		}
		params.EncKey = *flagWrapperKey
		params.Header = header
	}

	if *flagDecrypt {
		if *flagDecryptKeyBlock == "" {
			return params, errors.New("please select the key block to unwrap with key_block flag")
		}
		params.KeyBlock = *flagDecryptKeyBlock
	}

	return params, nil
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
It wraps and unwraps keys with a Key Block Protection Key (KBPK) that is stored in a Vault KV v2 secret.

USAGE
   tr31 [-v] [-e] [-d] [flags]

EXAMPLES
  tr31 -v           Print the version of tr31 (Example: %s)
  tr31 -e           Wrap a key (-wrapper_key) under the KBPK
  tr31 -d           Unwrap a key block (-key_block) with the KBPK

  tr31 -e -vault_address=http://127.0.0.1:8200 -vault_token=myroot -key_path=secret/data/tr31 -key_name=kbpk \
     -wrapper_key=3F419E1CB7079442AA37474C2EFBF8B8 -version_id=B -key_usage=P0 -algorithm=T -mode_of_use=E

  tr31 -d -vault_address=http://127.0.0.1:8200 -vault_token=myroot -key_path=secret/data/tr31 -key_name=kbpk \
     -key_block=B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A3B8E4FA4C5F5341176EED7B727B8A248E

FLAGS
`), tr31.Version)
	fmt.Println("")
	flag.PrintDefaults()
}
