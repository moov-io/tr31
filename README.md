[![Moov Banner Logo](https://user-images.githubusercontent.com/20115216/104214617-885b3c80-53ec-11eb-8ce0-9fc745fb5bfc.png)](https://github.com/moov-io)

<p align="center">
  <a href="https://moov-io.github.io/tr31/">Project Documentation</a>
  ·
  <a href="https://moov-io.github.io/tr31/api/#overview">API Endpoints</a>
  ·
  <a href="https://slack.moov.io/">Community</a>
  ·
  <a href="https://moov.io/blog/">Blog</a>
  <br>
  <br>
</p>

# TR-31

A Go library implementing the TR-31 (ANSI X9.143) key block standard for secure cryptographic key exchange.

## Overview

TR-31 is a method defined by ASC X9.143 for secure cryptographic key exchange between devices and systems, particularly in the financial industry. This format provides a structured way to protect sensitive key material while maintaining essential metadata about key usage, algorithms, and other attributes.

## Project Status

moov-io/tr31 is undergoing active development and testing within Moov. Please star the project and share feedback, bugs, questions, etc in the [`tr31` channel in slack](https://slack.moov.io/). If you find security vulnerabilities reach out to `oss@moov.io`.

## Features

- Supports all major TR-31 key block versions:
  - Version A (TDES variant)
  - Version B (TDES key derivation - preferred TDES implementation)
  - Version C (TDES variant)
  - Version D (AES key derivation)
- Implements multiple encryption algorithms:
  - Triple DES (TDES)
  - Single DES (legacy)
  - AES
- Comprehensive error handling with detailed error messages
- Thread-safe operations
- No external dependencies

## Installation

```bash
go get github.com/moov-io/tr31
```

## Usage

### Basic Example

```go
package main

import (
    "fmt"
    "github.com/moov-io/tr31/pkg/tr31"
)

func main() {
    // Create a new header with TR-31 version D (AES)
    header, err := tr31.NewHeader(
      tr31.TR31_VERSION_D,            // Version ID
      tr31.KEY_USAGE_DATA_ENCRYPTION, // Key Usage "D0" (symmetric data encryption key)
      tr31.ENC_ALGORITHM_AES,         // Algorithm "A" (AES)
      tr31.MODE_OF_USE_ENCRYPT,       // Mode of Use "E" (encrypt only)
      "01",                           // Version Number
      tr31.EXPORTABILITY_TRUSTED,     // Exportability "E" (exportable under a KEK, per X9.24)
    )
    if err != nil {
        panic(err)
    }

    // Optional: check the key usage and mode of use agree. NewHeader does
    // not, so a header such as B1 (Initial DUKPT Key) with mode E would
    // otherwise be accepted.
    if err := header.ValidateKeyUsageModeOfUse(); err != nil {
        panic(err)
    }

    // Create a key block with your Key Block Protection Key (KBPK)
    kbpk, err := tr31.GenerateKBPK(tr31.KBPKOptions{
        Version:   tr31.TR31_VERSION_D,
        KeyLength: 32,
    })
    if err != nil {
        panic(err)
    }
    // Create a new KeyBlock
    keyBlock, err := tr31.NewKeyBlock(kbpk, header)
    if err != nil {
        panic(err)
    }

    // Wrap a 16-byte AES-128 data encryption key
    keyToWrap := []byte{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    }
    wrappedKey, err := keyBlock.Wrap(keyToWrap, nil)
    if err != nil {
        panic(err)
    }

    // Unwrap a key
    unwrappedKey, err := keyBlock.Unwrap(wrappedKey)
    if err != nil {
        panic(err)
    }
    fmt.Printf("unwrapped a %d-byte key\n", len(unwrappedKey))
}
```

## API Reference

### KeyBlock Functions

#### Wrap

```go
func (kb *KeyBlock) Wrap(key []byte, maskedKeyLen *int) (string, error)
```

Wraps a cryptographic key using the TR-31 format.

Parameters:
- `key`: The key to be wrapped (byte slice)
- `maskedKeyLen`: Optional pointer to an integer specifying the masked key length. If nil, uses the maximum key size for the algorithm.

Returns:
- `string`: The wrapped key block in TR-31 format
- `error`: Any error that occurred during the wrapping process

#### Unwrap

```go
func (kb *KeyBlock) Unwrap(keyBlock string) ([]byte, error)
```

Unwraps a TR-31 formatted key block to retrieve the original key.

Parameters:
- `keyBlock`: The TR-31 formatted key block string to unwrap

Returns:
- `[]byte`: The unwrapped key
- `error`: Any error that occurred during the unwrapping process

### Version-Specific Implementation Details

The library supports different TR-31 versions with specific characteristics:

- **Version A/C**:
  - Uses TDES encryption
  - Simple key derivation (XOR with constants)
  - 4-byte MAC

- **Version B**:
  - Uses TDES encryption
  - CMAC-based key derivation
  - 8-byte MAC
  - Recommended for TDES implementations

- **Version D**:
  - Uses AES encryption
  - CMAC-based key derivation
  - 16-byte MAC
  - Supports AES-128, AES-192, and AES-256

## Security Considerations

- Always use strong, random Key Block Protection Keys (KBPK)
- Version B is preferred over Version A/C for TDES implementations
- Version D (AES) is recommended for new implementations
- The library performs key length validation and padding automatically
- Ensure your Go environment and dependencies are up to date

## Error Handling

The library provides detailed error messages through two custom error types:
- `HeaderError`: For issues related to TR-31 header processing
- `KeyBlockError`: For issues related to key block processing

## Benchmarks

Unwraps a TR-31 formatted key block to retrieve the original key.

```bash
Running tool: /opt/homebrew/bin/go test -benchmem -run=^$ -bench ^BenchmarkUnwrap_D_32_WithSetup$ github.com/moov-io/tr31/pkg/tr31

goos: darwin
goarch: arm64
pkg: github.com/moov-io/tr31/pkg/tr31
cpu: Apple M1 Pro
BenchmarkUnwrap_D_32_WithSetup-10    	  301116	      3619 ns/op	    8608 B/op	      64 allocs/op
```

### Command Line Usage

tr31 is a tool that wraps a key under a Key Block Protection Key (KBPK) and unwraps TR-31 key blocks. The KBPK is stored in a Vault KV v2 secret.

```bash
go install github.com/moov-io/tr31/cmd/tr31@latest
```

### USAGE
    tr31 [-v] [-e] [-d] [flags]

### EXAMPLES
    tr31 -v
      Print the version of tr31 (Example: v1.0.0)
    tr31 -e
      Wrap a key (-wrapper_key) under the KBPK. Requires the key block header flags.
    tr31 -d
      Unwrap a key block (-key_block) with the KBPK

Use only one of `-e` or `-d`.

### FLAGS
```
  -algorithm string
    	Algorithm of the wrapped key: T (TDES), D (DES) or A (AES) (used with -e)
  -d	Unwrap a key block (-key_block) with the KBPK stored in Vault
  -e	Wrap a key (-wrapper_key) under the KBPK stored in Vault
  -exportability string
    	Exportability: E, N or S (used with -e) (default "N")
  -key_block string
    	TR-31 key block to unwrap (used with -d)
  -key_name string
    	Field in the Vault secret that holds the hex-encoded KBPK, for example kbpk
  -key_path string
    	Vault KV v2 API path of the secret that holds the KBPK, for example secret/data/tr31
  -key_usage string
    	Key usage, for example P0, D0, K0 or B0 (used with -e)
  -key_version string
    	Key version number (used with -e) (default "00")
  -mode_of_use string
    	Mode of use, for example E, D, B, N or X (used with -e)
  -v	Print tr31 cli version
  -vault_address string
    	Vault address, for example http://127.0.0.1:8200
  -vault_token string
    	Vault token for authentication
  -version_id string
    	Key block version ID: A, B, C or D (used with -e)
  -wrapper_key string
    	Hex-encoded key to wrap (used with -e)
```

### Vault KBPK

Store the hex-encoded KBPK in a Vault KV v2 secret. Then set `-key_path` to the KV v2 API path (with `data/`) and `-key_name` to the field name:

```bash
vault kv put secret/tr31 kbpk=DD7515F2BFC17F85CE48F3CA25CB21F6
```

A path without `data/` (for example `-key_path=secret/tr31`) fails with `missing 'data' key in secret response`.

### EXAMPLES
```
tr31 -e -vault_address=http://127.0.0.1:8200 -vault_token=myroot -key_path=secret/data/tr31 -key_name=kbpk \
   -wrapper_key=3F419E1CB7079442AA37474C2EFBF8B8 \
   -version_id=B -key_usage=P0 -algorithm=T -mode_of_use=E -key_version=00 -exportability=N
RESULT: B0096P0TE00N0000...

tr31 -d -vault_address=http://127.0.0.1:8200 -vault_token=myroot -key_path=secret/data/tr31 -key_name=kbpk \
   -key_block=B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A3B8E4FA4C5F5341176EED7B727B8A248E
RESULT: 3f419e1cb7079442aa37474c2efbf8b8
```

### Rest APIs
TR31 library provided web server. Please check following http endpoints

| Method | Request Body | Route              | Action         |
|--------|--------------|--------------------|----------------|
| POST   | JSON         | /encrypt_data      | Encrypt Data   |
| POST   | JSON         | /decrypt_data      | Decrypt Data   |


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [ASC X9.143 Standard](https://x9.org/standards/tr-31-interoperable-secure-key-exchange-key-block-specification-for-symmetric-algorithms/)
- [ANSI TR-31 Documentation](https://www.ncr.com/content/dam/ncrcom/content-type/documents/ncr-tr31-security.pdf)

---
**Note**: This implementation is provided as-is. Users should verify the implementation meets their security requirements before using in production environments.
