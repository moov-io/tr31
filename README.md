[![Moov Banner Logo](https://user-images.githubusercontent.com/20115216/104214617-885b3c80-53ec-11eb-8ce0-9fc745fb5bfc.png)](https://github.com/moov-io)

<p align="center">
  <a href="https://pkg.go.dev/github.com/moov-io/tr31/pkg/tr31">Go Documentation</a>
  ·
  <a href="#rest-apis">API Endpoints</a>
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
- The `pkg/tr31` library depends only on the Go standard library and [`go-safecast`](https://github.com/ccoveille/go-safecast). The CLI and server also use Vault, go-kit and moov-io/base.

## Installation

tr31 requires Go 1.26 or newer.

Add the library to your Go module:

```bash
go get github.com/moov-io/tr31/pkg/tr31@latest
```

Install the CLI and the server:

```bash
go install github.com/moov-io/tr31/cmd/tr31@latest
go install github.com/moov-io/tr31/cmd/server@latest
```

The releases do not include prebuilt binaries.

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

### Unwrap a key block from another system

To unwrap a key block from an HSM or another system, you need only the KBPK. Give `nil` as the header to `NewKeyBlock`. `Unwrap` reads the header from the key block. The `header` parameter of `NewKeyBlock` also accepts a `*tr31.Header` or a header string.

```go
package main

import (
    "encoding/hex"
    "fmt"

    "github.com/moov-io/tr31/pkg/tr31"
)

func main() {
    kbpk, err := hex.DecodeString("DD7515F2BFC17F85CE48F3CA25CB21F6") // double-length TDES KBPK
    if err != nil {
        panic(err)
    }

    keyBlock, err := tr31.NewKeyBlock(kbpk, nil)
    if err != nil {
        panic(err)
    }

    key, err := keyBlock.Unwrap("B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A3B8E4FA4C5F5341176EED7B727B8A248E")
    if err != nil {
        panic(err)
    }
    fmt.Printf("key: %X\n", key) // prints 3F419E1CB7079442AA37474C2EFBF8B8

    // Read the header (and optional blocks) of the unwrapped key block
    header := keyBlock.GetHeader()
    fmt.Printf("version=%s key usage=%s algorithm=%s mode of use=%s\n",
        header.VersionID, header.KeyUsage, header.Algorithm, header.ModeOfUse)
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

### Key Block Protection Keys (KBPK)

`GenerateKBPK` and `ValidateKBPK` accept these KBPK lengths:

| Version | KBPK algorithm | KBPK length (bytes) |
|---------|----------------|---------------------|
| A, B, C | TDES           | 16 (double-length) or 24 (triple-length) |
| D       | AES            | 16, 24, or 32       |

TDES KBPKs must have odd parity, and the 8-byte parts of the key must be different. `GenerateKBPK` sets the parity for you.

```go
// Double-length TDES KBPK for version B (the usual ZMK size on many HSMs)
kbpk, err := tr31.GenerateKBPK(tr31.KBPKOptions{
    Version:   tr31.TR31_VERSION_B,
    KeyLength: 16,
})
if err != nil {
    panic(err)
}

header, err := tr31.NewHeader(
    tr31.TR31_VERSION_B,
    tr31.KEY_USAGE_PIN_ENCRYPTION, // "P0"
    tr31.ENC_ALGORITHM_TRIPLE_DES, // "T"
    tr31.MODE_OF_USE_ENCRYPT,      // "E"
    "00",
    tr31.EXPORTABILITY_NONE, // "N"
)
if err != nil {
    panic(err)
}
keyBlock, err := tr31.NewKeyBlock(kbpk, header)
```

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

The benchmarks measure `Unwrap` for each key block version. Run them with:

```bash
go test ./pkg/tr31 -run '^$' -bench '^BenchmarkUnwrap' -benchmem
# or, to get the median of 6 runs:
make bench
```

Example result (Apple M1 Pro):

```
BenchmarkUnwrap_D_32_WithSetup-10    	  301116	      3619 ns/op	    8608 B/op	      64 allocs/op
```

The results from CI are stored in the [`bench-data` branch](https://github.com/moov-io/tr31/tree/bench-data/docs/bench).

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

The CLI reads the KBPK from a Vault KV v2 secret. Set `-key_path` to the KV v2 API path (for example `secret/data/tr31`) and `-key_name` to the field name. See [Vault setup](#vault-setup).

### EXAMPLES
```
tr31 -e -vault_address=http://127.0.0.1:8200 -vault_token=myroot -key_path=secret/data/tr31 -key_name=kbpk \
   -version_id=B -key_usage=P0 -algorithm=T -mode_of_use=E -key_version=00 -exportability=N \
   -wrapper_key=3F419E1CB7079442AA37474C2EFBF8B8 # gitleaks:allow
RESULT: B0096P0TE00N0000...

tr31 -d -vault_address=http://127.0.0.1:8200 -vault_token=myroot -key_path=secret/data/tr31 -key_name=kbpk \
   -key_block=B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A3B8E4FA4C5F5341176EED7B727B8A248E # gitleaks:allow
RESULT: 3f419e1cb7079442aa37474c2efbf8b8
```

### Rest APIs
TR31 library provided web server. The server reads the KBPK from a Vault KV v2 secret (see [Vault setup](#vault-setup)).

Start the server:

```bash
go run ./cmd/server
# or
go install github.com/moov-io/tr31/cmd/server@latest
```

By default the HTTP server listens on `:8096` and the admin server listens on `:9106`. Use `-http.addr` and `-admin.addr` (or `HTTP_BIND_ADDRESS` and `HTTP_ADMIN_BIND_ADDRESS`) to change them. Set `HTTPS_CERT_FILE` and `HTTPS_KEY_FILE` to serve HTTPS. Set `LOG_FORMAT=json` for JSON logs.

| Method | Request Body | Route              | Action         |
|--------|--------------|--------------------|----------------|
| GET    |              | /ping              | Health check (returns `PONG`) |
| POST   | JSON         | /encrypt_data      | Wrap a key under the KBPK in Vault |
| POST   | JSON         | /decrypt_data      | Unwrap a key block with the KBPK in Vault |
| POST   | JSON         | /machine           | Create a machine |
| GET    |              | /machines          | List machines  |
| GET    |              | /machine/{ik}      | Get a machine  |
| GET    |              | :9106/version      | Server version (admin server) |

Errors return a JSON body `{"error": "..."}`. A missing required field returns `400 Bad Request`.

**Encrypt Data** (all fields are required)

```bash
ENCRYPT_KEY="3F419E1CB7079442AA37474C2EFBF8B8" # gitleaks:allow
curl -X POST http://localhost:8096/encrypt_data -d '{
  "VaultAddr": "http://127.0.0.1:8200",
  "VaultToken": "myroot",
  "KeyPath": "secret/data/tr31",
  "KeyName": "kbpk",
  "EncryptKey": "'"$ENCRYPT_KEY"'",
  "Header": {
    "VersionId": "B",
    "KeyUsage": "P0",
    "Algorithm": "T",
    "ModeOfUse": "E",
    "KeyVersion": "00",
    "Exportability": "N"
  }
}'
```
```json
{"data":"B0096P0TE00N0000464e4b02...","error":""}
```

**Decrypt Data**

```bash
KEY_BLOCK="B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A3B8E4FA4C5F5341176EED7B727B8A248E" # gitleaks:allow
curl -X POST http://localhost:8096/decrypt_data -d '{
  "VaultAddr": "http://127.0.0.1:8200",
  "VaultToken": "myroot",
  "KeyPath": "secret/data/tr31",
  "KeyName": "kbpk",
  "KeyBlock": "'"$KEY_BLOCK"'"
}'
```
```json
{"data":"3f419e1cb7079442aa37474c2efbf8b8","error":""}
```

**Machines**

```bash
curl -X POST http://localhost:8096/machine -d '{"VaultAddress":"http://127.0.0.1:8200","VaultToken":"myroot"}'
```
```json
{"ik":"4c1be97a6604c657","machine":{"InitialKey":"4c1be97a6604c657","TransactionKey":"9724a226da2801c2","CreatedAt":"0001-01-01T00:00:00Z"},"error":""}
```

```bash
curl http://localhost:8096/machines
curl http://localhost:8096/machine/4c1be97a6604c657
```

#### Vault setup

The CLI and the server read the KBPK (hex encoded) from a Vault KV v2 secret. `-key_path` / `KeyPath` is the KV v2 API path, which includes `data/`. `-key_name` / `KeyName` is the field in the secret.

```bash
vault kv put secret/tr31 kbpk=DD7515F2BFC17F85CE48F3CA25CB21F6
# then use: KeyPath "secret/data/tr31", KeyName "kbpk"
```

A path without `data/` (for example `secret/tr31`) fails with `missing 'data' key in secret response`.

`make setup` starts a Vault dev server with Docker Compose (address `http://localhost:8200`, token `myroot`) and stores this test KBPK at `secret/tr31` (field `kbpk`). Do not use the test KBPK in production.


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

To run the tests:

```bash
make setup     # start a Vault dev server with Docker Compose
go test ./...
make teardown
```

`make check` runs the full set of checks that CI runs.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [ANSI X9.143-2022 Standard](https://webstore.ansi.org/standards/ascx9/ansix91432022)
- [ANSI TR-31 Documentation](https://www.ncr.com/content/dam/ncrcom/content-type/documents/ncr-tr31-security.pdf)

---
**Note**: This implementation is provided as-is. Users should verify the implementation meets their security requirements before using in production environments.
