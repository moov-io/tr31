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
go get github.com/yourusername/tr31
```

## Usage

### Basic Example

```go
package main

import (
    "fmt"
    "github.com/moov-io/tr31/tr31"
)

func main() {
    // Create a new header with TR-31 version B
    header, err := encryption.NewHeader(
      encryption.TR31_VERSION_D, // Version ID
      "B0",                      // Key Usage (Data Encryption Key)
      "A",                       // Algorithm (AES)
      "E",                       // Mode of Use (Encrypt)
      "01",                      // Version Number
      "X",                       // Exportability (Exportable with restrictions)
    )

    if err != nil {
        panic(err)
    }

    // Create a key block with your Key Block Protection Key (KBPK)
    kbpkopts := KBPKOptions{
		  Version:   "D",
		  KeyLength: 32,
	  }
    kbpk, _ := GenerateKBPK(kbpkopts)
    // Create a new KeyBlock 
    keyBlock, err := encryption.NewKeyBlock(kbpk, header)
    if err != nil {
        panic(err)
    }

    // Wrap a key
    keyToWrap := []byte{...} // Your key to wrap
    wrappedKey, err := keyBlock.Wrap(keyToWrap, nil)
    if err != nil {
        panic(err)
    }

    // Unwrap a key
    unwrappedKey, err := keyBlock.Unwrap(wrappedKey)
    if err != nil {
        panic(err)
    }
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

tr31 is a tool for managing both TDES and AES-derived unique keys per transaction (TR-31) key management.

### USAGE 
    tr31 [-v] [-algorithm] [-e] [-d]

### EXAMPLES
    tr31 -v 
      Print the version of tr31 (Example: v1.0.0) 
    tr31 -e 
      Encrypt a card data block using the TR-31 transaction key 
    tr31 -d 
      Decrypt a card data block using the TR-31 transaction key

### FLAGS
    -e_va string 
      Vault address where the encryption key is stored 
    -e_tk string 
      Vault token for authentication 
    -e_kp string 
      Path to the encryption key in the vault 
    -e_kn string 
      Name of the encryption key in the vault 
    -e_ek string 
      Encryption key

    -d_va string 
      Vault address where the decryption key is stored 
    -d_tk string 
      Vault token for authentication 
    -d_kp string 
      Path to the decryption key in the vault 
    -d_kn string 
      Name of the decryption key in the vault 
    -d_kb string 
      Wrapped key block for decryption

### EXAMPLES
```
      tr31 -e -enc_va="https://vault-cluster....com:8200" -e_tk="hvs.CA******Ak" -e_kp="kv/.../key" -e_kn="encKey" -e_ek="A0088******A356E"
      tr31 -d -dec_va="https://vault-cluster....com:8200" -d_tk="hvs.CA******Ak" -d_kp="kv/.../key" -d_kn="kbkp" -d_kb="A0088******A356E"
```
### Service instance
TR31 library provided service instance that support multi tr31 encrypt machines. 
```
type Service interface {
	GetSecretManager() SecretManager
	CreateMachine(m *Machine) error
	GetMachine(ik string) (*Machine, error)
	GetMachines() []*Machine
	DeleteMachine(ik string) error
	EncryptData(vaultAddr, vaultToken, keyPath, keyName, encKey string, header HeaderParams, timeout time.Duration) (string, error)
	DecryptData(vaultAddr, vaultToken, keyPath, keyName, keyBlock string, timeout time.Duration) (string, error)
}
```

User can use the service instance using special logger
```
	logger := log.NewLogger(kitlogger)
	logger.Logf("Starting tr31 server version %s", tr31.Version)

	// Setup underlying tr31 service
	r := server.NewRepositoryInMemory(logger)
	svc = server.NewService(r)
```
### Rest APIs
TR31 library provided web server. Please check following http endpoints

| Method | Request Body | Route              | Action         |
|--------|--------------|--------------------|----------------|
| GET    |              | /machines          | Get Machines   |
| GET    |              | /machine/{ik}      | Get Machine    |
| POST   |              | /machine           | Create Machine |
| POST   | JSON         | /encrypt_data      | Encrypt Data   |
| POST   | JSON         | /decrypt_data      | Decrypt Data   | 

User can create web service using following http handler 
```
	handler = server.MakeHTTPHandler(svc)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [ASC X9.143 Standard](https://x9.org/standards/tr-31-interoperable-secure-key-exchange-key-block-specification-for-symmetric-algorithms/)
- [ANSI TR-31 Documentation](https://www.ncr.com/content/dam/ncrcom/content-type/documents/ncr-tr31-security.pdf)

---
**Note**: This implementation is provided as-is. Users should verify the implementation meets their security requirements before using in production environments.
