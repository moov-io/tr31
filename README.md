[![Moov Banner Logo](https://user-images.githubusercontent.com/20115216/104214617-885b3c80-53ec-11eb-8ce0-9fc745fb5bfc.png)](https://github.com/moov-io)

<p align="center">
  <a href="https://moov-io.github.io/psec/">Project Documentation</a>
  ·
  <a href="https://moov-io.github.io/psec/api/#overview">API Endpoints</a>
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
    "github.com/yourusername/tr31/encryption"
)

func main() {
    // Create a new header with TR-31 version B
    header, err := encryption.NewHeader(
        encryption.TR31_VERSION_B, // Version ID
        "P0",                      // Key Usage (PIN Encryption Key)
        "T",                       // Algorithm (Triple DES)
        "E",                       // Mode of Use (Encrypt)
        "00",                      // Version Number
        "N",                       // Exportability (Non-exportable)
    )
    if err != nil {
        panic(err)
    }

    // Create a key block with your Key Block Protection Key (KBPK)
    kbpk := []byte{...} // Your 16 or 24-byte KBPK
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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [ASC X9.143 Standard](https://x9.org/standards/tr-31-interoperable-secure-key-exchange-key-block-specification-for-symmetric-algorithms/)
- [ANSI TR-31 Documentation](https://www.ncr.com/content/dam/ncrcom/content-type/documents/ncr-tr31-security.pdf)

---
**Note**: This implementation is provided as-is. Users should verify the implementation meets their security requirements before using in production environments.
