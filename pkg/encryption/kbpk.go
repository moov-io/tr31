package encryption

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// KBPKOptions defines the options for generating a KBPK
type KBPKOptions struct {
	// Version of TR-31 being used (e.g., "A", "B", "C", "D")
	Version string
	// Key length in bytes (16, 24, or 32 for AES; 24 for TDES)
	KeyLength int
}

// GenerateKBPK generates a valid Key Block Protection Key
func GenerateKBPK(opts KBPKOptions) ([]byte, error) {
	// Validate options
	if err := validateKBPKOptions(opts); err != nil {
		return nil, fmt.Errorf("invalid options: %v", err)
	}

	// Generate random key of specified length
	key := make([]byte, opts.KeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}

	// For TDES versions (A and B), ensure odd parity and no weak keys
	if opts.Version == TR31_VERSION_A || opts.Version == TR31_VERSION_B {
		adjustParityTDES(key)
		if isWeakTDESKey(key) {
			// Recursively try again if we got a weak key
			return GenerateKBPK(opts)
		}
	}

	// For AES versions (C and D), just validate key length
	if opts.Version == TR31_VERSION_C || opts.Version == TR31_VERSION_D {
		if opts.KeyLength != 16 && opts.KeyLength != 24 && opts.KeyLength != 32 {
			return nil, errors.New("AES key length must be 16, 24, or 32 bytes")
		}
	}

	return key, nil
}

// ValidateKBPK validates an existing KBPK
func ValidateKBPK(key []byte, version string) error {
	switch version {
	case TR31_VERSION_A, TR31_VERSION_B:
		if len(key) != 24 {
			return errors.New("TDES KBPK must be 24 bytes")
		}
		if !hasOddParityTDES(key) {
			return errors.New("TDES KBPK must have odd parity")
		}
		if isWeakTDESKey(key) {
			return errors.New("TDES KBPK must not be a weak key")
		}
	case TR31_VERSION_C, TR31_VERSION_D:
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return errors.New("AES KBPK must be 16, 24, or 32 bytes")
		}
	default:
		return fmt.Errorf("unsupported TR-31 version: %s", version)
	}
	return nil
}

// Helper functions

func validateKBPKOptions(opts KBPKOptions) error {
	switch opts.Version {
	case TR31_VERSION_A, TR31_VERSION_B:
		if opts.KeyLength != 24 {
			return errors.New("TDES KBPK must be 24 bytes")
		}
	case TR31_VERSION_C, TR31_VERSION_D:
		if opts.KeyLength != 16 && opts.KeyLength != 24 && opts.KeyLength != 32 {
			return errors.New("AES KBPK must be 16, 24, or 32 bytes")
		}
	default:
		return fmt.Errorf("unsupported TR-31 version: %s", opts.Version)
	}
	return nil
}

func adjustParityTDES(key []byte) {
	for i := range key {
		// Count the number of 1 bits
		bits := 0
		for j := 0; j < 7; j++ {
			if key[i]&(1<<uint(j)) != 0 {
				bits++
			}
		}
		// Set or clear the parity bit to ensure odd parity
		if bits%2 == 0 {
			key[i] |= 1
		} else {
			key[i] &= 0xFE
		}
	}
}

func hasOddParityTDES(key []byte) bool {
	for _, b := range key {
		bits := 0
		for j := 0; j < 8; j++ {
			if b&(1<<uint(j)) != 0 {
				bits++
			}
		}
		if bits%2 == 0 {
			return false
		}
	}
	return true
}

func isWeakTDESKey(key []byte) bool {
	// Check if any of the three 8-byte parts are identical
	if len(key) != 24 {
		return true
	}

	// Compare key parts (simplified check - production code should include full weak key table)
	part1 := key[0:8]
	part2 := key[8:16]
	part3 := key[16:24]

	return byteSliceEqual(part1, part2) ||
		byteSliceEqual(part2, part3) ||
		byteSliceEqual(part1, part3)
}

func byteSliceEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
