package tr31

import (
	"errors"
	"fmt"
	"strconv"
)

// KBPKOptions defines the options for generating a KBPK
type KBPKOptions struct {
	// Version of TR-31 being used (e.g., "A", "B", "C", "D")
	//
	// Versions A, B and C use a TDES KBPK. Version D uses an AES KBPK.
	Version string
	// Key length in bytes (16 or 24 for TDES; 16, 24, or 32 for AES)
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
	if err := Rand(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}

	// For TDES versions (A, B and C), ensure odd parity and no weak keys
	if isTDESVersion(opts.Version) {
		adjustParityTDES(key)
		if isWeakTDESKey(key) {
			// Recursively try again if we got a weak key
			return GenerateKBPK(opts)
		}
	}

	return key, nil
}

// ValidateKBPK validates an existing KBPK
func ValidateKBPK(key []byte, version string) error {
	switch version {
	case "A", "B", "C":
		if len(key) != 16 && len(key) != 24 {
			return errors.New("TDES KBPK must be 16 or 24 bytes")
		}
		if !hasOddParityTDES(key) {
			return errors.New("TDES KBPK must have odd parity")
		}
		if isWeakTDESKey(key) {
			return errors.New("TDES KBPK must not be a weak key")
		}
	case "D":
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return errors.New("AES KBPK must be 16, 24, or 32 bytes")
		}
	default:
		return fmt.Errorf("unsupported TR-31 version: %s", version)
	}
	return nil
}

// Helper functions

func isTDESVersion(version string) bool {
	return version == "A" || version == "B" || version == "C"
}

func validateKBPKOptions(opts KBPKOptions) error {
	switch opts.Version {
	case "A", "B", "C":
		if opts.KeyLength != 16 && opts.KeyLength != 24 {
			return errors.New("TDES KBPK must be 16 or 24 bytes")
		}
	case "D":
		if opts.KeyLength != 16 && opts.KeyLength != 24 && opts.KeyLength != 32 {
			return errors.New("AES KBPK must be 16, 24, or 32 bytes")
		}
	default:
		return fmt.Errorf("unsupported TR-31 version: %s", opts.Version)
	}
	return nil
}

// adjustParityTDES sets the low bit of each byte so that each byte has odd parity.
func adjustParityTDES(key []byte) {
	for i, b := range key {
		bits := 0
		for j := uint(1); j < 8; j++ {
			if b&(1<<j) != 0 {
				bits++
			}
		}
		if bits%2 == 0 {
			key[i] = b | 1
		} else {
			key[i] = b &^ 1
		}
	}
}

func hasOddParityTDES(key []byte) bool {
	for _, b := range key {
		bits := 0
		for j := 0; j < 8; j++ {
			if j >= 0 && j < strconv.IntSize && b&(1<<uint(j)) != 0 {
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
	switch len(key) {
	case 16:
		// Double-length key: K1 and K2 must be different, otherwise TDES is single DES.
		return byteSliceEqual(key[0:8], key[8:16])

	case 24:
		// Triple-length key: check if any of the three 8-byte parts are identical
		// (simplified check - production code should include full weak key table)
		part1 := key[0:8]
		part2 := key[8:16]
		part3 := key[16:24]

		return byteSliceEqual(part1, part2) ||
			byteSliceEqual(part2, part3) ||
			byteSliceEqual(part1, part3)
	}
	return true
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
