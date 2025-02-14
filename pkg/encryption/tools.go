package encryption

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"regexp"
	"unicode"
)

/*
Apply "exclusive or" to two byte slices.
Many thanks:
https://stackoverflow.com/a/29409299

	Parameters:
	data - byte slice to be XOR'd
	key  - byte slice used as the XOR mask

	Returns:
	A byte slice that is the result of XOR'ing data with the key.
*/
func xor(data, key []byte) []byte {
	if key == nil || len(key) == 0 {
		return nil
	}
	result := make([]byte, len(data))

	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}

	return result
}

/*
Check integer parity.
Many thanks: in_parallel
http://p-nand-q.com/python/_algorithms/math/bit-parity.html

	Parameters:
	v - integer to check the parity of

	Returns:
	0 - even parity (even number of bits enabled, e.g., 0, 3, 5)
	1 - odd parity (odd number of bits enabled, e.g., 1, 2, 4)
*/
func oddParity(v int) int {
	v ^= v >> 16
	v ^= v >> 8
	v ^= v >> 4
	v &= 0xF
	return int((0x6996 >> v) & 1)
}

/*
Check if a string is ASCII alphanumeric (A-Z, a-z, 0-9).

Parameters:
s - string to check

Returns:
True if the string is ASCII alphanumeric. False otherwise.
*/
// asciiAlphanumeric checks if the string contains only ASCII alphanumeric characters.
func asciiAlphanumeric(s string) bool {
	asciiAN := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for _, char := range s {
		if !contains(asciiAN, char) {
			return false
		}
	}
	return true
}

// contains checks if a character is in the provided string.
func contains(str string, char rune) bool {
	for _, c := range str {
		if c == char {
			return true
		}
	}
	return false
}

// asciiNumeric checks if the string contains only ASCII numeric characters.
func asciiNumeric(s string) bool {
	for _, char := range s {
		if !unicode.IsDigit(char) {
			return false
		}
	}
	return true
}

/*
Check if a string is ASCII printable.

Printable ASCII characters are those with hex values
in the range 20-7E, inclusive.

Parameters:
s - string to check

Returns:
True if the string is ASCII printable. False otherwise.
*/
func asciiPrintable(s string) bool {
	asciiPA := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 " +
		"\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~!"
	return isSubset(s, asciiPA)
}

// Check if the string contains only valid hex characters.
func isAsciiHex(s string) bool {
	re := regexp.MustCompile("^[0-9A-Fa-f]+$")
	return re.MatchString(s)
}

func bytesToInt(b []byte) int64 {
	// Ensure the slice has at least 8 bytes for Uint64 conversion
	if len(b) < 8 {
		return 0 // or handle this case as per your requirements
	}
	return int64(binary.BigEndian.Uint64(b))
}

func intToBytes(i int, length int) []byte {
	b := make([]byte, length)
	if length >= 8 {
		// Use BigEndian to put the integer into the byte slice
		binary.BigEndian.PutUint64(b[len(b)-8:], uint64(i))
	} else {
		// If length is less than 8, handle smaller slices
		temp := make([]byte, 8)
		binary.BigEndian.PutUint64(temp, uint64(i))
		copy(b[len(b)-length:], temp[len(temp)-length:])
	}
	return b
}

func hexToInt(hexStr string) int {
	var result int
	fmt.Sscanf(hexStr, "%X", &result)
	return result
}

func stringToInt(s string) int {
	var result int
	for i := 0; i < len(s); i++ {
		result = result*10 + int(s[i]-'0')
	}
	return result
}

// compareMAC compares two MACs
func compareMAC(mac1, mac2 []byte) bool {
	if len(mac1) != len(mac2) {
		return false
	}
	for i := range mac1 {
		if mac1[i] != mac2[i] {
			return false
		}
	}
	return true
}

func isSubset(s, subset string) bool {
	for _, char := range s {
		if !contains(subset, char) {
			return false
		}
	}
	return true
}

func CompareByte(src []byte, dst []byte) bool {
	return subtle.ConstantTimeCompare(src, dst) == 1
}
