package tr31

import (
	"bytes"
	"testing"
)

func TestXor(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		key  []byte
		want []byte
	}{
		{"Equal length data and key", []byte{0x01, 0x02, 0x03}, []byte{0x0A, 0x0B, 0x0C}, []byte{0x0B, 0x09, 0x0F}},
		{"Key shorter than data (repeating key)", []byte{0xFF, 0xEE, 0xDD, 0xCC}, []byte{0x0F, 0xF0}, []byte{0xF0, 0x1E, 0xD2, 0x3C}},
		{"Single-byte key", []byte{0x01, 0x02, 0x03, 0x04}, []byte{0xFF}, []byte{0xFE, 0xFD, 0xFC, 0xFB}},
		{"Empty data", []byte{}, []byte{0x0A, 0x0B}, []byte{}},
		{"Empty key", []byte{0x01, 0x02, 0x03}, []byte{}, nil},
		{"Both empty", []byte{}, []byte{}, []byte{}},
		{"Alternating bits", []byte{0xAA, 0x55, 0xAA, 0x55}, []byte{0xFF, 0x00}, []byte{0x55, 0x55, 0x55, 0x55}},
		{"Key same as data", []byte{0x12, 0x34, 0x56}, []byte{0x12, 0x34, 0x56}, []byte{0x00, 0x00, 0x00}},
		{"Key longer than data", []byte{0x11, 0x22}, []byte{0x0F, 0xF0, 0x0F}, []byte{0x1E, 0xD2}},
		{"All zero data", []byte{0x00, 0x00, 0x00}, []byte{0xAA, 0xBB, 0xCC}, []byte{0xAA, 0xBB, 0xCC}},
		{"All zero key", []byte{0xAA, 0xBB, 0xCC}, []byte{0x00, 0x00, 0x00}, []byte{0xAA, 0xBB, 0xCC}},
		{"Large dataset", bytes.Repeat([]byte{0xAB}, 1000), []byte{0xCD}, bytes.Repeat([]byte{0x66}, 1000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil && tt.want == nil {
					t.Logf("Expected panic for empty key: %v", r)
				} else if r != nil {
					t.Errorf("Unexpected panic: %v", r)
				}
			}()

			got := xor(tt.data, tt.key)

			if !bytes.Equal(got, tt.want) {
				t.Errorf("xor(%v, %v) = %v, want %v", tt.data, tt.key, got, tt.want)
			}
		})
	}
}

func TestOddParity(t *testing.T) {
	tests := []struct {
		name  string
		input int
		want  int
	}{
		{"All zero bits (even parity)", 0b00000000, 0},      // 0 has even parity
		{"Single 1 bit (odd parity)", 0b00000001, 1},        // 1 bit set
		{"Two 1 bits (even parity)", 0b00000011, 0},         // 2 bits set
		{"Three 1 bits (odd parity)", 0b00000111, 1},        // 3 bits set
		{"Four 1 bits (even parity)", 0b00001111, 0},        // 4 bits set
		{"All ones (even parity)", 0b11111111, 0},           // 8 bits set → even parity
		{"Large number odd parity", 0b1011001100110011, 1},  // 9 bits set → odd parity
		{"Large number even parity", 0b1100110011001100, 0}, // 8 bits set → even parity
		{"Random odd parity", 0b101010101, 1},               // 5 bits set → odd parity
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := oddParity(tt.input)
			if got != tt.want {
				t.Errorf("oddParity(%b) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestAsciiAlphanumeric(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Empty string", "", true},                                 // No invalid characters
		{"Lowercase letters", "hello", true},                       // All lowercase letters
		{"Uppercase letters", "HELLO", true},                       // All uppercase letters
		{"Numbers only", "123456", true},                           // Only numbers
		{"Mixed alphanumeric", "Test123", true},                    // Combination of letters and numbers
		{"Contains space", "Hello World", false},                   // Space is not allowed
		{"Contains special characters", "abc@123", false},          // Special characters not allowed
		{"Contains underscore", "abc_def", false},                  // Underscore is not allowed
		{"Contains hyphen", "abc-def", false},                      // Hyphen is not allowed
		{"Long alphanumeric string", "A1b2C3D4E5F6G7H8I9J0", true}, // Valid long alphanumeric string
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := asciiAlphanumeric(tt.input)
			if got != tt.want {
				t.Errorf("asciiAlphanumeric(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name string
		str  string
		char rune
		want bool
	}{
		{"Character in string", "hello", 'e', true},      // 'e' is in "hello"
		{"Character at beginning", "world", 'w', true},   // 'w' is at the beginning of "world"
		{"Character at end", "hello", 'o', true},         // 'o' is at the end of "hello"
		{"Character not in string", "hello", 'z', false}, // 'z' is not in "hello"
		{"Empty string", "", 'a', false},                 // Empty string, no character to find
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.str, tt.char)
			if got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.str, tt.char, got, tt.want)
			}
		})
	}
}

func TestAsciiNumeric(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Empty string", "", true},                          // Empty string is valid (no non-numeric chars)
		{"Only digits", "123456", true},                     // Only digits
		{"Digits with space", "123 456", false},             // Space is not allowed
		{"Digits with letters", "123abc", false},            // Letters mixed with digits
		{"Single digit", "7", true},                         // Single digit
		{"Digits with special character", "123@456", false}, // Special character is not allowed
		{"Alphanumeric string", "abc123", false},            // Alphanumeric string is invalid
		{"Digits with leading zero", "01234", true},         // Leading zero should be allowed
		{"Digits with punctuation", "12,34", false},         // Punctuation is not allowed
		{"Valid number with digits", "999999", true},        // Valid all digits string
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := asciiNumeric(tt.input)
			if got != tt.want {
				t.Errorf("asciiNumeric(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestAsciiPrintable(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Empty string", "", true},                                       // Empty string is valid
		{"Only printable characters", "Hello World!", true},              // All characters are printable
		{"Contains newline", "Hello\nWorld", false},                      // Contains newline, invalid
		{"Contains tab", "Hello\tWorld", false},                          // Contains tab, invalid
		{"Contains non-printable char", "Hello\x01World", false},         // Contains non-printable char (ASCII 1), invalid
		{"Only digits", "1234567890", true},                              // Only digits, valid
		{"Only lowercase letters", "abcdefghijklmnopqrstuvwxyz", true},   // Only lowercase letters, valid
		{"Only uppercase letters", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", true},   // Only uppercase letters, valid
		{"Only punctuation", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", true}, // Only punctuation, valid
		{"Valid string with spaces", "Hello World", true},                // Valid string with spaces
		{"Contains special character", "Hello@World", true},              // Valid string with special char
		{"Invalid string with control char", "Hello\x02World", false},    // Contains control char (ASCII 2), invalid
		{"String with numbers and letters", "abc123", true},              // Numbers and letters, valid
		{"String with escape sequence", "Hello\\World", true},            // Escape sequence (backslash) is valid
		{"String with some special characters", "Hello$World", true},     // Valid string with special chars
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := asciiPrintable(tt.input)
			if got != tt.want {
				t.Errorf("asciiPrintable(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsAsciiHex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Empty string", "", false},                      // Empty string is invalid (hex should have at least one character)
		{"Only hex digits", "123ABC", true},              // Only valid hex digits
		{"Only lowercase hex digits", "abcdef", true},    // Only lowercase hex digits
		{"Only uppercase hex digits", "ABCDEF", true},    // Only uppercase hex digits
		{"Mixed case hex digits", "aBcDeF", true},        // Mixed case, still valid
		{"Contains non-hex character", "123GHI", false},  // Contains non-hex characters (G, H, I)
		{"Contains spaces", "1 2 3 4", false},            // Contains spaces, invalid
		{"Contains special characters", "123$#@", false}, // Contains special characters, invalid
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAsciiHex(tt.input)
			if got != tt.want {
				t.Errorf("isAsciiHex(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBytesToInt(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  int64
	}{
		{"Valid 8-byte value", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 1},    // 8-byte value
		{"Valid 8-byte value", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF}, 255},  // 8-byte value (large number)
		{"All zeros", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0},             // All bytes are zero
		{"Valid negative value", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, -1}, // All bytes set to 0xFF
		{"One byte", []byte{0x01}, 0},        // Slice is too small, should return 0
		{"Two bytes", []byte{0x01, 0x02}, 0}, // Slice is too small, should return 0
		{"Valid 8-byte big number", []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, 16777216},         // 8-byte big number
		{"Edge case max int64", []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 9223372036854775807},  // Maximum value for int64
		{"Edge case min int64", []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, -9223372036854775808}, // Minimum value for int64
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bytesToInt(tt.input)
			if got != tt.want {
				t.Errorf("bytesToInt(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIntToBytes(t *testing.T) {
	tests := []struct {
		name   string
		input  int
		length int
		want   []byte
	}{
		{"8-byte value", 123456789, 8, []byte{0x00, 0x00, 0x00, 0x00, 0x07, 0x5B, 0xCD, 0x15}},  // Standard 8-byte conversion
		{"4-byte value", 123456, 4, []byte{0x00, 0x01, 0xE2, 0x40}},                             // 4-byte conversion (larger value)
		{"1-byte value", 5, 1, []byte{0x05}},                                                    // 1-byte value (single byte)
		{"2-byte value", 1025, 2, []byte{0x04, 0x01}},                                           // 2-byte value (binary: 00000100 00000001)
		{"6-byte value", 123456789, 6, []byte{0x00, 0x00, 0x07, 0x5B, 0xCD, 0x15}},              // 6-byte conversion
		{"Smallest possible int", 0, 8, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, // 0 should return all zeros
		{"Largest 4-byte int", 2147483647, 4, []byte{0x7F, 0xFF, 0xFF, 0xFF}},                   // Max 4-byte value (2147483647)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intToBytes(tt.input, tt.length)
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("intToBytes(%d, %d) = %v, want %v", tt.input, tt.length, got, tt.want)
					break
				}
			}
		})
	}
}

func TestHexToInt(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"Valid hex 1", "1A", 26},          // Hexadecimal '1A' should be 26 in decimal
		{"Valid hex 2", "FF", 255},         // Hexadecimal 'FF' should be 255 in decimal
		{"Valid hex 3", "ABC", 2748},       // Hexadecimal 'ABC' should be 2748 in decimal
		{"Valid hex 4", "10", 16},          // Hexadecimal '10' should be 16 in decimal
		{"Valid hex 5", "0", 0},            // Hexadecimal '0' should be 0 in decimal
		{"Valid hex 6", "123ABC", 1194684}, // Hexadecimal '123ABC' should be 1194684 in decimal
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hexToInt(tt.input)
			if got != tt.want {
				t.Errorf("hexToInt(%s) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestStringToInt(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"Valid positive number 1", "123", 123},           // Converts "123" to 123
		{"Valid positive number 2", "4567", 4567},         // Converts "4567" to 4567
		{"Valid single digit", "9", 9},                    // Converts "9" to 9
		{"Valid number with leading zeros", "00123", 123}, // Converts "00123" to 123 (leading zeros are ignored)
		{"Empty string", "", 0},                           // Converts empty string to 0
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stringToInt(tt.input)
			if got != tt.want {
				t.Errorf("stringToInt(%s) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestUrandom(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"Test length 0", 0},       // Edge case: zero length
		{"Test length 1", 1},       // Smallest non-zero length
		{"Test length 5", 5},       // Random length
		{"Test length 8", 8},       // Common byte length (like block size)
		{"Test length 10", 10},     // Slightly larger length
		{"Test length 16", 16},     // Typical length used in many cryptographic systems
		{"Test length 32", 32},     // Larger length, checking if it works for bigger sizes
		{"Test length 64", 64},     // Common size for buffers or keys
		{"Test length 128", 128},   // Larger buffer size
		{"Test length 1024", 1024}, // Very large length for stress test

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := urandom(t, tt.length)
			if len(got) != tt.length {
				t.Errorf("urandom(%d) = len(%d), want len(%d)", tt.length, len(got), tt.length)
			}

			// Ensure the random bytes are in the valid range [0, 255]
			for _, b := range got {
				t.Errorf("urandom(%d) generated an invalid byte: %d", tt.length, b)
			}
		})
	}
}

func TestCompareMAC(t *testing.T) {
	tests := []struct {
		name string
		mac1 []byte
		mac2 []byte
		want bool
	}{
		{"Equal MACs", []byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x03}, true},                                              // Identical MACs
		{"Different MACs", []byte{0x01, 0x02, 0x03}, []byte{0x04, 0x05, 0x06}, false},                                         // Different MACs
		{"Different length MACs", []byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02}, false},                                        // Different lengths
		{"Empty MACs", []byte{}, []byte{}, true},                                                                              // Both are empty
		{"Empty MAC1", []byte{}, []byte{0x01, 0x02, 0x03}, false},                                                             // MAC1 is empty, MAC2 is not
		{"Empty MAC2", []byte{0x01, 0x02, 0x03}, []byte{}, false},                                                             // MAC2 is empty, MAC1 is not
		{"One byte different", []byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x04}, false},                                     // One byte differs
		{"Identical MACs with larger size", []byte{0x01, 0x02, 0x03, 0x04, 0x05}, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, true}, // Identical larger MACs
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareMAC(tt.mac1, tt.mac2)
			if got != tt.want {
				t.Errorf("compareMAC(%v, %v) = %v, want %v", tt.mac1, tt.mac2, got, tt.want)
			}
		})
	}
}

func TestCompareByte(t *testing.T) {
	tests := []struct {
		name string
		src  []byte
		dst  []byte
		want bool
	}{
		{"Equal bytes", []byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x03}, true},
		{"Different bytes", []byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x04}, false},
		{"Different lengths (src longer)", []byte{0x01, 0x02, 0x03, 0x04}, []byte{0x01, 0x02, 0x03}, false},
		{"Different lengths (dst longer)", []byte{0x01, 0x02, 0x03}, []byte{0x01, 0x02, 0x03, 0x04}, false},
		{"Both empty slices", []byte{}, []byte{}, true},
		{"One empty, one non-empty", []byte{}, []byte{0x01}, false},
		{"Identical long slices", []byte("hello world"), []byte("hello world"), true},
		{"Different long slices", []byte("hello world"), []byte("Hello World"), false},
		{"Single byte match", []byte{0xFF}, []byte{0xFF}, true},
		{"Single byte mismatch", []byte{0xFF}, []byte{0x00}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareByte(tt.src, tt.dst)
			if got != tt.want {
				t.Errorf("CompareByte(%v, %v) = %v, want %v", tt.src, tt.dst, got, tt.want)
			}
		})
	}
}
