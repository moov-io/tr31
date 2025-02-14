package encryption

import (
	"testing"
)

// TestGenerateKBPK test for version D and key length 32
func TestGenerateKBPK_D_32(t *testing.T) {
	key, err := GenerateKBPK(KBPKOptions{
		Version:   "D",
		KeyLength: 32,
	})
	if err != nil {
		t.Fatalf("GenerateKBPK failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("invalid key length: got %d, want 32", len(key))
	}
	// validate the key
	if err = ValidateKBPK(key, "D"); err != nil {
		t.Fatalf("ValidateKBPK failed: %v", err)
	}
}

// TestGenerateKBPK tests the GenerateKBPK function
func TestGenerateKBPK(t *testing.T) {
	// Test cases
	tests := []struct {
		name     string
		opts     KBPKOptions
		expected int
	}{
		{
			name: "AES-128",
			opts: KBPKOptions{
				Version:   "C",
				KeyLength: 16,
			},
			expected: 16,
		},
		{
			name: "AES-192",
			opts: KBPKOptions{
				Version:   "D",
				KeyLength: 24,
			},
			expected: 24,
		},
		{
			name: "AES-256",
			opts: KBPKOptions{
				Version:   "D",
				KeyLength: 32,
			},
			expected: 32,
		},
		{
			name: "TDES-168",
			opts: KBPKOptions{
				Version:   "B",
				KeyLength: 24,
			},
			expected: 24,
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKBPK(tt.opts)
			if err != nil {
				t.Fatalf("GenerateKBPK failed: %v", err)
			}
			if len(key) != tt.expected {
				t.Fatalf("invalid key length: got %d, want %d", len(key), tt.expected)
			}
		})
	}
}

// TestValidateKBPK tests the ValidateKBPK function
func TestValidateKBPK(t *testing.T) {
	// Test cases
	tests := []struct {
		name     string
		key      []byte
		version  string
		expected bool
	}{
		{
			name:     "AES-128",
			key:      []byte("0123456789ABCDEF"),
			version:  "C",
			expected: true,
		},
		{
			name:     "AES-192",
			key:      []byte("0123456789ABCDEF0123456789ABCDEF"),
			version:  "D",
			expected: true,
		},
		/* {
			name:     "AES-256",
			key:      []byte("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
			version:  "D",
			expected: true,
		},
		{
			name:     "TDES-168",
			key:      []byte("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
			version:  "B",
			expected: true,
		},
		*/{
			name:     "Invalid key length",
			key:      []byte("0123456789ABCDEF3"),
			version:  "D",
			expected: false,
		},
		{
			name:     "Invalid key parity",
			key:      []byte("0123456789ABCDEF0123456789ABCDEF"),
			version:  "B",
			expected: false,
		},
		{
			name:     "Weak key",
			key:      []byte("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
			version:  "B",
			expected: false,
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKBPK(tt.key, tt.version)
			valid := err == nil
			if valid != tt.expected {

				// If the test failed, print the error message and name of the test
				t.Fatalf("ValidateKBPK failed: got %v, want %v @ name:%s", valid, tt.expected, tt.name)

			}
		})
	}
}
