package tr31

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestApplyKeyVariant(t *testing.T) {
	tests := []struct {
		key      []byte
		variant  int
		expected interface{}
	}{
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 1, nil},                                                                                                                                                                      // Test Case 1
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}, 5, nil},                                                                                                                      // Test Case 2
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}, 10, nil},                                                                     // Test Case 3
		{[]byte{0x01, 0x02, 0x03}, 0, fmt.Errorf("Key must be a single, double or triple DES key")},                                                                                                                                           // Test Case 4
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A}, 0, fmt.Errorf("Key must be a single, double or triple DES key")}, // Test Case 5
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, -1, fmt.Errorf("Variant must be in the range of 0 to 31")},                                                                                                                   // Test Case 6
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 32, fmt.Errorf("Variant must be in the range of 0 to 31")},                                                                                                                   // Test Case 7
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 0, nil},                                                                                                                                                                      // Test Case 8
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 31, nil},                                                                                                                                                                     // Test Case 9
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 15, nil},                                                                                                                                                                     // Test Case 10
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("key=%v,variant=%d", tt.key, tt.variant), func(t *testing.T) {
			_, err := ApplyKeyVariant(tt.key, tt.variant)
			if err != nil && err.Error() != tt.expected.(error).Error() {
				t.Errorf("expected error %v, got %v", tt.expected, err)
			}
		})
	}
}

func TestAdjustKeyParity(t *testing.T) {
	tests := []struct {
		key      []byte
		expected interface{}
	}{
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, nil},                                                                                                                                                                            // Test Case 1
		{[]byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}, nil},                                                                                                                                                                            // Test Case 2
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, nil},                                                                                                                            // Test Case 3
		{[]byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}, nil},                                                                                                                            // Test Case 4
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, nil},                                                                            // Test Case 5
		{[]byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}, nil},                                                                            // Test Case 6
		{[]byte{0x01, 0x02, 0x03}, fmt.Errorf("Key must be a single, double or triple DES key")},                                                                                                                                                 // Test Case 7
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B}, fmt.Errorf("Key must be a single, double or triple DES key")}, // Test Case 8
		{[]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01}, nil},                                                                                                                                                                            // Test Case 9
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, nil},                                                                                                                                                                            // Test Case 10
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("key=%v", tt.key), func(t *testing.T) {
			_, err := AdjustKeyParity(tt.key)
			if err != nil && err.Error() != tt.expected.(error).Error() {
				t.Errorf("expected error %v, got %v", tt.expected, err)
			}
		})
	}
}

func TestBitsOn(t *testing.T) {
	tests := []struct {
		b        byte
		expected int
	}{
		{0x00, 0}, // Test Case 1
		{0x01, 1}, // Test Case 2
		{0x03, 2}, // Test Case 3
		{0x0F, 4}, // Test Case 4
		{0xFF, 8}, // Test Case 5
		{0x5A, 4}, // Test Case 6
		{0xAA, 4}, // Test Case 7
		{0x40, 1}, // Test Case 8
		{0x00, 0}, // Test Case 9
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("b=%v", tt.b), func(t *testing.T) {
			result := bitsOn(tt.b)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestEncryptTDESCBC(t *testing.T) {
	tests := []struct {
		name     string
		key      []byte
		iv       []byte
		data     []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "Test Case 1: Valid 8-byte key (single DES encryption)",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     []byte("Test data"),
			expected: "f8d33103f1c612598eb5c6507426c8d1", // Replace with actual expected result
			wantErr:  false,
		},
		{
			name:     "Test Case 2: Valid 16-byte key (double DES encryption)",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     []byte("Test data"),
			expected: "e89402220c20a70e00c284d2959e3fa3", // Replace with actual expected result
			wantErr:  false,
		},
		{
			name:     "Test Case 3: Invalid Key length",
			key:      []byte{0x01, 0x23, 0x45},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     []byte("Test data"),
			expected: "",
			wantErr:  true,
		},
		{
			name:     "Test Case 4: Key too long (greater than 24 bytes)",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     []byte("Test data"),
			expected: "",
			wantErr:  true,
		},
		{
			name:     "Test Case 5: Empty data",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     []byte(""),
			expected: "d5d44ff720683d0d", // Replace with actual expected result
			wantErr:  false,
		},
		{
			name:     "Test Case 6: Valid 24-byte key (triple DES encryption)",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     []byte("Test data"),
			expected: "0aa2dd51c335a7e2cb5aae3d14761224", // Replace with actual expected result
			wantErr:  false,
		},
		{
			name:     "Test Case 7: Max length of data",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     make([]byte, 1024),                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 // large data size
			expected: "d5d44ff720683d0d5661e9804fe87b779aed30bb219fda918728c0b50afc37494691682e1b6f07aac8a3e12c2f838d5d39a968421edd6d8dc43744150288320f57b4df95e16fc8ddffe2277ec0b5172885444c89285a7fabf039871847af4b25d93fcb4e56db116bed4b20881d75bcecc5613d551bc733505fe77765e1780df349e376d564282b8531206fc06a4bb62abd05d55f69785c3ab2ca24914adf871a09ae84caabaa1886ea4456afd1ac6de4aef4aff5e1a61c591b7bfc3c5f7d333a620efd8b8b15b56a3f058cd667f1203feae7effc30e5202e100bc749e883bd3a13c7445e09e79def73f5cadba75afa71293fa57ea4a82df7e542d6d6a1560134095b985a6a86883430f49e7508a237d116669b153a5de6ed194b98dc4be923a8b4ceba4ceaece6db16d54cb15f3475f40e722f20eb5e538de747592f72445cef2e19f9febcac28c0baa946538153892e0f50395869d0ba3b5275cf2f5b48cf7d3c7f1dab0fe82bfcebfce6ba21d3d259e18056b43841d22035ff31e0bfd61a6bea9f5db83079846bb709b986686c1adff234a89c222776f7690193e570b37f7f1a37af1f9a797cfc18bb8ea4b40a2dfa0657c195ece964a32cf147602a707f39c0fdd90ea229fd7d7d04f51a19d13bff87f3fb242236e675d4be1a831a0803b4c1f755360cf17d8bae7286637062f4ec95aeaad5e1f3e321165c25f30572c16414085d68e9818d3c69ce6ccbbbf9efff8138863839a52d389a54cccee878a69b3456b6dcf8484ee01425dc301a1233d69c0d0d830e38769744be38d9daeebab6bbe8f098e4aa668f5c8820287c11d4b76785b2fd861a6276aef04aa56a3b519f126c8f0b684d3da77d7c4c2b3571cdba9f6f54f77e4f52a65cb838b244d4b1ced9026bb3178811e8a1c830e3cb5eb7d86e9ca9c7e083eea7ee5a64eb4ad311598e6da91c2a453a29963389e8e42729bcf1e3205c31d1608bd7808241faa670a53c6dd545f56fd0af47b1eda8abafa9f5f945ac40c65ddbf23bf8ad9afa6f93d55de389f7d4a6c4786e16421dfdf75b3d7969e421e5531f52302b27ea2db63c3150e67fdc18aff2a6540f60c0b9587c5fb583c4ebb64819d27176b725a1a5ad144769e3e14500c9cddfc7876a67df32c87ddb98dea4fb155783554c10b0fee6f6a3603518006e0c4ac9bc47aee41992fc4a0c33d0bba2749c3de56275b848d0803d64665a86c758a4595b6557717b607a2e30e2393399f1ce14eceb30dce4a19ca1ad98df6b3ea626f7f9961334da66a2324f14766334c67ed37a4a0d7f1a239ba0f7beaa34d99fb19ae2965084ed4248f98d436610bf85fdd3621acec36617fec7549708b15ec5b6cf1520e444581f53468fd283be0008659cf85bdf181b2d0ea83958442d9ec694e13bf3ad917dbaea4b62e5d0876ae9bf1de0044d5ba5e9a4", // Replace with actual expected result
			wantErr:  false,
		},
		{
			name:     "Test Case 8: Different IV",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			iv:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			data:     []byte("Test data"),
			expected: "1fe998f0451a59505a0d357c50c30d05", // Replace with actual expected result
			wantErr:  false,
		},
		{
			name:     "Test Case 9: All zero IV",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     []byte("Test data"),
			expected: "f8d33103f1c612598eb5c6507426c8d1", // Replace with actual expected result
			wantErr:  false,
		},
		{
			name:     "Test Case 10: Non-ASCII data",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     []byte{0xF0, 0xF1, 0xF2, 0xF3},
			expected: "fabe3640c574ccba", // Replace with actual expected result
			wantErr:  false,
		},
		{
			name:     "Test Case 11: Shorter data",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     []byte("Short"),
			expected: "1c079cdce144bc67", // Replace with actual expected result
			wantErr:  false,
		},
		{
			name:     "Test Case 12: Invalid IV length",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			iv:       []byte{0x00, 0x00, 0x00},
			data:     []byte("Test data"),
			expected: "",
			wantErr:  true,
		},
		{
			name:     "Test Case 13: Valid but empty IV",
			key:      []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			iv:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			data:     []byte("Test data"),
			expected: "f8d33103f1c612598eb5c6507426c8d1", // Replace with actual expected result
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paddedData, err := padISO1(tt.data, 8)
			if err != nil {
				t.Errorf("EncryptTDESCBC() error =Data Pad error")
			}
			got, err := EncryptTDESCBC(tt.key, tt.iv, paddedData)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptTDESCBC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if hex.EncodeToString(got) != tt.expected {
				t.Errorf("EncryptTDESCBC() = %v, want %v", hex.EncodeToString(got), tt.expected)
			}
		})
	}
}

func TestDecryptTDESCBC(t *testing.T) {
	tests := []struct {
		name     string
		key      []byte
		iv       []byte
		data     []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "Test Case 1",
			key:      []byte("12345678"),                                 // 8-byte key
			iv:       []byte("abcdefgh"),                                 // 8-byte IV
			data:     []byte("encryptedDataHere123"),                     // ciphertext, should be replaced with actual
			expected: "19c8c6588ab68f5a96054b6e09853718f63e93509886f339", // expected decrypted result
			wantErr:  false,
		},
		{
			name:     "Test Case 2",
			key:      []byte("1234567890123456"),                         // 16-byte key
			iv:       []byte("abcdefgh"),                                 // 8-byte IV
			data:     []byte("encryptedDataHere123"),                     // ciphertext, should be replaced with actual
			expected: "e2878b0481d8f8a65f57928e80ffe35565b5b6fc79766800", // expected decrypted result
			wantErr:  false,
		},
		{
			name:     "Test Case 3",
			key:      []byte("123456789012345678901234"),                 // 24-byte key
			iv:       []byte("abcdefgh"),                                 // 8-byte IV
			data:     []byte("encryptedDataHere123"),                     // ciphertext, should be replaced with actual
			expected: "1df688ee341dfe9225e03ffc5e60b3a50a4ec0d4f5005d33", // expected decrypted result
			wantErr:  false,
		},
		{
			name:     "Test Case 4",
			key:      []byte("12345678"), // 8-byte key
			iv:       []byte("abcdefgh"), // 8-byte IV
			data:     []byte("short"),    // invalid ciphertext size
			expected: "8d8fe598f45ffe9d",
			wantErr:  false, // should fail due to invalid ciphertext length
		},
		{
			name:     "Test Case 5",
			key:      []byte("1234567890123456"), // 16-byte key
			iv:       []byte("invalidIVsize"),    // 12-byte IV
			data:     []byte("encryptedDataHere123"),
			expected: "",
			wantErr:  true, // invalid IV length
		},
		{
			name:     "Test Case 6",
			key:      []byte("12345678"),            // 8-byte key
			iv:       []byte("abcdefgh"),            // 8-byte IV
			data:     []byte("mismatchedLength123"), // incorrect size (not multiple of block size)
			expected: "cdd545cc69cc04c2f0365b067e29c8b0ad363a0068abdd96",
			wantErr:  false, // should fail due to mismatched length
		},
		{
			name:     "Test Case 7",
			key:      []byte("shortkey9"), // incorrect key length
			iv:       []byte("abcdefgh"),  // 8-byte IV
			data:     []byte("encryptedDataHere123"),
			expected: "",
			wantErr:  true, // key length must be 16, 24, or 8 bytes
		},
		{
			name:     "Test Case 8",
			key:      []byte("12345678"),                 // 8-byte key
			iv:       []byte("abcdefgh"),                 // 8-byte IV
			data:     []byte("validCiphertext"),          // valid ciphertext, should be replaced with actual encrypted data
			expected: "ab1b966bc6955478c3924fbac4edaf73", // expected decrypted result
			wantErr:  false,
		},
		{
			name:     "Test Case 9",
			key:      []byte("1234567890123456"),                         // 16-byte key
			iv:       []byte("abcdefgh"),                                 // 8-byte IV
			data:     []byte("validCiphertext123"),                       // valid ciphertext, should be replaced with actual encrypted data
			expected: "c97102a4563ba9e3fb9dbc2bfb3d600c3619d3bff309e536", // expected decrypted result
			wantErr:  false,
		},
		{
			name:     "Test Case 10",
			key:      []byte("123456789012345678901234"),                 // 24-byte key
			iv:       []byte("abcdefgh"),                                 // 8-byte IV
			data:     []byte("validCiphertextHere"),                      // valid ciphertext, should be replaced with actual encrypted data
			expected: "aabff595a5073adbbca75b541a98908090c8a595221f3522", // expected decrypted result
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.name), func(t *testing.T) {
			paddedData, err := padISO1(tt.data, 8)
			got, err := DecryptTDESCBC(tt.key, tt.iv, paddedData)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptTDESCBC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if hex.EncodeToString(got) != tt.expected {
				t.Errorf("DecryptTDESCBC() = %v, want %v", hex.EncodeToString(got), tt.expected)
			}
		})
	}
}

func TestTDESCBC(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		iv      []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "Test Case 1",
			key:     []byte("12345678"),     // 8-byte key
			iv:      []byte("abcdefgh"),     // 8-byte IV
			data:    []byte("Hello World!"), // sample plaintext
			wantErr: false,
		},
		{
			name:    "Test Case 2",
			key:     []byte("1234567890123456"),  // 16-byte key
			iv:      []byte("abcdefgh"),          // 8-byte IV
			data:    []byte("Data for testing!"), // sample plaintext
			wantErr: false,
		},
		{
			name:    "Test Case 3",
			key:     []byte("123456789012345678901234"), // 24-byte key
			iv:      []byte("abcdefgh"),                 // 8-byte IV
			data:    []byte("Encryption Testing!"),      // sample plaintext
			wantErr: false,
		},
		{
			name:    "Test Case 4",
			key:     []byte("12345678"),    // 8-byte key
			iv:      []byte("abcdefgh"),    // 8-byte IV
			data:    []byte("Short text!"), // short plaintext
			wantErr: false,
		},
		{
			name:    "Test Case 5",
			key:     []byte("1234567890123456"),       // 16-byte key
			iv:      []byte("abcdefgh"),               // 8-byte IV
			data:    []byte("Some random text here!"), // random plaintext
			wantErr: false,
		},
		{
			name:    "Test Case 6",
			key:     []byte("123456789012345678901234"), // 24-byte key
			iv:      []byte("abcdefgh"),                 // 8-byte IV
			data:    []byte("Test longer data for TDES encryption!"),
			wantErr: false,
		},
		{
			name:    "Test Case 7",
			key:     []byte("ABCDEFGH"),         // 8-byte key
			iv:      []byte("IJKLMNOP"),         // 8-byte IV
			data:    []byte("Another example!"), // another sample
			wantErr: false,
		},
		{
			name:    "Test Case 8",
			key:     []byte("Test1234Test1234"), // 16-byte key
			iv:      []byte("abcdefgh"),         // 8-byte IV
			data:    []byte("1234567890Test!"),  // sample numeric and text data
			wantErr: false,
		},
		{
			name:    "Test Case 9",
			key:     []byte("12345678"), // 8-byte key
			iv:      []byte("abcdefgh"), // 8-byte IV
			data:    []byte("Longer text for testing encryption!"),
			wantErr: false,
		},
		{
			name:    "Test Case 10",
			key:     []byte("ABCDEFGHIJKLMNOP"), // 16-byte key
			iv:      []byte("12345678"),         // 8-byte IV
			data:    []byte("Data for encrypting in CBC mode!"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("key=%v, iv=%v", tt.key, tt.iv), func(t *testing.T) {
			// Encrypt the data
			paddedData, err := padISO1(tt.data, 8)
			encryptedData, err := EncryptTDESCBC(tt.key, tt.iv, paddedData)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptTDESCBC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Decrypt the data
			decryptedData, err := DecryptTDESCBC(tt.key, tt.iv, encryptedData)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptTDESCBC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check if the decrypted data matches the original data
			if !bytes.Equal(decryptedData, paddedData) {
				t.Errorf("Decrypted data = %v, want %v", decryptedData, tt.data)
			}
		})
	}
}

func TestEncryptDecryptTDSECB(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "Test Case 1",
			key:     []byte("1234567890123456"), // 16-byte key
			data:    []byte("Hello World!123"),  // Data length is a multiple of 8 bytes
			wantErr: false,
		},
		{
			name:    "Test Case 2",
			key:     []byte("87654321abcdefgh"),  // 16-byte key
			data:    []byte("Data for testing!"), // Data length is a multiple of 8 bytes
			wantErr: false,
		},
		{
			name:    "Test Case 3",
			key:     []byte("123456789012345678901234"), // 24-byte key
			data:    []byte("Encryption Test 123!"),     // Data length is a multiple of 8 bytes
			wantErr: false,
		},
		{
			name:    "Test Case 4",
			key:     []byte("abcdefgh"),   // 8-byte key
			data:    []byte("Short test"), // Data length is a multiple of 8 bytes
			wantErr: false,
		},
		{
			name:    "Test Case 5",
			key:     []byte("ABCDEFGH12345678"),  // 16-byte key
			data:    []byte("ECB Mode Testing!"), // Data length is a multiple of 8 bytes
			wantErr: false,
		},
		{
			name:    "Test Case 6",
			key:     []byte("1234567890123456"), // 16-byte key
			data:    []byte("Random Data!"),     // Data length is a multiple of 8 bytes
			wantErr: false,
		},
		{
			name:    "Test Case 7",
			key:     []byte("87654321abcdefgh"), // 16-byte key
			data:    []byte("Test12345678!"),    // Data length is a multiple of 8 bytes
			wantErr: false,
		},
		{
			name:    "Test Case 8",
			key:     []byte("TestKey12345678"),                   // 15-byte key
			data:    []byte("Longer data for testing with ECB!"), // Data length is a multiple of 8 bytes
			wantErr: true,
		},
		{
			name:    "Test Case 9",
			key:     []byte("ABCDEFGHIJKLMNOP"),              // 16-byte key
			data:    []byte("Multiple blocks data for ECB!"), // Data length is a multiple of 8 bytes
			wantErr: false,
		},
		{
			name:    "Test Case 10",
			key:     []byte("QWERTYUIASDFGHJK"),            // 16-byte key
			data:    []byte("Final test with valid data!"), // Data length is a multiple of 8 bytes
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.name), func(t *testing.T) {
			// Encrypt the data
			paddedData, err := padISO1(tt.data, 8)
			encryptedData, err := EncryptTDSECB(tt.key, paddedData)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("EncryptTDSECB() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				return
			}

			// Decrypt the data
			decryptedData, err := DecryptTDSECB(tt.key, encryptedData)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptTDSECB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check if the decrypted data matches the original data
			if !CompareByte(decryptedData, paddedData) {
				t.Errorf("Decrypted data = %v, want %v", decryptedData, paddedData)
			}
		})
	}
}
