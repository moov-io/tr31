package encryption

import (
	"crypto/aes"
	"testing"
)

func TestEncryptAESCBC_KeySizes(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{"AES-128", 16, false},
		{"AES-192", 24, false},
		{"AES-256", 32, false},
		{"Invalid size", 20, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			iv := make([]byte, aes.BlockSize)
			data := make([]byte, aes.BlockSize)

			_, err := EncryptAESCBC(key, iv, data)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptAESCBC() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncryptAESCBC(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		iv      []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "Valid AES-128 encryption",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Valid AES-256 encryption",
			key:     make([]byte, 32),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Data length not multiple of block size",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize-1),
			wantErr: true,
		},
		{
			name:    "Invalid key size (too short)",
			key:     make([]byte, 10),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize),
			wantErr: true,
		},
		{
			name:    "Invalid key size (not 16, 24, or 32 bytes)",
			key:     make([]byte, 20),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize),
			wantErr: true,
		},
		{
			name:    "Invalid IV size (too short)",
			key:     make([]byte, 16),
			iv:      make([]byte, 10),
			data:    make([]byte, aes.BlockSize),
			wantErr: true,
		},
		{
			name:    "Invalid IV size (too long)",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize+5),
			data:    make([]byte, aes.BlockSize),
			wantErr: true,
		},
		{
			name:    "Empty data input",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize),
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "All-zero input data",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Long data (multiple blocks)",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize*4),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptAESCBC(tt.key, tt.iv, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptAESCBC() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestEncryptAESECB(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "Valid AES-128 encryption",
			key:     make([]byte, 16),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Valid AES-256 encryption",
			key:     make([]byte, 32),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Data length not multiple of block size",
			key:     make([]byte, 16),
			data:    make([]byte, aes.BlockSize-1),
			wantErr: true,
		},
		{
			name:    "Invalid key size (too short)",
			key:     make([]byte, 10),
			data:    make([]byte, aes.BlockSize),
			wantErr: true,
		},
		{
			name:    "Invalid key size (not 16, 24, or 32 bytes)",
			key:     make([]byte, 20),
			data:    make([]byte, aes.BlockSize),
			wantErr: true,
		},
		{
			name:    "Empty data input",
			key:     make([]byte, 16),
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "All-zero input data",
			key:     make([]byte, 16),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Long data (multiple blocks)",
			key:     make([]byte, 16),
			data:    make([]byte, aes.BlockSize*4),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptAESECB(tt.key, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptAESECB() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestDecryptAESCBC(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		iv      []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "Valid AES-128 decryption",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Valid AES-256 decryption",
			key:     make([]byte, 32),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Data length not multiple of block size",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize-1),
			wantErr: true,
		},
		{
			name:    "Invalid key size (too short)",
			key:     make([]byte, 10),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize),
			wantErr: true,
		},
		{
			name:    "Invalid IV size",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize-1),
			data:    make([]byte, aes.BlockSize),
			wantErr: true,
		},
		{
			name:    "Empty data input",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize),
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "All-zero input data",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Long data (multiple blocks)",
			key:     make([]byte, 16),
			iv:      make([]byte, aes.BlockSize),
			data:    make([]byte, aes.BlockSize*4),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptAESCBC(tt.key, tt.iv, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptAESCBC() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestDecryptAESECB(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "Valid AES-128 decryption",
			key:     make([]byte, 16),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Valid AES-256 decryption",
			key:     make([]byte, 32),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Data length not multiple of block size",
			key:     make([]byte, 16),
			data:    make([]byte, aes.BlockSize-1),
			wantErr: true,
		},
		{
			name:    "Invalid key size (too short)",
			key:     make([]byte, 10),
			data:    make([]byte, aes.BlockSize),
			wantErr: true,
		},
		{
			name:    "Empty data input",
			key:     make([]byte, 16),
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "All-zero input data",
			key:     make([]byte, 16),
			data:    make([]byte, aes.BlockSize),
			wantErr: false,
		},
		{
			name:    "Long data (multiple blocks)",
			key:     make([]byte, 16),
			data:    make([]byte, aes.BlockSize*4),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptAESECB(tt.key, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptAESECB() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
