package tr31

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// EncryptAESCBC encrypts data using AES CBC algorithm
func EncryptAESCBC(key []byte, iv []byte, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("Data is empty")
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data length (%d) must be a multiple of AES block size %d", len(data), aes.BlockSize)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV length (%d) must be a equal of AES block size %d", len(data), aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(data))
	blockMode.CryptBlocks(encrypted, data)
	return encrypted, nil
}

// EncryptAESECB encrypts data using AES ECB algorithm
func EncryptAESECB(key []byte, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("Data is empty")
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data length (%d) must be a multiple of AES block size %d", len(data), aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Encrypt(encrypted[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}

	return encrypted, nil
}

// DecryptAESCBC decrypts data using AES CBC algorithm
func DecryptAESCBC(key []byte, iv []byte, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("Data is empty")
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data length (%d) must be a multiple of AES block size %d", len(data), aes.BlockSize)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV length (%d) must be a equal of AES block size %d", len(data), aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	blockMode.CryptBlocks(decrypted, data)

	return decrypted, nil
}

// DecryptAESECB decrypts data using AES ECB algorithm
func DecryptAESECB(key []byte, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("Data is empty")
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data length (%d) must be a multiple of AES block size %d", len(data), aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(decrypted[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}

	return decrypted, nil
}
