package tr31

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
	"fmt"
)

// ApplyKeyVariant applies the variant to the most significant byte of each DES key pair.
func ApplyKeyVariant(key []byte, variant int) ([]byte, error) {
	if len(key) != 8 && len(key) != 16 && len(key) != 24 {
		return nil, errors.New("key must be a single, double or triple DES key")
	}

	if variant < 0 || variant > 31 {
		return nil, errors.New("variant must be in the range of 0 to 31")
	}

	mask := make([]byte, len(key))
	shiftedVariant := byte(8 * variant)
	for i := 0; i < len(mask); i++ {
		mask[i] = shiftedVariant
	}

	return xor(key, mask), nil
}

// AdjustKeyParity adjusts the DES key parity to ensure odd parity.
func AdjustKeyParity(key []byte) ([]byte, error) {
	if len(key) != 8 && len(key) != 16 && len(key) != 24 {
		return nil, fmt.Errorf("key must be a single, double or triple DES key")
	}

	adjustedKey := make([]byte, len(key))
	copy(adjustedKey, key)

	for i, byteVal := range adjustedKey {
		if !hasOddParity(byteVal) {
			adjustedKey[i] ^= 1
		}
	}

	return adjustedKey, nil
}

// hasOddParity checks if a byte has odd parity.
func hasOddParity(b byte) bool {
	return bitsOn(b)%2 == 1
}

// bitsOn counts the number of bits set to 1.
func bitsOn(b byte) int {
	count := 0
	for b != 0 {
		b &= b - 1
		count++
	}
	return count
}

// Encrypt3DESCBC encrypts plaintext using 3DES in CBC mode with the provided 16-byte key.
//
//gosec:disable G502 -- Legacy system requires 3DES
func EncryptTDESCBC(key, iv, data []byte) ([]byte, error) {
	if len(key) != 8 && len(key) != 16 && len(key) != 24 {
		return nil, fmt.Errorf("key length must be 8, 16, 24 bytes")
	}
	if len(iv) != 8 {
		return nil, fmt.Errorf("iv length must be 8 bytes")
	}
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("data length must be a multiple of 8")
	}
	// Create a 24-byte key for 3DES by appending the first 8 bytes of the key to itself.
	desKey := append(key, key[:8]...)
	if len(key) == 24 {
		desKey = key
	} else if len(key) == 8 {
		desKey = append(desKey, key...)
	}
	block, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create 3DES cipher: %v", err)
	}

	// Encrypt the padded plaintext.
	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)
	return ciphertext, nil
}

// Decrypt3DESCBC decrypts ciphertext using 3DES in CBC mode with the provided 16-byte key and IV.
func DecryptTDESCBC(key, iv, data []byte) ([]byte, error) {
	if len(key) != 8 && len(key) != 16 && len(key) != 24 {
		return nil, fmt.Errorf("key length must be 8, 16, 24 bytes")
	}
	if len(iv) != 8 {
		return nil, fmt.Errorf("iv length must be 8 bytes")
	}
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("data length must be a multiple of 8")
	}

	// Create a 24-byte key for 3DES by appending the first 8 bytes of the key to itself.
	desKey := append(key, key[:8]...)
	if len(key) == 24 {
		desKey = key
	} else if len(key) == 8 {
		desKey = append(desKey, key...)
	}

	block, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create 3DES cipher: %v", err)
	}

	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("invalid IV length: expected %d bytes, got %d", block.BlockSize(), len(iv))
	}

	if len(data)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	// Decrypt the ciphertext.
	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, data)

	return plaintext, nil
}

// EncryptTDSECB encrypts data using Triple DES ECB algorithm.
func EncryptTDSECB(key, data []byte) ([]byte, error) {
	if len(key) != 8 && len(key) != 16 && len(key) != 24 {
		return nil, fmt.Errorf("key length must be 16 bytes")
	}
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("data length must be multiple of DES block size 8")
	}
	// Create a 24-byte key for 3DES by appending the first 8 bytes of the key to itself.
	desKey := append(key, key[:8]...)
	if len(key) == 24 {
		desKey = key
	} else if len(key) == 8 {
		desKey = append(desKey, key...)
	}
	block, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}

	// ECB mode does not require an IV
	encryptedData := make([]byte, len(data))
	for i := 0; i < len(data); i += des.BlockSize {
		block.Encrypt(encryptedData[i:i+des.BlockSize], data[i:i+des.BlockSize])
	}

	return encryptedData, nil
}

// DecryptTDSECB decrypts data using Triple DES ECB algorithm.
func DecryptTDSECB(key, data []byte) ([]byte, error) {
	if len(key) != 8 && len(key) != 16 && len(key) != 24 {
		return nil, fmt.Errorf("key length must be 16 bytes")
	}
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("data length must be multiple of DES block size 8")
	}
	desKey := append(key, key[:8]...)
	if len(key) == 24 {
		desKey = key
	} else if len(key) == 8 {
		desKey = append(desKey, key...)
	}
	block, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}

	// ECB mode does not require an IV
	decryptedData := make([]byte, len(data))
	for i := 0; i < len(data); i += des.BlockSize {
		block.Decrypt(decryptedData[i:i+des.BlockSize], data[i:i+des.BlockSize])
	}

	return decryptedData, nil
}

//gosec:enable G502
