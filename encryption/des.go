package encryption

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// ApplyKeyVariant applies the variant to the most significant byte of each DES key pair.
func ApplyKeyVariant(key []byte, variant int) ([]byte, error) {
	if len(key) != 8 && len(key) != 16 && len(key) != 24 {
		return nil, fmt.Errorf("Key must be a single, double or triple DES key")
	}

	if variant < 0 || variant > 31 {
		return nil, fmt.Errorf("Variant must be in the range of 0 to 31")
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
		return nil, fmt.Errorf("Key must be a single, double or triple DES key")
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

// GenerateKCV generates the DES key checksum value (KCV).
func GenerateKCV(key []byte, length int) ([]byte, error) {
	if len(key) != 8 && len(key) != 16 && len(key) != 24 {
		return nil, fmt.Errorf("Key must be a single, double or triple DES key")
	}

	// Initialize the cipher block
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	// Create an initialization vector (IV) with all zeroes
	iv := make([]byte, des.BlockSize)

	// Encrypt the data with the key
	cbc := cipher.NewCBCEncrypter(block, iv)
	kcv := make([]byte, length)
	cbc.CryptBlocks(kcv, make([]byte, des.BlockSize))

	return kcv, nil
}

// EncryptTDESCBC encrypts data using Triple DES CBC algorithm.
func EncryptTDESCBC(key, iv, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("Data length must be multiple of DES block size 8")
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	encryptedData := make([]byte, len(data))
	cbc.CryptBlocks(encryptedData, data)

	return encryptedData, nil
}

// EncryptTDSECB encrypts data using Triple DES ECB algorithm.
func EncryptTDSECB(key, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("Data length must be multiple of DES block size 8")
	}

	block, err := des.NewTripleDESCipher(key)
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

// DecryptTDESCBC decrypts data using Triple DES CBC algorithm.
func DecryptTDESCBC(key, iv, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("Data length must be multiple of DES block size 8")
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	decryptedData := make([]byte, len(data))
	cbc.CryptBlocks(decryptedData, data)

	return decryptedData, nil
}

// DecryptTDSECB decrypts data using Triple DES ECB algorithm.
func DecryptTDSECB(key, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("Data length must be multiple of DES block size 8")
	}

	block, err := des.NewTripleDESCipher(key)
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
