package encryption

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type Algorithm int

const (
	DES Algorithm = iota
	AES
)

var _padDispatch = map[int]func(data []byte, blockSize int) ([]byte, error){
	1: padISO1,
	2: padISO2,
	3: padISO3,
}

func generateCBCMAC(key []byte, data []byte, padding int, length int, algorithm Algorithm) ([]byte, error) {
	if length == 0 {
		if algorithm == AES {
			length = 16
		} else {
			length = 8
		}
	}

	implementation := EncryptTDESCBC
	blockSize := 8

	if algorithm == DES {
		blockSize = 8
		implementation = EncryptTDESCBC
	}
	if algorithm == AES {
		blockSize = 16
		implementation = EncryptAESCBC
	}

	paddedData, err := _padDispatch[padding](data, blockSize)
	if err != nil {
		return nil, fmt.Errorf("invalid padding method: %v", err)
	}

	// Encrypt the data
	mac, err := implementation(key, make([]byte, blockSize), paddedData)
	fmt.Println(hex.EncodeToString(mac))
	mac = mac[len(mac)-blockSize:]
	fmt.Println(hex.EncodeToString(mac))
	return mac[:length], err
}

func generateRetailMAC(key1 []byte, key2 []byte, data []byte, padding int, length int) ([]byte, error) {
	if length == 0 {
		length = 8
	}

	paddedData, err := _padDispatch[padding](data, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid padding method: %v", err)
	}

	// First, encrypt using key1
	data, err = EncryptTDESCBC(key1, make([]byte, 8), paddedData)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypt using key1: %v", err)
	}
	// Then, encrypt the last block using TDES with key2 and key1
	data, err = EncryptTDESCBC(key2, data, data)
	if err != nil {
		return nil, fmt.Errorf("encrypt the last block using TDES with key2 and key1: %v", err)
	}
	return data[:length], nil
}

func padISO1(data []byte, blockSize int) ([]byte, error) {
	remainder := len(data) % blockSize
	if remainder > 0 {
		data = append(data, make([]byte, blockSize-remainder)...)
	}

	if len(data) == 0 {
		data = make([]byte, blockSize)
	}

	return data, nil
}

func padISO2(data []byte, blockSize int) ([]byte, error) {
	data = append(data, 0x80)
	return padISO1(data, blockSize)
}

func padISO3(data []byte, blockSize int) ([]byte, error) {
	lengthBytes := make([]byte, blockSize)
	binary.BigEndian.PutUint64(lengthBytes, uint64(len(data)*8))
	paddedData, err := padISO1(data, blockSize)
	if err != nil {
		return nil, err
	}
	return append(lengthBytes, paddedData...), nil
}
