package tr31

import (
	"encoding/binary"
	"errors"
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

func GenerateCBCMAC(key []byte, data []byte, padding int, length int, algorithm Algorithm) ([]byte, error) {
	if padding == 0 {
		return nil, fmt.Errorf("specify valid padding method: 1, 2 or 3")
	}
	if key == nil {
		return nil, fmt.Errorf("invalid key")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid data")
	}
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
	if padding > 3 {
		return nil, errors.New("specify valid padding method: 1, 2 or 3")
	}
	paddedData, err := _padDispatch[padding](data, blockSize)
	if err != nil {
		return nil, fmt.Errorf("invalid padding method: %v", err)
	}

	// Encrypt the data
	mac, err := implementation(key, make([]byte, blockSize), paddedData)
	if err != nil {
		return nil, err
	}
	mac = mac[len(mac)-blockSize:]
	return mac[:length], nil
}

func generateRetailMAC(key1 []byte, key2 []byte, data []byte, padding int, length int) ([]byte, error) {
	if padding == 0 || padding > 3 {
		return nil, errors.New("specify valid padding method: 1, 2 or 3")
	}
	if key1 == nil || key2 == nil {
		return nil, errors.New("invalid key")
	}
	if len(data) == 0 {
		return nil, errors.New("invalid data")
	}
	if length == 0 {
		length = 8
	}

	paddedData, err := _padDispatch[padding](data, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid padding method: %v", err)
	}

	// First, encrypt using key1
	encData, err := EncryptTDESCBC(key1, make([]byte, 8), paddedData)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypt using key1: %v", err)
	}
	encData = encData[len(encData)-8:]
	// Then, encrypt the last block using TDES with key2 and key1
	data, err = EncryptTDESCBC(key2, encData, encData)
	if err != nil {
		return nil, fmt.Errorf("encrypt the last block using TDES with key2 and key1: %v", err)
	}
	return data[:length], nil
}

func padISO1(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		blockSize = 8 // Default block size
	}
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
	if blockSize <= 0 {
		blockSize = 8 // Default block size
	}
	data = append(data, 0x80)
	return padISO1(data, blockSize)
}

func padISO3(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		blockSize = 8 // Default block size
	}
	lengthBytes := make([]byte, blockSize)
	if blockSize < 4 {
		value := uint64(len(data)) * 8
		for i := 0; i < blockSize; i++ {
			lengthBytes[i] = byte(value >> (8 * (blockSize - 1 - i))) // Extract highest bytes first
		}
	} else if blockSize < 8 {
		if len(lengthBytes) < 4 {
			return nil, errors.New("lengthBytes slice must be at least 4 bytes for PutUint32")
		}
		dataLen := len(data)
		maxAllowed := (1 << 29) - 1 // 536,870,911
		if dataLen > maxAllowed {
			return nil, errors.New("data length too large to encode as uint32")
		}
		// Cast to uint64 first to prevent int overflow during multiplication
		binary.BigEndian.PutUint32(lengthBytes, uint32(uint64(dataLen)*8))
	} else {
		if len(lengthBytes) < 8 {
			return nil, errors.New("lengthBytes slice must be at least 8 bytes for PutUint64")
		}
		dataLen := len(data)
		maxAllowed := (1 << 61) - 1 // 2,305,843,009,213,693,951
		if dataLen > maxAllowed {
			return nil, errors.New("data length too large to encode as uint64")
		}
		// Safe conversion: uint64 before multiplication
		binary.BigEndian.PutUint64(lengthBytes, uint64(dataLen)*8)
	}
	paddedData, err := padISO1(data, blockSize)
	if err != nil {
		return nil, err
	}
	return append(lengthBytes, paddedData...), nil
}
