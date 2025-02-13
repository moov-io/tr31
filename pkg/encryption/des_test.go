package encryption

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTDesCBCWith16Key8Data(t *testing.T) {
	keyBytes, err := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB")
	if err != nil {
		fmt.Println("Error decoding key:", err)
		return
	}
	dataByte, err := hex.DecodeString("AAAAAAAAAAAAAAAA")
	if err != nil {
		fmt.Println("Error decoding data:", err)
		return
	}
	blockSize := 8
	encriptData, err := EncryptTDESCBC(keyBytes, make([]byte, blockSize), dataByte)
	println(hex.EncodeToString(encriptData))

	decData, err := DecryptTDESCBC(keyBytes, make([]byte, blockSize), encriptData)
	println(hex.EncodeToString(decData))
	assert.Equal(t, true, CompareByte(dataByte, decData))
	//ef99478d77ba6c9d
}
func TestTDesCBCWith16Key16Data(t *testing.T) {
	keyBytes, err := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB")
	if err != nil {
		fmt.Println("Error decoding key:", err)
		return
	}
	dataByte, err := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		fmt.Println("Error decoding data:", err)
		return
	}
	blockSize := 8
	encriptData, err := EncryptTDESCBC(keyBytes, make([]byte, blockSize), dataByte)
	println(hex.EncodeToString(encriptData))

	decData, err := DecryptTDESCBC(keyBytes, make([]byte, blockSize), encriptData)
	println(hex.EncodeToString(decData))
	assert.Equal(t, true, CompareByte(dataByte, decData))
	//ef99478d77ba6c9d4533ed27dd10c637
}
func TestTDesCBCWith16Key24Data(t *testing.T) {
	keyBytes, err := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB")
	if err != nil {
		fmt.Println("Error decoding key:", err)
		return
	}
	dataByte, err := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	pythonData, err := hex.DecodeString("79bd62f07f33fd73853180bc015a7d24b48b11fa0e286506")
	if err != nil {
		fmt.Println("Error decoding data:", err)
		return
	}
	blockSize := 8
	encriptData, err := EncryptTDESCBC(keyBytes, make([]byte, blockSize), dataByte)
	println(hex.EncodeToString(encriptData))

	decData, err := DecryptTDESCBC(keyBytes, make([]byte, blockSize), encriptData)
	println(hex.EncodeToString(decData))
	assert.Equal(t, true, CompareByte(dataByte, decData))
	assert.Equal(t, true, CompareByte(pythonData, encriptData))
	//79bd62f07f33fd73853180bc015a7d24b48b11fa0e286506
}
func TestTDesCBCWith16Key48Data(t *testing.T) {
	keyBytes, err := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB")
	if err != nil {
		fmt.Println("Error decoding key:", err)
		return
	}
	dataByte, err := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	pythonData, err := hex.DecodeString("79bd62f07f33fd73853180bc015a7d24b48b11fa0e2865065d9850146193f9fb0b11f558529005b60cc487165a8da2c5")
	if err != nil {
		fmt.Println("Error decoding data:", err)
		return
	}
	blockSize := 8
	encriptData, err := EncryptTDESCBC(keyBytes, make([]byte, blockSize), dataByte)
	println(hex.EncodeToString(encriptData))

	decData, err := DecryptTDESCBC(keyBytes, make([]byte, blockSize), encriptData)
	println(hex.EncodeToString(decData))
	assert.Equal(t, true, CompareByte(dataByte, decData))
	assert.Equal(t, true, CompareByte(pythonData, encriptData))
	//79bd62f07f33fd73853180bc015a7d24b48b11fa0e286506
}
func TestTDesCBCWith24Key48Data(t *testing.T) {
	keyBytes, err := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	if err != nil {
		fmt.Println("Error decoding key:", err)
		return
	}
	dataByte, err := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	pythonData, err := hex.DecodeString("c3f16bf4fd61f1519a0388ee566c0ba9b34078de1b0a2461041b32e46240c6eadeed7238bf8ca4974e34ef2c79d43863")
	if err != nil {
		fmt.Println("Error decoding data:", err)
		return
	}
	blockSize := 8
	encriptData, err := EncryptTDESCBC(keyBytes, make([]byte, blockSize), dataByte)
	println(hex.EncodeToString(encriptData))

	decData, err := DecryptTDESCBC(keyBytes, make([]byte, blockSize), encriptData)
	println(hex.EncodeToString(decData))
	assert.Equal(t, true, CompareByte(dataByte, decData))
	assert.Equal(t, true, CompareByte(pythonData, encriptData))
	//79bd62f07f33fd73853180bc015a7d24b48b11fa0e286506
}
func TestDecTDesCBCWith16Key8Data(t *testing.T) {
	keyBytes, err := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB")
	if err != nil {
		fmt.Println("Error decoding key:", err)
		return
	}
	planText, err := hex.DecodeString("AAAAAAAAAAAAAAAA")
	dataByte, err := hex.DecodeString("79bd62f07f33fd73")
	if err != nil {
		fmt.Println("Error decoding data:", err)
		return
	}
	blockSize := 8
	result, err := DecryptTDESCBC(keyBytes, make([]byte, blockSize), dataByte)
	println(hex.EncodeToString(result))
	assert.Equal(t, true, CompareByte(planText, result))
	//ef99478d77ba6c9d
}
func TestDecTDesCBCWith16Key16Data(t *testing.T) {
	keyBytes, err := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB")
	if err != nil {
		fmt.Println("Error decoding key:", err)
		return
	}
	planText, err := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	dataByte, err := hex.DecodeString("79bd62f07f33fd73853180bc015a7d24")
	if err != nil {
		fmt.Println("Error decoding data:", err)
		return
	}
	blockSize := 8
	result, err := DecryptTDESCBC(keyBytes, make([]byte, blockSize), dataByte)
	println(hex.EncodeToString(result))
	assert.Equal(t, true, CompareByte(planText, result))
	//ef99478d77ba6c9d
}
func TestDecTDesCBCWith16Key24Data(t *testing.T) {
	keyBytes, err := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB")
	if err != nil {
		fmt.Println("Error decoding key:", err)
		return
	}
	planText, err := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	dataByte, err := hex.DecodeString("79bd62f07f33fd73853180bc015a7d24b48b11fa0e286506")
	if err != nil {
		fmt.Println("Error decoding data:", err)
		return
	}
	blockSize := 8
	result, err := DecryptTDESCBC(keyBytes, make([]byte, blockSize), dataByte)
	println(hex.EncodeToString(result))
	assert.Equal(t, true, CompareByte(planText, result))
	//ef99478d77ba6c9d
}
