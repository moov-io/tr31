package server

import (
	"bytes"
	"encoding/hex"
	"github.com/moov-io/tr31/pkg/encryption"
)

type UnifiedParams struct {
	VaultAddr  string
	VaultToken string
	KeyPath    string
	KeyName    string
	KeyBlock   string
}

type WrapperCall func(params UnifiedParams) (string, error)

func InitialKey(params UnifiedParams) (string, error) {
	planData := []byte(params.VaultAddr + params.VaultToken)
	kbpk := bytes.Repeat([]byte("E"), 24)
	encData, err := encryption.GenerateCBCMAC(kbpk, planData, 1, 8, encryption.DES)
	if err != nil {
		return "", err
	}
	identify := hex.EncodeToString(encData)
	return identify, err
}
func TransactionKey(params UnifiedParams) (string, error) {
	planData := []byte(params.VaultAddr + params.VaultToken)
	kbpk := bytes.Repeat([]byte("F"), 24)
	encData, err := encryption.GenerateCBCMAC(kbpk, planData, 1, 8, encryption.DES)
	if err != nil {
		return "", err
	}
	identify := hex.EncodeToString(encData)
	return identify, nil
}

func DecryptData(params UnifiedParams) (string, error) {
	kbpkStr, _ := readKey(params.VaultAddr, params.VaultToken, params.KeyPath, params.KeyName)
	kbpk, _ := hex.DecodeString(kbpkStr)
	block, _ := encryption.NewKeyBlock(kbpk, nil)
	resultKB, _ := block.Unwrap(params.KeyBlock)
	encodedStr := hex.EncodeToString(resultKB)
	return encodedStr, nil
}
