package server

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/moov-io/tr31/pkg/encryption"
	"time"
)

type UnifiedParams struct {
	VaultAddr  string
	VaultToken string
	KeyPath    string
	KeyName    string
	KeyBlock   string
	timeout    time.Duration
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
	kbpkStr, err := readKey(params.VaultAddr, params.VaultToken, params.KeyPath, params.KeyName, params.timeout)
	if err != nil {
		return "", errors.New(err.Message)
	}
	kbpk, decErr := hex.DecodeString(kbpkStr)
	if decErr != nil {
		return "", decErr
	}
	block, bErr := encryption.NewKeyBlock(kbpk, nil)
	if bErr != nil {
		return "", bErr
	}
	resultKB, wErr := block.Unwrap(params.KeyBlock)
	if wErr != nil {
		return "", wErr
	}
	encodedStr := hex.EncodeToString(resultKB)
	return encodedStr, nil
}
