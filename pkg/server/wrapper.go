package server

import (
	"bytes"
	"encoding/hex"

	"github.com/moov-io/tr31/pkg/tr31"
)

type UnifiedParams struct {
	VaultAddr  string
	VaultToken string
	KekId      string
	KeyBlock   string
}

type WrapperCall func(params UnifiedParams) (string, error)

func InitialKey(params UnifiedParams) (string, error) {
	planData := []byte(params.VaultAddr + params.VaultToken)
	kbpk := bytes.Repeat([]byte("E"), 24)
	encData, err := tr31.GenerateCBCMAC(kbpk, planData, 1, 8, tr31.DES)
	if err != nil {
		return "", err
	}
	identify := hex.EncodeToString(encData)
	return identify, err
}
func TransactionKey(params UnifiedParams) (string, error) {
	planData := []byte(params.VaultAddr + params.VaultToken)
	kbpk := bytes.Repeat([]byte("F"), 24)
	encData, err := tr31.GenerateCBCMAC(kbpk, planData, 1, 8, tr31.DES)
	if err != nil {
		return "", err
	}
	identify := hex.EncodeToString(encData)
	return identify, nil
}
func DecryptData(params UnifiedParams) (string, error) {
	return "aaaaaaaaa", nil
}
