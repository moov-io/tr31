package server

import (
	"bytes"
	"encoding/hex"
	"errors"
	"time"

	"github.com/moov-io/tr31/pkg/tr31"
)

type HeaderParams struct {
	VersionId     string
	KeyUsage      string
	Algorithm     string
	ModeOfUse     string
	KeyVersion    string
	Exportability string
}
type UnifiedParams struct {
	VaultAddr  string
	VaultToken string
	KeyPath    string
	KeyName    string
	Kbkp       string
	KeyBlock   string
	EncKey     string
	Header     HeaderParams
	timeout    time.Duration
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

func readKey(vault SecretManager, params UnifiedParams) (string, error) {
	kbpkStr, err := vault.ReadSecret(params.KeyPath, params.KeyName)
	if err != nil {
		return "", errors.New(err.Message)
	}
	return kbpkStr, nil
}

func EncryptData(params UnifiedParams) (string, error) {
	kbpkStr := params.Kbkp
	kbpk, decErr := hex.DecodeString(kbpkStr)
	if decErr != nil {
		return "", decErr
	}
	enckey, decErr := hex.DecodeString(params.EncKey)
	if decErr != nil {
		return "", decErr
	}
	header, hErr := tr31.NewHeader(
		params.Header.VersionId,
		params.Header.KeyUsage,
		params.Header.Algorithm,
		params.Header.ModeOfUse,
		params.Header.KeyVersion,
		params.Header.Exportability)
	if hErr != nil {
		return "", decErr
	}
	kblock, bErr := tr31.NewKeyBlock(kbpk, header)
	if bErr != nil {
		return "", bErr
	}
	kb, wErr := kblock.Wrap(enckey, nil)
	if wErr != nil {
		return "", wErr
	}
	return kb, nil
}

func DecryptData(params UnifiedParams) (string, error) {
	kbpkStr := params.Kbkp
	kbpk, decErr := hex.DecodeString(kbpkStr)
	if decErr != nil {
		return "", decErr
	}
	block, bErr := tr31.NewKeyBlock(kbpk, nil)
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
