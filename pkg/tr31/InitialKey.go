package tr31

import (
	"bytes"
	"encoding/hex"
	"github.com/moov-io/psec/encryption"
)

func GenerateIntialKey(data string) string {
	planData, _ := hex.DecodeString(data)
	kbpk := bytes.Repeat([]byte("E"), 24)
	encData, _ := encryption.GenerateCBCMAC(kbpk, planData, 1, 8, encryption.DES)
	return hex.EncodeToString(encData)
}
