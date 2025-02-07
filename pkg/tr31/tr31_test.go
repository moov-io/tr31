package tr31

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_wrap_unwrap_functions(t *testing.T) {
	kbpk := []byte{0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB}
	key := []byte{0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD}
	kb, _ := Wrap(kbpk, "B0096P0TE00N0000", key, nil)
	hOut, keyOut, _ := Unwrap(kbpk, kb)

	assert.Equal(t, key, keyOut)
	assert.Equal(t, "B", hOut.VersionID)
	assert.Equal(t, "P0", hOut.KeyUsage)
	assert.Equal(t, "T", hOut.Algorithm)
	assert.Equal(t, "E", hOut.ModeOfUse)
	assert.Equal(t, "00", hOut.VersionNum)
	assert.Equal(t, "N", hOut.Exportability)
	assert.Equal(t, "00", hOut.Reserved)
	assert.Equal(t, 0, len(hOut.GetBlocks()))
}
func Test_wrap_unwrap_header_functions(t *testing.T) {
	kbpk := []byte{0xEF, 0xEF, 0xEF, 0xEF, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF}
	key := []byte{0x55, 0x55, 0x55, 0x55, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0x55, 0x55, 0x55, 0x55, 0x55}
	kb, _ := Wrap(kbpk, "", key, nil)
	_, keyOut, _ := Unwrap(kbpk, kb)

	assert.Equal(t, key, keyOut)
}
func Test_Unwrap_Apple_Proximity(t *testing.T) {
	// Key Block Protection Key
	kbpk, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	// Key Block
	kb := "D0112D0AD00E00009ef4ff063d9757987d1768a1e317a6530de7d8ac81972c19a3659afb28e8d35f48aaa5b0f124e73893163e9a020ae5f3"
	// Expected Key
	key, _ := hex.DecodeString("B9517FF24FD4C71833478D424C29751D")

	_, keyOut, err := Unwrap(kbpk, kb)
	assert.Nil(t, err)
	assert.Equal(t, key, keyOut)
}
