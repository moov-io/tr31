package tr31

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_wrap_unwrap_functions(t *testing.T) {
	kbpk := []byte{0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB}
	key := []byte{0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD}
	kb, _ := wrap(kbpk, "B0096P0TE00N0000", key, nil)
	hOut, keyOut, _ := unwrap(kbpk, kb)

	assert.Equal(t, key, keyOut)
	assert.Equal(t, "B", hOut.VersionID)
	assert.Equal(t, "P0", hOut.KeyUsage)
	assert.Equal(t, "T", hOut.Algorithm)
	assert.Equal(t, "E", hOut.ModeOfUse)
	assert.Equal(t, "00", hOut.VersionNum)
	assert.Equal(t, "N", hOut.Exportability)
	assert.Equal(t, "00", hOut.Reserved)
	assert.Equal(t, 1, len(hOut.GetBlocks()))
	assert.Equal(t, "00604B120F9292800000", hOut.GetBlocks()["KS"])

}
