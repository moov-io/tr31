package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecryptData(t *testing.T) {
	mockVault := NewMockVaultClient()
	err := mockVault.WriteSecret("secret/data/myapp", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	require.Nil(t, err)

	kbkp, vErr := mockVault.ReadSecret("secret/data/myapp", "kbkp")
	require.Nil(t, vErr)
	require.Equal(t, "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", kbkp)

	param := UnifiedParams{
		Kbkp:     kbkp,
		KeyBlock: "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E", // gitleaks:allow
	}

	keyStr, _ := DecryptData(param)

	mockVault.DeleteSecret("secret/data/myapp", "kbkp")

	require.Equal(t, "ccccccccccccccccdddddddddddddddd", keyStr)
}
