package server

import (
	"github.com/stretchr/testify/require"
	"testing"
)

/****************************************************************************/
/********************  Test local vault for develop  ************************/
/****************************************************************************/
func TestFetchKBPKLocal(t *testing.T) {
	vaultClient, err := NewVaultClient(Vault{VaultAddress: "http://127.0.0.1:8200", VaultToken: "my-fixed-token"})
	require.Nil(t, err)

	vErr := vaultClient.StartClient()
	require.Nil(t, vErr)

	vErr = vaultClient.WriteSecret("secret/data/myapp", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	require.Nil(t, vErr)

	kbkp, vErr := vaultClient.ReadSecret("secret/data/myapp", "kbkp")
	require.Nil(t, vErr)
	require.Equal(t, "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", kbkp)

	vaultClient.DeleteSecret("secret/data/myapp", "kbkp")

	vaultClient.CloseClient()
}

func TestDecryptDataWithLocalVault(t *testing.T) {
	vaultClient, err := NewVaultClient(Vault{VaultAddress: "http://127.0.0.1:8200", VaultToken: "my-fixed-token"})
	require.Nil(t, err)

	vaultClient.StartClient()

	vaultClient.WriteSecret("secret/data/myapp", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")

	kbkp, vErr := vaultClient.ReadSecret("secret/data/myapp", "kbkp")
	require.Nil(t, vErr)
	require.Equal(t, "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", kbkp)

	param := UnifiedParams{
		Kbkp:     kbkp,
		KeyBlock: "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E",
	}

	keyStr, _ := DecryptData(param)

	vaultClient.DeleteSecret("secret/data/myapp", "kbkp")
	vaultClient.CloseClient()

	require.Equal(t, "ccccccccccccccccdddddddddddddddd", keyStr)
}

/****************************************************************************/
/********************  Test with vault mock	  ************************/
/****************************************************************************/
func TestDecryptData(t *testing.T) {
	mockVault := NewMockVaultClient()
	err := mockVault.WriteSecret("secret/data/myapp", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	require.Nil(t, err)

	kbkp, vErr := mockVault.ReadSecret("secret/data/myapp", "kbkp")
	require.Nil(t, vErr)
	require.Equal(t, "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", kbkp)

	param := UnifiedParams{
		Kbkp:     kbkp,
		KeyBlock: "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E",
	}

	keyStr, _ := DecryptData(param)

	mockVault.DeleteSecret("secret/data/myapp", "kbkp")

	require.Equal(t, "ccccccccccccccccdddddddddddddddd", keyStr)
}
