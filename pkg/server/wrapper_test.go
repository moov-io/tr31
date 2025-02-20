package server

import (
	"github.com/stretchr/testify/require"
	"testing"
)

/****************************************************************************/
/********************  Test local vault for develop  ************************/
/****************************************************************************/
func TestFetchKBPKLocal(t *testing.T) {
	vaultClient, err := createVaultClient("http://127.0.0.1:8200", "my-fixed-token", 1)
	require.Nil(t, err)
	onlineVaultClient := NewOnlineVaultClient(vaultClient)
	vault := VaultClient{onlineVaultClient}
	vErr := vault.startVault()
	require.Nil(t, vErr)

	vErr = vault.saveKey("secret/data/myapp", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	require.Nil(t, vErr)

	kbkp, vErr := vault.readKey("secret/data/myapp", "kbkp")
	require.Nil(t, vErr)
	require.Equal(t, "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", kbkp)

	vault.removeKey("secret/data/myapp", "kbkp")

	vault.closeVault()
}

func TestDecryptDataWithLocalVault(t *testing.T) {
	vaultClient, err := createVaultClient("http://127.0.0.1:8200", "my-fixed-token", 1)
	require.Nil(t, err)
	onlineVaultClient := NewOnlineVaultClient(vaultClient)
	vault := VaultClient{onlineVaultClient}
	vault.startVault()

	vault.saveKey("secret/data/myapp", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")

	kbkp, vErr := vault.readKey("secret/data/myapp", "kbkp")
	require.Nil(t, vErr)
	require.Equal(t, "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", kbkp)

	param := UnifiedParams{
		Kbkp:     kbkp,
		KeyBlock: "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E",
	}

	keyStr, _ := DecryptData(param)

	vault.removeKey("secret/data/myapp", "kbkp")
	vault.closeVault()

	require.Equal(t, "ccccccccccccccccdddddddddddddddd", keyStr)
}

/****************************************************************************/
/********************  Test with vault mock	  ************************/
/****************************************************************************/
func TestDecryptData(t *testing.T) {
	mockVault := NewMockVaultClient()
	mockVault.startVault()
	err := mockVault.saveKey("secret/data/myapp", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	require.Nil(t, err)

	kbkp, vErr := mockVault.readKey("secret/data/myapp", "kbkp")
	require.Nil(t, vErr)
	require.Equal(t, "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", kbkp)

	param := UnifiedParams{
		Kbkp:     kbkp,
		KeyBlock: "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E",
	}

	keyStr, _ := DecryptData(param)

	mockVault.removeKey("secret/data/myapp", "kbkp")
	mockVault.closeVault()

	require.Equal(t, "ccccccccccccccccdddddddddddddddd", keyStr)
}
