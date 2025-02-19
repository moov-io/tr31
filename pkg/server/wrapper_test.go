package server

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFetchKBPKLocal(t *testing.T) {
	vaultClient, err := createVaultClient("http://127.0.0.1:8200", "my-fixed-token", 1)
	require.Nil(t, err)
	vault := VaultClient{vaultClient}
	vErr := vault.startVault()
	require.Nil(t, vErr)

	vErr = vault.saveKey("myapp/config", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	require.Nil(t, vErr)

	kbkp, vErr := vault.readKey("myapp/config", "kbkp")
	require.Nil(t, vErr)
	require.Equal(t, "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", kbkp)

	vault.removeKey("myapp/config", "kbkp")

	vault.closeVault()
}

func TestDecriptDataWithLocalVault(t *testing.T) {
	vaultClient, err := createVaultClient("http://127.0.0.1:8200", "my-fixed-token", 1000)
	require.Nil(t, err)
	vault := VaultClient{vaultClient}
	vault.startVault()

	vault.saveKey("myapp/config", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")

	param := UnifiedParams{
		VaultAddr:  "http://127.0.0.1:8200",
		VaultToken: "my-fixed-token",
		KeyPath:    "myapp/config",
		KeyName:    "kbkp",
		KeyBlock:   "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E",
	}

	keyStr, _ := DecryptData(param)

	vault.removeKey("myapp/config", "kbkp")
	vault.closeVault()

	require.Equal(t, "ccccccccccccccccdddddddddddddddd", keyStr)
}
