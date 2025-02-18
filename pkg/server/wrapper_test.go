package server

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFetchKBPKLocal(t *testing.T) {
	startLocalVault("my-fixed-token")
	saveKey("http://127.0.0.1:8200", "my-fixed-token", "myapp/config", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	kbkp, _ := readKey("http://127.0.0.1:8200", "my-fixed-token", "myapp/config", "kbkp")
	require.Equal(t, "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", kbkp)
	removeKey("http://127.0.0.1:8200", "my-fixed-token", "myapp/config", "kbkp")
	closeVault()
}

func TestDecriptDataWithLocalVault(t *testing.T) {
	param := UnifiedParams{
		VaultAddr:  "http://127.0.0.1:8200",
		VaultToken: "my-fixed-token",
		KeyPath:    "myapp/config",
		KeyName:    "kbkp",
		KeyBlock:   "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E",
	}
	startLocalVault(param.VaultToken)
	saveKey(param.VaultAddr, param.VaultToken, "myapp/config", "kbkp", "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")

	keyStr, _ := DecryptData(param)
	removeKey(param.VaultAddr, param.VaultToken, "myapp/config", "kbkp")
	closeVault()
	require.Equal(t, "ccccccccccccccccdddddddddddddddd", keyStr)
}
