package server

import (
	"testing"
	"time"
)

func TestFetchVaultLocal(t *testing.T) {
	startVault() // Start Vault

	// Example usage
	saveKey("myapp/config", "password", "supersecret123")
	readKey("myapp/config", "password")
	removeKey("myapp/config", "password")

	// Stop Vault after 2 seconds
	time.Sleep(2 * time.Second)
	closeVault()
}
