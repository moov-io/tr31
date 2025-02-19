package server

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"os"
	"os/exec"
	"time"
)

type VaultError struct {
	Message string
}

const (
	VaultErrorRunning         string = "Vault failed to start with error: %v"
	VaultErrorCreatClient     string = "Error creating Vault client: %v"
	VaultErrorClient          string = "Error Vault client."
	VaultErrorNoServerAddress string = "Server address is not supported."
	VaultErrorNoServerToken   string = "Vault token is not supported."
	VaultErrorNoKeyPath       string = "Key path is not supported."
	VaultErrorNoKeyName       string = "Key name is not supported."
	VaultErrorNoKeyData       string = "Key data is not supported."
	VaultErrorWriting         string = "Error writing to Vault with error: %v:"
	VaultErrorReadResult      string = "Error reading from Vault or no data found:%v"
	VaultErrorResultNotString string = "Value is not a string: %v"
	VaultErrorResultNotExist  string = "Key not found:%v"
	VaultErrorUpdate          string = "Error updating Vault: %v"
)

type VaultClientInterface interface {
	startVault() *VaultError
	saveKey(path, key, value string) *VaultError
	readKey(path, key string) (string, *VaultError)
	removeKey(path, key string) *VaultError
	closeVault()
}

type VaultClient struct {
	client *api.Client
}

// Vault Process Reference
var vaultCmd *exec.Cmd

func createVaultClient(vaultAddr, vaultToken string, timeout time.Duration) (*api.Client, *VaultError) {
	config := api.DefaultConfig()
	config.Address = vaultAddr
	config.HttpClient.Timeout = timeout
	client, err := api.NewClient(config)
	if err != nil {
		return nil, &VaultError{
			Message: fmt.Sprintf(VaultErrorCreatClient, err),
		}
	}
	client.SetToken(vaultToken)
	return client, nil
}

// 1️⃣ Start Vault (First close existing Vault if running)
func (v *VaultClient) startVault() *VaultError {
	// Kill existing Vault process
	v.closeVault()
	// Start Vault in dev mode
	vaultCmd = exec.Command("vault", "server", "-dev", "-dev-root-token-id="+v.client.Token())
	vaultCmd.Stdout = os.Stdout
	vaultCmd.Stderr = os.Stderr

	if err := vaultCmd.Start(); err != nil {
		return &VaultError{
			Message: fmt.Sprintf(VaultErrorRunning, err),
		}
	}
	return nil
}

// 2️⃣ Save a key-value pair in Vault
func (v *VaultClient) saveKey(path, key, value string) *VaultError {
	if err := func() *VaultError {
		switch {
		case v.client == nil:
			return &VaultError{Message: fmt.Sprintf(VaultErrorClient)}
		case len(path) == 0:
			return &VaultError{Message: fmt.Sprintf(VaultErrorNoKeyPath)}
		case len(key) == 0:
			return &VaultError{Message: fmt.Sprintf(VaultErrorNoKeyName)}
		case len(value) == 0:
			return &VaultError{Message: fmt.Sprintf(VaultErrorNoKeyData)}
		default:
			return nil
		}
	}(); err != nil {
		return err
	}

	client := v.client
	// Store key-value
	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			key: value,
		},
	}

	_, vErr := client.Logical().Write("secret/data/"+path, secretData)
	if vErr != nil {
		return &VaultError{Message: fmt.Sprintf(VaultErrorWriting, vErr)}
	}
	return nil
}

// 3️⃣ Read a key from Vault
func (v *VaultClient) readKey(path, key string) (string, *VaultError) {
	if err := func() *VaultError {
		switch {
		case v.client == nil:
			return &VaultError{Message: fmt.Sprintf(VaultErrorClient)}
		case len(path) == 0:
			return &VaultError{Message: fmt.Sprintf(VaultErrorNoKeyPath)}
		case len(key) == 0:
			return &VaultError{Message: fmt.Sprintf(VaultErrorNoKeyName)}
		default:
			return nil
		}
	}(); err != nil {
		return "", err
	}

	client := v.client

	secret, vErr := client.Logical().Read("secret/data/" + path)
	if vErr != nil || secret == nil {
		return "", &VaultError{Message: fmt.Sprintf(VaultErrorReadResult, vErr)}
	}

	// Extract the value
	data := secret.Data["data"].(map[string]interface{})
	if valueKey, ok := data[key]; ok {
		if strValue, ok := valueKey.(string); ok {
			return strValue, nil
		} else {
			return "", &VaultError{Message: fmt.Sprintf(VaultErrorResultNotString, valueKey)}
		}
	} else {
		return "", &VaultError{Message: fmt.Sprintf(VaultErrorResultNotExist, key)}
	}
}

// 4️⃣ Remove a key from Vault
func (v *VaultClient) removeKey(path, key string) *VaultError {
	if err := func() *VaultError {
		switch {
		case v.client == nil:
			return &VaultError{Message: fmt.Sprintf(VaultErrorClient)}
		case len(path) == 0:
			return &VaultError{Message: fmt.Sprintf(VaultErrorNoKeyPath)}
		case len(key) == 0:
			return &VaultError{Message: fmt.Sprintf(VaultErrorNoKeyName)}
		default:
			return nil
		}
	}(); err != nil {
		return err
	}
	client := v.client

	// Read existing data
	secret, vErr := client.Logical().Read("secret/data/" + path)
	if vErr != nil || secret == nil {
		return &VaultError{Message: fmt.Sprintf(VaultErrorReadResult, vErr)}
	}

	// Remove key from data
	data := secret.Data["data"].(map[string]interface{})
	if _, exists := data[key]; exists {
		delete(data, key)
	} else {
		return &VaultError{Message: fmt.Sprintf(VaultErrorResultNotExist, key)}
	}

	// Write updated data back to Vault
	updatedSecret := map[string]interface{}{
		"data": data,
	}

	_, vErr = client.Logical().Write("secret/data/"+path, updatedSecret)
	if vErr != nil {
		return &VaultError{Message: fmt.Sprintf(VaultErrorUpdate, key)}
	}
	return nil
}

// 5️⃣ Stop Vault Process
func (*VaultClient) closeVault() {
	// Kill Vault process (Linux/Mac)
	exec.Command("pkill", "vault").Run()

	// If Vault was started in this process, terminate it
	if vaultCmd != nil && vaultCmd.Process != nil {
		if err := vaultCmd.Process.Kill(); err != nil {
		}
	}
}
