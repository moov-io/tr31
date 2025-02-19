package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"os"
	"os/exec"
	"runtime"
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
	VaultErrorPermisson       string = "Error give permission to Vault with error: %v:"
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
	config.HttpClient.Timeout = timeout * time.Second
	client, err := api.NewClient(config)
	if err != nil {
		return nil, &VaultError{
			Message: fmt.Sprintf(VaultErrorCreatClient, err),
		}
	}
	client.SetToken(vaultToken)
	return client, nil
}
func enableKVSecretsEngine(client *api.Client, path string) error {
	// Prepare the request body for enabling kv-v2 secrets engine
	mountRequest := map[string]interface{}{
		"type":        "kv",
		"options":     map[string]interface{}{"version": "2"}, // specify kv-v2 version
		"description": "KV secrets engine version 2",
	}

	// Marshal the request body into JSON
	mountRequestBody, err := json.Marshal(mountRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal mount request: %v", err)
	}

	// Use the Vault client to send an HTTP request to the sys/mounts endpoint
	req := client.NewRequest("POST", fmt.Sprintf("/v1/sys/mounts/%s", path))

	// Set the request body
	req.Body = bytes.NewBuffer(mountRequestBody)

	// Send the request to enable the KV engine at the given path
	resp, err := client.RawRequest(req)
	if err != nil {
		return fmt.Errorf("failed to enable KV engine at path %s: %v", path, err)
	}

	if resp.StatusCode != 204 {
		return fmt.Errorf("failed to enable KV engine, unexpected status code: %v", resp.StatusCode)
	}

	fmt.Printf("Successfully enabled KV version 2 at path: %s\n", path)
	return nil
}

// 1️⃣ Start Vault (First close existing Vault if running)
func (v *VaultClient) startVault() *VaultError {
	// Kill existing Vault process
	v.closeVault()
	// Start Vault in dev mode
	vaultCmd = exec.Command("vault", "server", "-dev", "-dev-root-token-id="+v.client.Token())
	vaultCmd.Stdout = os.Stdout
	vaultCmd.Stderr = os.Stderr

	// Set environment variable based on OS
	if runtime.GOOS == "windows" {
		// For Windows (cmd.exe and PowerShell)
		err := os.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
		if err != nil {
			return &VaultError{
				Message: fmt.Sprintf("failed to set VAULT_ADDR: %v", err),
			}
		}
	} else {
		// For Linux/macOS
		os.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	}

	if err := vaultCmd.Start(); err != nil {
		return &VaultError{
			Message: fmt.Sprintf(VaultErrorRunning, err),
		}
	}
	time.Sleep(1 * time.Second)

	_ = enableKVSecretsEngine(v.client, "secret")
	//if sErr != nil {
	//	return &VaultError{Message: fmt.Sprintf("%v", sErr)}
	//}
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
	fmt.Println("Saving secret at path:", path, "with key:", key, "and value:", value)
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
func (v *VaultClient) closeVault() {
	if runtime.GOOS == "windows" {
		// Run PowerShell command to force kill Vault
		cmd := exec.Command("powershell", "-Command", "Get-Process vault | Stop-Process -Force")
		err := cmd.Run()
		if err != nil {
			fmt.Println("Error killing Vault process:", err)
		} else {
			fmt.Println("Vault process terminated successfully (Windows)")
		}
	} else {
		// Linux/macOS: Use pkill
		cmd := exec.Command("pkill", "vault")
		cmd.Run()
	}
}
