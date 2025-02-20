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

func (e *VaultError) Error() string {
	return e.Message
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
	VaultErrorPermission      string = "Error give permission to Vault with error: %v:"
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
	client VaultClientInterface
}

// Proxy methods to delegate to the real or mock client
func (v *VaultClient) startVault() *VaultError {
	return v.client.startVault()
}
func (v *VaultClient) saveKey(path, key, value string) *VaultError {
	return v.client.saveKey(path, key, value)
}

func (v *VaultClient) readKey(path, key string) (string, *VaultError) {
	return v.client.readKey(path, key)
}

func (v *VaultClient) removeKey(path, key string) *VaultError {
	return v.client.removeKey(path, key)
}

func (v *VaultClient) closeVault() {
	v.client.closeVault()
}

type OnlineVaultClient struct {
	client *api.Client
}

// Constructor
func NewOnlineVaultClient(client *api.Client) *OnlineVaultClient {
	return &OnlineVaultClient{client: client}
}

// Vault Process Reference
var vaultCmd *exec.Cmd

// createVaultClient initializes and returns a new Vault API client.
//
// Parameters:
// - vaultAddr: The address of the Vault server (e.g., "http://127.0.0.1:8200").
// - vaultToken: The authentication token used to access Vault.
// - timeout: The duration (in seconds) before the HTTP request times out.
//
// Returns:
// - *api.Client: A pointer to the initialized Vault client if successful.
// - *VaultError: An error object if the client creation fails.
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

// enableKVSecretsEngine enables the KV (Key-Value) secrets engine (version 2) at the specified path in Vault.
//
// Parameters:
// - client: A pointer to the Vault API client.
// - path: The mount path where the KV secrets engine should be enabled.
//
// Returns:
// - error: An error if the operation fails; otherwise, nil.
//
// This function sends a request to the Vault server to mount the KV v2 secrets engine
// at the specified path. It constructs the request body, makes an HTTP request, and
// validates the response status.
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

// startVault starts a local Vault server in development mode.
//
// This function is only called when using a locally installed Vault. It performs the following steps:
// 1. Kills any existing Vault process.
// 2. Starts a new Vault server in development mode with a predefined root token.
// 3. Sets the VAULT_ADDR environment variable based on the operating system.
// 4. Enables the KV secrets engine at the "secret" path.
//
// Returns:
// - *VaultError: An error object if the Vault process fails to start or if setting the environment variable fails.
func (v *OnlineVaultClient) startVault() *VaultError {
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

// saveKey stores a key-value pair in the Vault secrets engine in development mode.
//
// This function is intended for use with a local Vault instance. It validates input parameters
// and writes the specified key-value pair to the given path in Vault.
//
// Parameters:
// - path: The Vault path where the secret should be stored (e.g., "secret/myapp").
// - key: The name of the key to store in the secret (e.g., "API_KEY").
// - value: The value associated with the key.
//
// Returns:
// - *VaultError: An error object if the operation fails; otherwise, nil.
func (v *OnlineVaultClient) saveKey(path, key, value string) *VaultError {
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
	_, vErr := client.Logical().Write(path, secretData)
	if vErr != nil {
		return &VaultError{Message: fmt.Sprintf(VaultErrorWriting, vErr)}
	}
	return nil
}

// readKey retrieves a specific key's value from the Vault secrets engine.
//
// This function reads a stored secret from Vault at the specified path and extracts
// the requested key's value.
//
// Parameters:
// - path: The Vault path where the secret is stored (e.g., "secret/myapp").
// - key: The specific key within the secret to retrieve.
//
// Returns:
// - string: The value associated with the key, if found.
// - *VaultError: An error object if the operation fails or the key does not exist.
func (v *OnlineVaultClient) readKey(path, key string) (string, *VaultError) {
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

	secret, vErr := client.Logical().Read(path)
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

// removeKey removes a specific key from a stored secret in the Vault secrets engine.
//
// This function reads the existing secret data from Vault, removes the specified key,
// and updates the stored secret. It is designed for use with a local Vault running
// in development mode.
//
// Parameters:
// - path: The Vault path where the secret is stored (e.g., "secret/myapp").
// - key: The specific key within the secret that should be removed.
//
// Returns:
// - *VaultError: An error object if the operation fails; otherwise, nil.
func (v *OnlineVaultClient) removeKey(path, key string) *VaultError {
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
	secret, vErr := client.Logical().Read(path)
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

// closeVault stops the running Vault process on the local machine in development mode.
//
// This function detects the operating system and executes the appropriate command
// to terminate the Vault process. It is intended for use in development mode when
// Vault is running locally.
//
// - On Windows, it uses PowerShell to forcefully stop the Vault process.
// - On Linux/macOS, it uses the `pkill` command to terminate Vault.
//
// This function does not return an error but logs the status of the termination.
func (v *OnlineVaultClient) closeVault() {
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
