package server

import (
	"fmt"

	"github.com/hashicorp/vault/api"
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

type SecretManager interface {
	// SetAddress set a vault server url
	SetAddress(address string) *VaultError
	// SetToken set a vault token
	SetToken(token string) *VaultError
	// WriteSecret writes a secret to the specified path
	WriteSecret(path, key, value string) *VaultError
	// ReadSecret retrieves a secret from the specified path
	ReadSecret(path, key string) (string, *VaultError)
	// ListSecrets lists all secrets under a specified path
	ListSecrets(path string) ([]string, *VaultError)
	// DeleteSecret removes a secret at the specified path
	DeleteSecret(path, key string) *VaultError
}

type VaultClient struct {
	client *api.Client
}

var _ SecretManager = (&VaultClient{})

func NewVaultClient(v Vault) (*VaultClient, error) {
	vClient, err := createVaultClient(v.VaultAddress, v.VaultToken)
	if err != nil {
		return nil, err
	}
	return &VaultClient{vClient}, nil
}

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
func createVaultClient(vaultAddr, vaultToken string) (*api.Client, *VaultError) {
	config := api.DefaultConfig()
	config.Address = vaultAddr
	client, err := api.NewClient(config)
	if err != nil {
		return nil, &VaultError{

			Message: fmt.Sprintf(VaultErrorCreatClient, err),
		}
	}
	client.SetToken(vaultToken)
	return client, nil
}
func (v *VaultClient) SetAddress(address string) *VaultError {
	if v.client == nil {
		return &VaultError{Message: VaultErrorClient}
	}
	client := v.client
	err := client.SetAddress(address)
	if err != nil {
		return nil
	}
	return nil
}
func (v *VaultClient) SetToken(token string) *VaultError {
	if v.client == nil {
		return &VaultError{Message: VaultErrorClient}
	}
	client := v.client
	client.SetToken(token)
	return nil
}

// WriteSecret stores a key-value pair in the Vault secrets engine in development mode.
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
func (v *VaultClient) WriteSecret(path, key, value string) *VaultError {
	if v.client == nil {
		return &VaultError{Message: VaultErrorClient}
	}
	if len(path) == 0 {
		return &VaultError{Message: VaultErrorNoKeyPath}
	}
	if len(key) == 0 {
		return &VaultError{Message: VaultErrorNoKeyName}
	}
	if len(value) == 0 {
		return &VaultError{Message: VaultErrorNoKeyData}
	}

	client := v.client
	// Store key-value
	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			key: value,
		},
	}
	_, vErr := client.Logical().Write(path, secretData)
	if vErr != nil {
		return &VaultError{Message: fmt.Sprintf(VaultErrorWriting, vErr)}
	}
	return nil
}

// ReadSecret retrieves a specific key's value from the Vault secrets engine.
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
func (v *VaultClient) ReadSecret(path, key string) (string, *VaultError) {
	if v.client == nil {
		return "", &VaultError{Message: VaultErrorClient}
	}
	if len(path) == 0 {
		return "", &VaultError{Message: VaultErrorNoKeyPath}
	}
	if len(key) == 0 {
		return "", &VaultError{Message: VaultErrorNoKeyName}
	}

	client := v.client

	secret, vErr := client.Logical().Read(path)
	if vErr != nil || secret == nil {
		return "", &VaultError{Message: fmt.Sprintf(VaultErrorReadResult, vErr)}
	}

	// Extract the value
	dataRaw, ok := secret.Data["data"]
	if !ok {
		return "", &VaultError{Message: "missing 'data' key in secret response"}
	}

	data, ok := dataRaw.(map[string]interface{})
	if !ok {
		return "", &VaultError{Message: "'data' key is not a valid map[string]interface{}"}
	}

	valueKey, ok := data[key]
	if !ok {
		return "", &VaultError{Message: fmt.Sprintf("key '%s' not found in data", key)}
	}
	if strValue, ok := valueKey.(string); ok {
		return strValue, nil
	} else {
		return "", &VaultError{Message: fmt.Sprintf(VaultErrorResultNotString, valueKey)}
	}
}

// ListSecrets retrieves a specific key's value from the Vault secrets engine.
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
func (v *VaultClient) ListSecrets(path string) ([]string, *VaultError) {
	if v.client == nil {
		return nil, &VaultError{Message: VaultErrorClient}
	}
	if len(path) == 0 {
		return nil, &VaultError{Message: VaultErrorNoKeyPath}
	}

	client := v.client

	secret, vErr := client.Logical().Read(path)
	if vErr != nil || secret == nil {
		return nil, &VaultError{Message: fmt.Sprintf(VaultErrorReadResult, vErr)}
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, &VaultError{Message: fmt.Sprintf(VaultErrorReadResult, vErr)}
	}
	stringValues := []string{}
	for _, value := range data {
		if str, ok := value.(string); ok {
			stringValues = append(stringValues, str)
		}
	}
	return stringValues, nil
}

// DeleteSecret removes a specific key from a stored secret in the Vault secrets engine.
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
func (v *VaultClient) DeleteSecret(path, key string) *VaultError {
	if v.client == nil {
		return &VaultError{Message: VaultErrorClient}
	}
	if len(path) == 0 {
		return &VaultError{Message: VaultErrorNoKeyPath}
	}
	if len(key) == 0 {
		return &VaultError{Message: VaultErrorNoKeyName}
	}
	client := v.client

	// Read existing data
	secret, vErr := client.Logical().Read(path)
	if vErr != nil || secret == nil {
		return &VaultError{Message: fmt.Sprintf(VaultErrorReadResult, vErr)}
	}

	// Remove key from data
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return &VaultError{
			Message: "Invalid type for key 'data'. Expected map[string]interface{}.",
		}
	}
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
