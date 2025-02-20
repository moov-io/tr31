package server

import (
	"fmt"
	"sync"
)

// MockVaultClient is a mock implementation of VaultClientInterface for testing.
type MockVaultClient struct {
	storage map[string]map[string]string
	mu      sync.Mutex
}

// NewMockVaultClient creates a new instance of MockVaultClient.
func NewMockVaultClient() *MockVaultClient {
	return &MockVaultClient{
		storage: make(map[string]map[string]string),
	}
}

// startVault simulates starting Vault.
func (m *MockVaultClient) startVault() *VaultError {
	fmt.Println("Mock Vault started")
	return nil
}

// saveKey simulates saving a key-value pair in Vault.
func (m *MockVaultClient) saveKey(path, key, value string) *VaultError {
	m.mu.Lock()
	defer m.mu.Unlock()

	if path == "" || key == "" || value == "" {
		return &VaultError{Message: "Invalid input: path, key, and value are required"}
	}

	if _, exists := m.storage[path]; !exists {
		m.storage[path] = make(map[string]string)
	}
	m.storage[path][key] = value

	fmt.Printf("Mock saved key %s in path %s\n", key, path)
	return nil
}

// readKey simulates reading a key-value pair from Vault.
func (m *MockVaultClient) readKey(path, key string) (string, *VaultError) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if path == "" || key == "" {
		return "", &VaultError{Message: "Invalid input: path and key are required"}
	}

	if values, exists := m.storage[path]; exists {
		if value, exists := values[key]; exists {
			fmt.Printf("Mock read key %s from path %s\n", key, path)
			return value, nil
		}
	}
	return "", &VaultError{Message: fmt.Sprintf("Key %s not found in path %s", key, path)}
}

// removeKey simulates removing a key-value pair from Vault.
func (m *MockVaultClient) removeKey(path, key string) *VaultError {
	m.mu.Lock()
	defer m.mu.Unlock()

	if path == "" || key == "" {
		return &VaultError{Message: "Invalid input: path and key are required"}
	}

	if values, exists := m.storage[path]; exists {
		if _, exists := values[key]; exists {
			delete(values, key)
			fmt.Printf("Mock removed key %s from path %s\n", key, path)
			return nil
		}
	}
	return &VaultError{Message: fmt.Sprintf("Key %s not found in path %s", key, path)}
}

// closeVault simulates closing Vault.
func (m *MockVaultClient) closeVault() {
	fmt.Println("Mock Vault closed")
}
