package server

import (
	"github.com/hashicorp/vault/api"
	"time"
)

// MockVaultClient is a mock implementation of VaultClientInterface
type MockVaultClient struct {
	Storage map[string]map[string]string // Simulating Vault storage
}

// NewMockVaultClient creates a new mock Vault client
func NewMockVaultClient() *MockVaultClient {
	return &MockVaultClient{Storage: make(map[string]map[string]string)}
}

func createMockVaultClient(vaultAddr, vaultToken string, timeout time.Duration) (*api.Client, *VaultError) {
	return &api.Client{}, nil // Returning an empty client for test purposes
}

func (m *MockVaultClient) startVault(vaultToken string) *VaultError {
	return nil // No-op for mock
}

func (m *MockVaultClient) saveKey(vaultAddr, vaultToken, path, key, value string, timeout time.Duration) *VaultError {
	if _, exists := m.Storage[path]; !exists {
		m.Storage[path] = make(map[string]string)
	}
	m.Storage[path][key] = value
	return nil
}

func (m *MockVaultClient) readKey(vaultAddr, vaultToken, path, key string, timeout time.Duration) (string, *VaultError) {
	if val, exists := m.Storage[path][key]; exists {
		return val, nil
	}
	return "", &VaultError{Message: "Key not found"}
}

func (m *MockVaultClient) removeKey(vaultAddr, vaultToken, path, key string, timeout time.Duration) *VaultError {
	if _, exists := m.Storage[path]; exists {
		delete(m.Storage[path], key)
	}
	return nil
}

func (m *MockVaultClient) closeVault() {
	m.Storage = make(map[string]map[string]string)
}
