package server

import (
	"cmp"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func mockServiceInMock() Service {
	repository := NewRepositoryInMemory(nil)
	return NewService(repository, MODE_MOCK)
}

func mockVaultAuthOne() Vault {
	address := cmp.Or(os.Getenv("VAULT_ADDR"), "http://localhost:8200")
	token := cmp.Or(os.Getenv("VAULT_TOKEN"), "token")

	return Vault{
		VaultAddress: address,
		VaultToken:   token,
	}
}

func mockVaultAuthTwo() Vault {
	return Vault{
		VaultAddress: os.Getenv("HASHICORP_VAULT_ADDRESS"),
		VaultToken:   os.Getenv("HASHICORP_VAULT_TOKEN"),
	}
}

func TestService__CreateMachine(t *testing.T) {
	s := mockServiceInMock()
	mDes := NewMachine(mockVaultAuthOne())
	err := s.CreateMachine(mDes)
	require.NoError(t, err)

	err = s.CreateMachine(mDes)
	require.Equal(t, "already exists", err.Error())
}

func TestService__GetMachine(t *testing.T) {
	s := mockServiceInMock()

	m := NewMachine(mockVaultAuthOne())
	err := s.CreateMachine(m)
	if err != nil {
		return
	}

	machines := s.GetMachines()
	require.Equal(t, 1, len(machines))

	machine, err := s.GetMachine(machines[0].InitialKey)
	require.NoError(t, err)
	require.Equal(t, "44cbb6e6434ddb22", machine.TransactionKey)
}

func TestService__DeleteMachine(t *testing.T) {
	s := mockServiceInMock()
	m1 := NewMachine(mockVaultAuthOne())
	m2 := NewMachine(mockVaultAuthTwo())
	err := s.CreateMachine(m1)
	if err != nil {
		return
	}
	err = s.CreateMachine(m2)
	if err != nil {
		return
	}

	require.NotEqual(t, m1.TransactionKey, m2.TransactionKey)
	require.NotEqual(t, m1.InitialKey, m2.InitialKey)

	machines := s.GetMachines()
	require.Equal(t, 2, len(machines))

	err = s.DeleteMachine(m1.InitialKey)
	if err != nil {
		return
	}
	err = s.DeleteMachine(m2.InitialKey)
	if err != nil {
		return
	}

	machines = s.GetMachines()
	require.Equal(t, 0, len(machines))
}

func TestService_Encrypt_Decrypt_Data_With_Mock(t *testing.T) {
	s := mockServiceInMock()
	m := NewMachine(mockVaultAuthOne())
	err := s.CreateMachine(m)
	if err != nil {
		return
	}
	serr := s.GetSecretManager().WriteSecret(
		"secret/tr31",
		"kbkp",
		"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC",
	)
	if serr != nil {
		log.Printf("Failed to write secret: %v", serr)
		return
	}
	
	header := HeaderParams{
		VersionId:     "D",
		KeyUsage:      "D0",
		Algorithm:     "A",
		ModeOfUse:     "D",
		KeyVersion:    "00",
		Exportability: "E",
	}
	data, err := s.EncryptData(mockVaultAuthOne().VaultAddress, mockVaultAuthOne().VaultToken, "secret/tr31", "kbkp", "ccccccccccccccccdddddddddddddddd", header, 10)
	require.NoError(t, err)

	data, err = s.DecryptData(mockVaultAuthOne().VaultAddress, mockVaultAuthOne().VaultToken, "secret/tr31", "kbkp", data, 10)
	require.NoError(t, err)

	require.Equal(t, data, "ccccccccccccccccdddddddddddddddd")

	verr := s.GetSecretManager().DeleteSecret("/auth/keys", "kbkp")
	require.NoError(t, verr)
}
