package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func mockServiceInMemory() Service {
	repository := NewRepositoryInMemory(nil)
	return NewService(repository)
}

func mockVaultAuthOne() Vault {
	return Vault{
		VaultAddress: "http://localhost:8200",
		VaultToken:   "hvs.EqkXJUliZk0KUNII5lsydvGB",
	}
}

func mockVaultAuthTwo() Vault {
	return Vault{
		VaultAddress: "https://https://portal.cloud.hashicorp.com:8200",
		VaultToken:   "hvs.EqkXJUliZk0KUNII5lsydvGBC",
	}
}

func TestService__CreateMachine(t *testing.T) {
	s := mockServiceInMemory()
	mDes := NewMachine(mockVaultAuthOne())
	err := s.CreateMachine(mDes)
	require.NoError(t, err)

	err = s.CreateMachine(mDes)
	require.Equal(t, "already exists", err.Error())
}

func TestService__GetMachine(t *testing.T) {
	s := mockServiceInMemory()

	m := NewMachine(mockVaultAuthOne())
	err := s.CreateMachine(m)
	if err != nil {
		return
	}

	machines := s.GetMachines()
	require.Equal(t, 1, len(machines))

	machine, err := s.GetMachine(machines[0].InitialKey)
	require.NoError(t, err)
	require.Equal(t, "8a5af5de83579a84", machine.TransactionKey)
}

func TestService__DeleteMachine(t *testing.T) {
	s := mockServiceInMemory()
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

func TestService_DecryptData(t *testing.T) {
	s := mockServiceInMemory()

	m := NewMachine(mockVaultAuthOne())
	err := s.CreateMachine(m)
	if err != nil {
		return
	}

	data, err := s.DecryptData(m.InitialKey, "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA")
	require.NoError(t, err)
	require.Equal(t, data, "aaaaaaaaa")
}
