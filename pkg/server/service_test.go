package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func mockServiceInMemory() Service {
	repository := NewRepositoryInMemory(nil)
	return NewMockService(repository)
}
func mockServiceInLocal() Service {
	repository := NewRepositoryInMemory(nil)
	return NewService(repository)
}
func mockVaultAuthOne() Vault {
	return Vault{
		VaultAddress: "http://localhost:8200",
		VaultToken:   "my-fixed-token",
	}
}
func mockVaultAuthTwo() Vault {
	return Vault{
		VaultAddress: "https://vault-cluster-public-vault-2d92a425.16ce2ded.z1.hashicorp.cloud:8200",
		VaultToken:   "hvs.CAESIBsqFKMFzHabqYh0uf4O5Ui4zcDrqmLjc1I48p0gkCX7GicKImh2cy5IaFdsN2tGMTI4Zzg3aFBJUTBZWWZRN00udVFFUzQQ1hk",
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

func TestService_Encrypt_Decrypt_Data_With_Mock(t *testing.T) {
	s := mockServiceInMemory()
	m := NewMachine(mockVaultAuthOne())
	err := s.CreateMachine(m)
	if err != nil {
		return
	}

	s.GetVaultClient().saveKey(
		"secret/tr31",
		"kbkp",
		"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC",
	)

	header := HeaderParams{
		VersionId:     "D",
		KeyUsage:      "D0",
		Algorithm:     "A",
		ModeOfUse:     "D",
		KeyVersion:    "00",
		Exportability: "E",
	}
	data, err := s.EncryptData(m.InitialKey, "secret/tr31", "kbkp", "ccccccccccccccccdddddddddddddddd", header, 10)
	require.NoError(t, err)

	data, err = s.DecryptData(m.InitialKey, "secret/tr31", "kbkp", data, 10)
	require.NoError(t, err)

	require.Equal(t, data, "ccccccccccccccccdddddddddddddddd")

	s.GetVaultClient().removeKey("/auth/keys", "kbkp")
}

/****************************************************************************/
/******************** Test hashicorp.cloud for develop  *********************/
/****************************************************************************/
func TestService_Encrypt_Decrypt_Data_WithHashicorp(t *testing.T) {
	s := mockServiceInLocal()
	m := NewMachine(mockVaultAuthTwo())
	err := s.CreateMachine(m)
	if err != nil {
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
	data, err := s.EncryptData(
		m.InitialKey,
		"/admin/kv/data/moov-io/tr31",
		"kbkp",
		"ccccccccccccccccdddddddddddddddd",
		header, 10)
	require.NoError(t, err)

	data, err = s.DecryptData(
		m.InitialKey,
		"/admin/kv/data/moov-io/tr31",
		"kbkp",
		data, 10)
	require.NoError(t, err)

	require.Equal(t, data, "ccccccccccccccccdddddddddddddddd")
}

/****************************************************************************/
/********************  Test local vault for develop  ************************/
/****************************************************************************/
func TestService_Encrypt_Decrypt_Data_With_Local(t *testing.T) {
	s := mockServiceInLocal()
	m := NewMachine(mockVaultAuthOne())
	err := s.CreateMachine(m)
	if err != nil {
		return
	}

	vErr := s.GetVaultClient().startVault()
	require.Nil(t, vErr)

	s.GetVaultClient().saveKey(
		"secret/data/myapp",
		"kbkp",
		"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC",
	)

	header := HeaderParams{
		VersionId:     "D",
		KeyUsage:      "D0",
		Algorithm:     "A",
		ModeOfUse:     "D",
		KeyVersion:    "00",
		Exportability: "E",
	}
	data, err := s.EncryptData(m.InitialKey, "secret/data/myapp", "kbkp", "ccccccccccccccccdddddddddddddddd", header, 10)
	require.NoError(t, err)

	data, err = s.DecryptData(m.InitialKey, "secret/data/myapp", "kbkp", data, 10)
	require.NoError(t, err)

	require.Equal(t, data, "ccccccccccccccccdddddddddddddddd")

	s.GetVaultClient().removeKey("secret/data/myapp", "kbkp")

	s.GetVaultClient().closeVault()
}
