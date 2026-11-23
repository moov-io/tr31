package main

import (
	"testing"

	"github.com/moov-io/tr31/pkg/server"
	"github.com/stretchr/testify/require"
)

func setFlag(t *testing.T, ptr *string, value string) {
	t.Helper()
	prev := *ptr
	*ptr = value
	t.Cleanup(func() { *ptr = prev })
}

func setBool(t *testing.T, ptr *bool, value bool) {
	t.Helper()
	prev := *ptr
	*ptr = value
	t.Cleanup(func() { *ptr = prev })
}

func setVaultFlags(t *testing.T) {
	t.Helper()
	setFlag(t, flagVaultAddress, "http://127.0.0.1:8200")
	setFlag(t, flagVaultToken, "myroot")
	setFlag(t, flagKeyPath, "secret/data/tr31")
	setFlag(t, flagKeyName, "kbpk")
}

func TestBuildParams_EncryptAndDecrypt(t *testing.T) {
	setBool(t, flagEncrypt, true)
	setBool(t, flagDecrypt, true)

	_, err := buildParams()
	require.ErrorContains(t, err, "use only one of -e or -d")
}

func TestBuildParams_EncryptMissingHeader(t *testing.T) {
	setBool(t, flagEncrypt, true)
	setVaultFlags(t)
	setFlag(t, flagWrapperKey, "3F419E1CB7079442AA37474C2EFBF8B8") // gitleaks:allow

	_, err := buildParams()
	require.ErrorContains(t, err, "-version_id, -key_usage, -algorithm, -mode_of_use")
}

func TestBuildParams_Encrypt(t *testing.T) {
	setBool(t, flagEncrypt, true)
	setVaultFlags(t)
	setFlag(t, flagWrapperKey, "3F419E1CB7079442AA37474C2EFBF8B8") // gitleaks:allow
	setFlag(t, flagVersionID, "B")
	setFlag(t, flagKeyUsage, "P0")
	setFlag(t, flagAlgorithm, "T")
	setFlag(t, flagModeOfUse, "E")

	params, err := buildParams()
	require.NoError(t, err)
	require.Equal(t, "00", params.Header.KeyVersion)
	require.Equal(t, "N", params.Header.Exportability)

	// Wrap with the header from the flags and a KBPK, without Vault
	params.Kbkp = "DD7515F2BFC17F85CE48F3CA25CB21F6"
	wrapped, err := server.EncryptData(params)
	require.NoError(t, err)
	require.Contains(t, wrapped, "B0096P0TE00N0000")

	unwrapped, err := server.DecryptData(server.UnifiedParams{
		Kbkp:     params.Kbkp,
		KeyBlock: wrapped,
	})
	require.NoError(t, err)
	require.Equal(t, "3f419e1cb7079442aa37474c2efbf8b8", unwrapped)
}

func TestBuildParams_Decrypt(t *testing.T) {
	setBool(t, flagDecrypt, true)
	setVaultFlags(t)

	_, err := buildParams()
	require.ErrorContains(t, err, "key_block")

	setFlag(t, flagDecryptKeyBlock, "B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A3B8E4FA4C5F5341176EED7B727B8A248E") // gitleaks:allow
	params, err := buildParams()
	require.NoError(t, err)
	require.Equal(t, "secret/data/tr31", params.KeyPath)
}
