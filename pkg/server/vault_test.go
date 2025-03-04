package server

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVaultClient(t *testing.T) {
	c := testVaultClient(t)

	// TODO: write tests using VaultClient interface
	_ = c
}

func testVaultClient(tb testing.TB) *VaultClient {
	tb.Helper()
	shouldSkipDockerTest(tb)

	conf := Vault{
		VaultAddress: "http://localhost:8200",
		VaultToken:   "myroot",
	}
	cc, err := NewVaultClient(conf)
	require.NoError(tb, err)

	return cc
}

func shouldSkipDockerTest(tb testing.TB) {
	tb.Helper()

	isGithubCI := os.Getenv("GITHUB_ACTIONS") != ""
	isLinux := runtime.GOOS == "linux"
	if isGithubCI && !isLinux {
		tb.Skipf("docker is not supported on %s github runners", runtime.GOOS)
	}
}
