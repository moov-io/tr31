package server

import (
	"time"
)

type Vault struct {
	VaultAddress string
	VaultToken   string
}
type Machine struct {
	vaultAuth      Vault
	InitialKey     string
	TransactionKey string
	CreatedAt      time.Time
}

func NewMachine(vaultAuth Vault) *Machine {
	return &Machine{
		vaultAuth: vaultAuth,
	}
}
