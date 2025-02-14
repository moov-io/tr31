package server

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

// Service is a REST interface for interacting with machine structures
type Service interface {
	CreateMachine(m *Machine) error
	GetMachine(ik string) (*Machine, error)
	GetMachines() []*Machine
	DeleteMachine(ik string) error
	DecryptData(ik, kekId, keyBlock string) (string, error)
}

// service a concrete implementation of the service.
type service struct {
	store Repository
}

// NewService creates a new concrete service
func NewService(r Repository) Service {
	return &service{
		store: r,
	}
}

// CreateMachine add a machine to storage
func (s *service) CreateMachine(m *Machine) error {
	if m == nil {
		return ErrNotFound
	}

	params := UnifiedParams{
		VaultAddr:  m.vaultAuth.VaultAddress,
		VaultToken: m.vaultAuth.VaultToken,
	}

	ik, err := InitialKey(params)
	if err != nil {
		return err
	}
	m.InitialKey = ik
	tk, err := TransactionKey(params)
	if err != nil {
		return err
	}
	m.TransactionKey = tk
	if err = s.store.StoreMachine(m); err != nil {
		return err
	}

	return nil
}

// GetMachine returns a machine based on the supplied initial key
func (s *service) GetMachine(ik string) (*Machine, error) {
	f, err := s.store.FindMachine(ik)
	if err != nil {
		return nil, ErrNotFound
	}
	return f, nil
}

func (s *service) GetMachines() []*Machine {
	return s.store.FindAllMachines()
}

func (s *service) DecryptData(ik, kekId, keyBlock string) (string, error) {
	m, err := s.GetMachine(ik)
	if err != nil {
		return "", fmt.Errorf("make next ksn: %v(%s)", err, ik)
	}

	params := UnifiedParams{
		VaultAddr:  m.vaultAuth.VaultAddress,
		VaultToken: m.vaultAuth.VaultToken,
		KekId:      kekId,
		KeyBlock:   keyBlock,
	}

	return DecryptData(params)
}

func (s *service) DeleteMachine(ik string) error {
	return s.store.DeleteMachine(ik)
}
