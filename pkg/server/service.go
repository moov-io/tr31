package server

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

// Service is a REST interface for interacting with machine structures
type Service interface {
	GetSecretManager() SecretManager
	CreateMachine(m *Machine) error
	GetMachine(ik string) (*Machine, error)
	GetMachines() []*Machine
	DeleteMachine(ik string) error
	EncryptData(ik, keyPath, keyName, encKey string, header HeaderParams, timeout time.Duration) (string, error)
	DecryptData(ik, keyPath, keyName, keyBlock string, timeout time.Duration) (string, error)
}

// service a concrete implementation of the service.
type service struct {
	store       Repository
	vaultClient SecretManager
}

// NewService creates a new concrete service
func NewService(r Repository) Service {
	return &service{
		store:       r,
		vaultClient: nil,
	}
}
func NewMockService(r Repository) Service {
	return &service{
		store:       r,
		vaultClient: NewMockVaultClient(),
	}
}

func (s *service) GetSecretManager() SecretManager {
	return s.vaultClient
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

	if s.GetSecretManager() == nil {
		s.vaultClient, err = NewVaultClient(Vault{VaultAddress: params.VaultAddr, VaultToken: params.VaultToken})
		if err != nil {
			return err
		}
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

func (s *service) EncryptData(ik, keyPath, keyName, encKey string, header HeaderParams, timeout time.Duration) (string, error) {
	m, err := s.GetMachine(ik)
	if err != nil {
		return "", fmt.Errorf("make next ksn: %v(%s)", err, ik)
	}

	vaultParams := UnifiedParams{
		VaultAddr:  m.vaultAuth.VaultAddress,
		VaultToken: m.vaultAuth.VaultToken,
		KeyPath:    keyPath,
		KeyName:    keyName,
		timeout:    timeout,
	}
	keyStr, vErr := readKey(s.vaultClient, vaultParams)
	if vErr != nil {
		return "", vErr
	}
	params := UnifiedParams{
		Kbkp:    keyStr,
		EncKey:  encKey,
		Header:  header,
		timeout: timeout,
	}
	return EncryptData(params)
}

func (s *service) DecryptData(ik, keyPath, keyName, keyBlock string, timeout time.Duration) (string, error) {
	m, err := s.GetMachine(ik)
	if err != nil {
		return "", fmt.Errorf("make next ksn: %v(%s)", err, ik)
	}
	vaultParams := UnifiedParams{
		VaultAddr:  m.vaultAuth.VaultAddress,
		VaultToken: m.vaultAuth.VaultToken,
		KeyPath:    keyPath,
		KeyName:    keyName,
		timeout:    timeout,
	}

	keyStr, err := readKey(s.vaultClient, vaultParams)
	if err != nil {
		return "", err
	}
	params := UnifiedParams{
		Kbkp:     keyStr,
		KeyName:  keyName,
		KeyBlock: keyBlock,
		timeout:  timeout,
	}

	return DecryptData(params)
}

func (s *service) DeleteMachine(ik string) error {
	return s.store.DeleteMachine(ik)
}

func Encrypt(params UnifiedParams) (string, error) {
	vaultClient, err := NewVaultClient(Vault{VaultAddress: params.VaultAddr, VaultToken: params.VaultToken})
	if err != nil {
		return "", err
	}
	vaultParams := UnifiedParams{
		VaultAddr:  params.VaultAddr,
		VaultToken: params.VaultToken,
		KeyPath:    params.KeyPath,
		KeyName:    params.KeyName,
		timeout:    0,
	}
	keyStr, err := readKey(vaultClient, vaultParams)
	if err != nil {
		return "", err
	}
	enc_params := UnifiedParams{
		Kbkp:    keyStr,
		EncKey:  params.EncKey,
		Header:  params.Header,
		timeout: 0,
	}
	return EncryptData(enc_params)
}

func Decrypt(params UnifiedParams) (string, error) {
	vaultClient, err := NewVaultClient(Vault{VaultAddress: params.VaultAddr, VaultToken: params.VaultToken})
	if err != nil {
		return "", err
	}
	vaultParams := UnifiedParams{
		VaultAddr:  params.VaultAddr,
		VaultToken: params.VaultToken,
		KeyPath:    params.KeyPath,
		KeyName:    params.KeyName,
		timeout:    0,
	}
	keyStr, err := readKey(vaultClient, vaultParams)
	if err != nil {
		return "", err
	}
	dec_params := UnifiedParams{
		Kbkp:     keyStr,
		KeyName:  params.KeyName,
		KeyBlock: params.KeyBlock,
		timeout:  0,
	}
	return DecryptData(dec_params)
}
