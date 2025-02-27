package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/gorilla/mux"
	moovhttp "github.com/moov-io/base/http"
)

func bindJSON(request *http.Request, params interface{}) (err error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return fmt.Errorf("could not parse json request: %s", err)
	}
	err = json.Unmarshal(body, params)
	if err != nil {
		return fmt.Errorf("could not parse json request: %s", err)
	}
	return
}

type getMachinesRequest struct {
	requestID string
}

type getMachinesResponse struct {
	Machines []*Machine `json:"machines"`
	Err      string     `json:"error"`
}

func decodeGetMachinesRequest(_ context.Context, request *http.Request) (interface{}, error) {
	return getMachinesRequest{
		requestID: moovhttp.GetRequestID(request),
	}, nil
}

func getMachinesEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, _ interface{}) (interface{}, error) {
		return getMachinesResponse{
			Machines: s.GetMachines(),
			Err:      "",
		}, nil
	}
}

type findMachineRequest struct {
	requestID string
	ik        string
}

type findMachineResponse struct {
	Machine *Machine `json:"machine"`
	Err     string   `json:"error"`
}

func decodeFindMachineRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := findMachineRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	req.ik = mux.Vars(request)["ik"]
	return req, nil
}
func findMachineEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(findMachineRequest)
		if req.ik == "" {
			return findMachineResponse{Err: errInvalidRequestId.Error()}, errInvalidRequestId
		}
		if !ok {
			return findMachineResponse{Err: ErrFoundABug.Error()}, ErrFoundABug
		}

		resp := findMachineResponse{}
		m, err := s.GetMachine(req.ik)
		if err != nil {
			resp.Err = err.Error()
			return resp, err
		}

		resp.Machine = m
		return resp, nil
	}
}

type createMachineRequest struct {
	vaultAuth Vault
	requestID string
}

type createMachineResponse struct {
	IK      string   `json:"ik"`
	Machine *Machine `json:"machine"`
	Err     string   `json:"error"`
}

func decodeCreateMachineRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := createMachineRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	if err := bindJSON(request, &req.vaultAuth); err != nil {
		return nil, err
	}

	return req, nil
}

func createMachineEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(createMachineRequest)
		if req.vaultAuth.VaultAddress == "" {
			return createMachineResponse{Err: errInvalidVaultAddress.Error()}, errInvalidVaultAddress
		}
		if req.vaultAuth.VaultToken == "" {
			return createMachineResponse{Err: errInvalidVaultToken.Error()}, errInvalidVaultToken
		}
		if !IsValidURL(req.vaultAuth.VaultAddress) {
			return createMachineResponse{Err: errInvalidVaultAddress.Error()}, errInvalidVaultAddress
		}
		if !ok {
			return createMachineResponse{Err: ErrFoundABug.Error()}, ErrFoundABug
		}

		resp := createMachineResponse{}

		m := NewMachine(req.vaultAuth)
		err := s.CreateMachine(m)
		if err != nil {
			resp.Err = err.Error()
			return resp, err
		}

		resp.Machine = m
		resp.IK = m.InitialKey

		return resp, nil
	}
}

type decryptDataRequest struct {
	requestID string
	ik        string
	keyPath   string
	keyName   string
	keyBlock  string
	timeout   time.Duration
}

type decryptDataResponse struct {
	Data string `json:"data"`
	Err  string `json:"error"`
}

func decodeDecryptDataRequest(_ context.Context, request *http.Request) (interface{}, error) {

	req := decryptDataRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	type requestParam struct {
		KeyPath  string
		KeyName  string
		KeyBlock string
	}

	reqParams := requestParam{}
	if err := bindJSON(request, &reqParams); err != nil {
		return req, err
	}
	req.ik = mux.Vars(request)["ik"]
	req.keyPath = reqParams.KeyPath
	req.keyName = reqParams.KeyName
	req.keyBlock = reqParams.KeyBlock
	return req, nil
}

func decryptDataEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(decryptDataRequest)
		if !ok {
			return decryptDataResponse{Err: ErrFoundABug.Error()}, ErrFoundABug
		}

		if req.keyPath == "" {
			return decryptDataResponse{Err: errInvalidKeyPath.Error()}, errInvalidKeyPath
		}
		if req.keyName == "" {
			return decryptDataResponse{Err: errInvalidKeyName.Error()}, errInvalidKeyName
		}
		if req.keyBlock == "" {
			return decryptDataResponse{Err: errInvalidKeyBlock.Error()}, errInvalidKeyBlock
		}

		resp := decryptDataResponse{}
		decrypted, err := s.DecryptData(req.ik, req.keyPath, req.keyName, req.keyBlock, req.timeout)
		if err != nil {
			resp.Err = err.Error()
			return resp, err
		}

		resp.Data = decrypted
		return resp, nil
	}
}

type encryptDataRequest struct {
	requestID  string
	ik         string
	keyPath    string
	keyName    string
	encryptKey string
	header     HeaderParams
	timeout    time.Duration
}
type encryptDataResponse struct {
	Data string `json:"data"`
	Err  error  `json:"error"`
}

func decodeEncryptDataRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := encryptDataRequest{
		requestID: moovhttp.GetRequestID(request),
	}
	req.ik = mux.Vars(request)["ik"]
	type requestParam struct {
		keyPath    string
		keyName    string
		encryptKey string
		header     HeaderParams
		timeout    time.Duration
	}
	reqParams := requestParam{}
	if err := bindJSON(request, &reqParams); err != nil {
		return nil, err
	}

	req.keyPath = reqParams.keyPath
	req.keyName = reqParams.keyName
	req.encryptKey = reqParams.encryptKey
	req.header = reqParams.header
	req.timeout = reqParams.timeout
	return req, nil
}

func encryptDataEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(encryptDataRequest)
		if !ok {
			return encryptDataResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := encryptDataResponse{}
		encrypted, err := s.EncryptData(req.ik, req.keyPath, req.keyName, req.encryptKey, req.header, req.timeout)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.Data = encrypted
		return resp, nil
	}
}
