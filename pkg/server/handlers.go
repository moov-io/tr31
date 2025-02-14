package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
	Err      error      `json:"error"`
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
			Err:      nil,
		}, nil
	}
}

type findMachineRequest struct {
	requestID string
	ik        string
}

type findMachineResponse struct {
	Machine *Machine `json:"machine"`
	Err     error    `json:"error"`
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
		if !ok {
			return findMachineResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := findMachineResponse{}
		m, err := s.GetMachine(req.ik)
		if err != nil {
			resp.Err = err
			return resp, nil
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
	Err     error    `json:"error"`
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
		if !ok {
			return createMachineResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := createMachineResponse{}

		m := NewMachine(req.vaultAuth)
		err := s.CreateMachine(m)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.Machine = m
		resp.IK = m.InitialKey

		return resp, nil
	}
}

type decryptDataRequest struct {
	requestID string
	ik        string
	kekId     string
	keyBlock  string
}

type decryptDataResponse struct {
	Data string `json:"data"`
	Err  error  `json:"error"`
}

func decodeDecryptDataRequest(_ context.Context, request *http.Request) (interface{}, error) {
	req := decryptDataRequest{
		requestID: moovhttp.GetRequestID(request),
	}

	req.ik = mux.Vars(request)["ik"]

	type requestParam struct {
		kekId    string
		keyBlock string
	}

	reqParams := requestParam{}
	if err := bindJSON(request, &reqParams); err != nil {
		return nil, err
	}

	req.kekId = reqParams.kekId
	req.keyBlock = reqParams.keyBlock
	return req, nil
}

func decryptDataEndpoint(s Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(decryptDataRequest)
		if !ok {
			return decryptDataResponse{Err: ErrFoundABug}, ErrFoundABug
		}

		resp := decryptDataResponse{}
		decrypted, err := s.DecryptData(req.ik, req.kekId, req.keyBlock)
		if err != nil {
			resp.Err = err
			return resp, nil
		}

		resp.Data = decrypted
		return resp, nil
	}
}
