package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mockHttpHandler() http.Handler {
	return MakeHTTPHandler(NewService(NewRepositoryInMemory(nil)))
}

func TestRouting_ping(t *testing.T) {
	router := mockHttpHandler()

	req := httptest.NewRequest("GET", "/ping", nil)
	req.Header.Set("Origin", "https://moov.io")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	w.Flush()

	if w.Code != http.StatusOK {
		t.Errorf("bogus HTTP status: %d", w.Code)
	}
	if v := w.Body.String(); v != "PONG" {
		t.Errorf("body: %s", v)
	}

	resp := w.Result()
	defer resp.Body.Close()
	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "https://moov.io" {
		t.Errorf("Access-Control-Allow-Origin: %s", v)
	}
}

func TestRouting_machine_mgmt(t *testing.T) {
	router := mockHttpHandler()

	// creating machine
	key := mockVaultAuthOne()
	requestBody, err := json.Marshal(key)
	fmt.Printf("%s", requestBody)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/machine", bytes.NewReader(requestBody))
	req.Header.Set("Origin", "https://moov.io")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	w.Flush()

	if w.Code != http.StatusOK {
		t.Errorf("bogus HTTP status: %d", w.Code)
	}

	response1 := createMachineResponse{}
	err = json.Unmarshal(w.Body.Bytes(), &response1)
	require.NoError(t, err)
	require.Equal(t, "99a16e3a9aeccd3c", response1.IK)

	resp := w.Result()
	defer resp.Body.Close()
	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "https://moov.io" {
		t.Errorf("Access-Control-Allow-Origin: %s", v)
	}

	// getting machine
	req = httptest.NewRequest("GET", "/machines", nil)
	req.Header.Set("Origin", "https://moov.io")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	w.Flush()

	if w.Code != http.StatusOK {
		t.Errorf("bogus HTTP status: %d", w.Code)
	}

	response2 := getMachinesResponse{}
	err = json.Unmarshal(w.Body.Bytes(), &response2)
	require.NoError(t, err)
	require.Equal(t, 1, len(response2.Machines))
	require.Equal(t, "99a16e3a9aeccd3c", response2.Machines[0].InitialKey)

	req = httptest.NewRequest("GET", "/machine/99a16e3a9aeccd3c", nil)
	req.Header.Set("Origin", "https://moov.io")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	w.Flush()

	if w.Code != http.StatusOK {
		t.Errorf("bogus HTTP status: %d", w.Code)
	}

	response3 := findMachineResponse{}
	err = json.Unmarshal(w.Body.Bytes(), &response3)
	require.NoError(t, err)
	require.NotNil(t, response3.Machine)
	require.Equal(t, "99a16e3a9aeccd3c", response3.Machine.InitialKey)
}

//func TestCreateMachine(t *testing.T) {
//	tests := []struct {
//		name            string
//		requestData     Vault
//		expectedStatus  int
//		expectedIK      string
//		expectedMachine *Machine
//		expectedError   string
//	}{
//		{
//			name:           "Valid Request",
//			requestData:    mockVaultAuthOne(),
//			expectedStatus: http.StatusOK,
//			expectedIK:     "99a16e3a9aeccd3c",
//			expectedMachine: &Machine{
//				ID:   "machine-001",
//				Name: "Test Machine",
//			},
//			expectedError: "",
//		},
//		{
//			name:           "Empty Request Body",
//			requestData:    Vault{},
//			expectedStatus: http.StatusBadRequest,
//			expectedError:  "invalid request body",
//		},
//		{
//			name: "Missing VaultToken",
//			requestData: Vault{
//				VaultAddress: "http://localhost:8200",
//				VaultToken:   "",
//			},
//			expectedStatus: http.StatusBadRequest,
//			expectedError:  "missing vault token",
//		},
//		{
//			name: "Missing VaultAddress",
//			requestData: Vault{
//				VaultAddress: "",
//				VaultToken:   "test-vault-token-123",
//			},
//			expectedStatus: http.StatusBadRequest,
//			expectedError:  "missing vault address",
//		},
//		{
//			name: "Invalid VaultToken",
//			requestData: Vault{
//				VaultAddress: "http://localhost:8200",
//				VaultToken:   "invalid-token",
//			},
//			expectedStatus: http.StatusUnauthorized,
//			expectedError:  "unauthorized access",
//		},
//		{
//			name: "Invalid VaultAddress",
//			requestData: Vault{
//				VaultAddress: "invalid-url",
//				VaultToken:   "test-vault-token-123",
//			},
//			expectedStatus: http.StatusBadRequest,
//			expectedError:  "invalid vault address",
//		},
//		{
//			name: "Long VaultToken",
//			requestData: Vault{
//				VaultAddress: "http://localhost:8200",
//				VaultToken:   "long-token-string-exceeding-limits-12345678901234567890",
//			},
//			expectedStatus: http.StatusBadRequest,
//			expectedError:  "invalid token format",
//		},
//		{
//			name:           "Machine Creation Failure",
//			requestData:    mockVaultAuthOne(),
//			expectedStatus: http.StatusInternalServerError,
//			expectedError:  "failed to create machine",
//		},
//		{
//			name: "Valid Request with Different User",
//			requestData: Vault{
//				VaultAddress: "http://localhost:8200",
//				VaultToken:   "test-vault-token-user002",
//			},
//			expectedStatus: http.StatusOK,
//			expectedIK:     "99a16e3a9aeccd3c",
//			expectedMachine: &Machine{
//				ID:   "machine-002",
//				Name: "Second Machine",
//			},
//			expectedError: "",
//		},
//		{
//			name: "Invalid JSON Request",
//			requestData: Vault{
//				VaultAddress: "http://localhost:8200",
//				VaultToken:   "<invalid-json>",
//			},
//			expectedStatus: http.StatusBadRequest,
//			expectedError:  "could not parse json",
//		},
//	}
//
//	for _, tc := range tests {
//		t.Run(tc.name, func(t *testing.T) {
//			requestBody, err := json.Marshal(tc.requestData)
//			require.NoError(t, err)
//
//			req := httptest.NewRequest("POST", "/machine", bytes.NewReader(requestBody))
//			req.Header.Set("Origin", "https://moov.io")
//
//			w := httptest.NewRecorder()
//			router.ServeHTTP(w, req)
//			w.Flush()
//
//			// Verify HTTP status code
//			require.Equal(t, tc.expectedStatus, w.Code)
//
//			// Parse response
//			var response createMachineResponse
//			err = json.Unmarshal(w.Body.Bytes(), &response)
//
//			// If the request was expected to be successful
//			if tc.expectedStatus == http.StatusOK {
//				require.NoError(t, err)
//				require.Equal(t, tc.expectedIK, response.IK)
//				require.Equal(t, tc.expectedMachine, response.Machine)
//				require.Empty(t, response.Err)
//			} else {
//				// Expect error message
//				require.Contains(t, response.Err, tc.expectedError)
//			}
//		})
//	}
//}
