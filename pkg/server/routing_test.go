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

func TestRouting_duplicate_machine(t *testing.T) {
	router := mockHttpHandler()
	requestBody, err := json.Marshal(mockVaultAuthOne())
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/machine", bytes.NewReader(requestBody))
	req.Header.Set("Origin", "https://moov.io")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	w.Flush()
	var responseAgain createMachineResponse
	err = json.Unmarshal(w.Body.Bytes(), &responseAgain)
	require.NoError(t, err)

	requestBodyAgain, err := json.Marshal(mockVaultAuthOne())
	require.NoError(t, err)

	req = httptest.NewRequest("POST", "/machine", bytes.NewReader(requestBodyAgain))
	req.Header.Set("Origin", "https://moov.io")
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)
	w.Flush()
	var response createMachineResponse
	json.Unmarshal(w.Body.Bytes(), &response)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "already exists")

}

func TestCreateMachine(t *testing.T) {
	tests := []struct {
		name           string
		requestData    Vault
		expectedStatus int
		expectedIK     string
		expectedError  string
	}{
		{
			name:           "Valid Request",
			requestData:    mockVaultAuthOne(),
			expectedStatus: http.StatusOK,
			expectedIK:     "80cae8bed08fe2cc",
		},
		{
			name:           "Missing Vault Address",
			requestData:    Vault{VaultToken: "valid_token"},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Invalid Vault Address.",
		},
		{
			name:           "Missing Vault Token",
			requestData:    Vault{VaultAddress: "http://localhost:8200"},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Invalid vault Token.",
		},
		{
			name:           "Invalid Vault Address",
			requestData:    Vault{VaultAddress: "invalid_address", VaultToken: "valid_token"},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Invalid Vault Address.",
		},
		{
			name:           "Empty Request Body",
			requestData:    Vault{},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Invalid Vault Address.",
		},
		{
			name:           "Invalid JSON Request",
			requestData:    Vault{VaultAddress: "{invalid_json}", VaultToken: "valid_token"},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Invalid Vault Address.",
		},
	}

	router := mockHttpHandler()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestBody, err := json.Marshal(tt.requestData)
			require.NoError(t, err)

			req := httptest.NewRequest("POST", "/machine", bytes.NewReader(requestBody))
			req.Header.Set("Origin", "https://moov.io")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)
			w.Flush()

			require.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				var response createMachineResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Equal(t, tt.expectedIK, response.IK)

				resp := w.Result()
				defer resp.Body.Close()
				if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "https://moov.io" {
					t.Errorf("Access-Control-Allow-Origin: %s", v)
				}
			} else {
				require.Contains(t, w.Body.String(), tt.expectedError)
			}
		})
	}
}
