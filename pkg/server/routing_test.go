package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func mockHttpHandler() http.Handler {
	repository := NewRepositoryInMemory(nil)
	return MakeHTTPHandler(NewMockService(repository))
}

func TestRouting_ping(t *testing.T) {
	repository := NewRepositoryInMemory(nil)
	mockService := NewMockService(repository)

	router := MakeHTTPHandler(mockService)

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

func TestRouting_create_duplicate_machine(t *testing.T) {
	router := mockHttpHandler()
	requestBody, err := json.Marshal(mockVaultAuthOne())
	require.NoError(t, err)

	expectedMachineIK := "80cae8bed08fe2cc"

	req := httptest.NewRequest("POST", "/machine", bytes.NewReader(requestBody))
	req.Header.Set("Origin", "https://moov.io")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	w.Flush()
	var responseAgain createMachineResponse
	err = json.Unmarshal(w.Body.Bytes(), &responseAgain)
	require.NoError(t, err)
	require.Equal(t, expectedMachineIK, responseAgain.IK)

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
			name:           "Missing Vault Token",
			requestData:    Vault{VaultAddress: "http://localhost:8200"},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Invalid vault Token.",
		},
		{
			name:           "Empty Request Body",
			requestData:    Vault{},
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
func TestGetMachineHandler(t *testing.T) {
	router := mockHttpHandler() // Initialize your mock HTTP handler

	// Define test cases
	tests := []struct {
		name           string
		method         string
		url            string
		body           interface{}
		headers        map[string]string
		expectedStatus int
		validateResp   bool // If true, validate response body
		expectedKey    string
	}{
		{
			name:           "Valid Machine Creation",
			method:         "POST",
			url:            "/machine",
			body:           mockVaultAuthOne(),
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusOK,
			validateResp:   true,
			expectedKey:    "99a16e3a9aeccd3c",
		},
		{
			name:           "Missing Request Body",
			method:         "POST",
			url:            "/machines",
			body:           nil,
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusNotFound,
			validateResp:   false,
		},
		{
			name:           "Invalid JSON Format",
			method:         "POST",
			url:            "/machines",
			body:           "{invalid json}",
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusNotFound,
			validateResp:   false,
		},
		{
			name:           "Fetch Created Machine",
			method:         "GET",
			url:            "/machines",
			body:           nil,
			headers:        map[string]string{"Authorization": "Bearer valid-token"},
			expectedStatus: http.StatusOK,
			validateResp:   true,
			expectedKey:    "80cae8bed08fe2cc",
		},
		{
			name:           "Machine Not Found",
			method:         "GET",
			url:            "/machines/nonexistent",
			body:           nil,
			headers:        map[string]string{"Authorization": "Bearer valid-token"},
			expectedStatus: http.StatusNotFound,
			validateResp:   false,
		},
	}

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody []byte
			var err error

			// Marshal request body if not nil
			if tt.body != nil {
				switch v := tt.body.(type) {
				case string:
					reqBody = []byte(v) // Handle invalid JSON case
				default:
					reqBody, err = json.Marshal(tt.body)
					require.NoError(t, err)
				}
			}

			// Create request
			req, err := http.NewRequest(tt.method, tt.url, bytes.NewBuffer(reqBody))
			require.NoError(t, err)

			// Set headers if provided
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Send request
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Validate response status
			require.Equal(t, tt.expectedStatus, w.Code)

			if tt.name == "Valid Machine Creation" {
				var response createMachineResponse
				err = json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
			} else if tt.validateResp {
				response2 := getMachinesResponse{}
				err = json.Unmarshal(w.Body.Bytes(), &response2)
				require.NoError(t, err)
				require.Equal(t, 1, len(response2.Machines))
				require.Equal(t, tt.expectedKey, response2.Machines[0].InitialKey)
			} else {
				response2 := getMachinesResponse{}
				println("%v", w.Body.String())
				if w.Code == http.StatusNotFound {

				} else {
					err = json.Unmarshal(w.Body.Bytes(), &response2)
					require.NoError(t, err)
				}
			}
		})
	}
}
func TestFindMachine(t *testing.T) {
	router := mockHttpHandler() // Initialize your mock HTTP handler

	// Define test cases
	tests := []struct {
		name           string
		method         string
		url            string
		body           interface{}
		headers        map[string]string
		expectedStatus int
		validateResp   bool // If true, validate response body
		expectedKey    string
	}{
		{
			name:           "Valid Machine Creation",
			method:         "POST",
			url:            "/machine",
			body:           mockVaultAuthOne(),
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusOK,
			validateResp:   true,
			expectedKey:    "80cae8bed08fe2cc",
		},
		{
			name:           "Find Existing Machine",
			method:         "GET",
			url:            "/machine/80cae8bed08fe2cc",
			body:           nil,
			headers:        map[string]string{"Authorization": "Bearer valid-token"},
			expectedStatus: http.StatusOK,
			validateResp:   true,
			expectedKey:    "80cae8bed08fe2cc",
		},
		{
			name:           "Machine Not Found",
			method:         "GET",
			url:            "/machine/nonexistent",
			body:           nil,
			headers:        map[string]string{"Authorization": "Bearer valid-token"},
			expectedStatus: http.StatusNotFound,
			validateResp:   false,
		},
		{
			name:           "Malformed Request URL",
			method:         "GET",
			url:            "/machine/??",
			body:           nil,
			headers:        map[string]string{"Authorization": "Bearer valid-token"},
			expectedStatus: http.StatusNotFound,
			validateResp:   false,
		},
		{
			name:           "Find Machine Without Initial Key",
			method:         "GET",
			url:            "/machines/",
			body:           nil,
			headers:        map[string]string{"Authorization": "Bearer valid-token"},
			expectedStatus: http.StatusNotFound,
			validateResp:   false,
		},
		{
			name:           "Invalid Method (POST instead of GET)",
			method:         "POST",
			url:            "/machine/99a16e3a9aeccd3c",
			body:           nil,
			headers:        map[string]string{"Authorization": "Bearer valid-token"},
			expectedStatus: http.StatusNotFound,
			validateResp:   false,
		},
	}

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody []byte
			var err error

			// Marshal request body if not nil
			if tt.body != nil {
				switch v := tt.body.(type) {
				case string:
					reqBody = []byte(v) // Handle invalid JSON case
				default:
					reqBody, err = json.Marshal(tt.body)
					require.NoError(t, err)
				}
			}

			// Create request
			req, err := http.NewRequest(tt.method, tt.url, bytes.NewBuffer(reqBody))
			require.NoError(t, err)

			// Set headers if provided
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Send request
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Validate response status
			require.Equal(t, tt.expectedStatus, w.Code)

			// Validate response body if needed
			if tt.name == "Valid Machine Creation" {
				var response createMachineResponse
				err = json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
			} else if tt.validateResp {
				response3 := findMachineResponse{}
				err = json.Unmarshal(w.Body.Bytes(), &response3)
				require.NoError(t, err)
				require.NotNil(t, response3.Machine)
				require.Equal(t, tt.expectedKey, response3.Machine.InitialKey)
			}
		})
	}
}
func Test_DecryptData(t *testing.T) {
	type decryptRequest struct {
		VaultAdd   string `json:"vaultAdd"`
		VaultToken string `json:"vaultToken"`
		KeyPath    string `json:"keyPath"`
		KeyName    string `json:"keyName"`
		KeyBlock   string `json:"keyBlock"`
	}

	tests := []struct {
		name           string
		method         string
		url            string
		body           interface{}
		headers        map[string]string
		expectedStatus int
		validateResp   bool // If true, validate response body
		expectedKey    string
	}{
		{
			name:           "Valid Machine Creation",
			method:         "POST",
			url:            "/machine",
			body:           mockVaultAuthOne(),
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusOK,
			validateResp:   true,
			expectedKey:    "99a16e3a9aeccd3c",
		},
		{
			name:           "Find Existing Machine",
			method:         "GET",
			url:            "/machine/80cae8bed08fe2cc",
			body:           nil,
			headers:        map[string]string{"Authorization": "Bearer valid-token"},
			expectedStatus: http.StatusOK,
			validateResp:   true,
			expectedKey:    "80cae8bed08fe2cc",
		},
		{
			name:   "Valid Decrypt data",
			method: "POST",
			url:    "/decrypt_data",
			body: decryptRequest{
				VaultAdd:   "mock",
				VaultToken: "mock",
				KeyPath:    "secret/tr31",
				KeyName:    "kbkp",
				KeyBlock:   "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E"}, // gitleaks:allow
			expectedStatus: http.StatusOK,
			validateResp:   true,
			expectedKey:    "ccccccccccccccccdddddddddddddddd",
		},
		{
			name:   "Missing KeyBlock",
			method: "POST",
			url:    "/decrypt_data",
			body: decryptRequest{
				KeyPath: "secret/tr31",
				KeyName: "kbkp",
			},
			expectedStatus: http.StatusInternalServerError,
			validateResp:   false,
		},
		{
			name:   "Invalid KeyBlock Format",
			method: "POST",
			url:    "/decrypt_data",
			body: decryptRequest{
				KeyPath:  "secret/tr31",
				KeyName:  "kbkp",
				KeyBlock: "INVALID_KEYBLOCK_1234",
			},
			expectedStatus: http.StatusInternalServerError,
			validateResp:   false,
		},
		{
			name:   "Missing KeyPath",
			method: "POST",
			url:    "/decrypt_data",
			body: decryptRequest{
				KeyName:  "kbkp",
				KeyBlock: "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E", // gitleaks:allow
			},
			expectedStatus: http.StatusInternalServerError,
			validateResp:   false,
		},
		{
			name:           "Invalid HTTP Method",
			method:         "GET",
			url:            "/decrypt_data",
			expectedStatus: http.StatusMethodNotAllowed,
			validateResp:   false,
		},
		{
			name:           "Empty Request Body",
			method:         "POST",
			url:            "/decrypt_data",
			body:           nil,
			expectedStatus: http.StatusInternalServerError,
			validateResp:   false,
		},
		{
			name:   "Unexpected JSON Structure",
			method: "POST",
			url:    "/decrypt_data",
			body: map[string]interface{}{
				"wrongField": "unexpected",
			},
			expectedStatus: http.StatusInternalServerError,
			validateResp:   false,
		},
	}

	repository := NewRepositoryInMemory(nil)
	mockService := NewMockService(repository)
	mockService.GetSecretManager().WriteSecret(
		"secret/tr31",
		"kbkp",
		"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC",
	)
	router := MakeHTTPHandler(mockService)

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody []byte
			var err error

			// Marshal request body if not nil
			if tt.body != nil {
				switch v := tt.body.(type) {
				case string:
					reqBody = []byte(v) // Handle invalid JSON case
				default:
					reqBody, err = json.Marshal(tt.body)
					require.NoError(t, err)
				}
			}

			// Create request
			req, err := http.NewRequest(tt.method, tt.url, bytes.NewBuffer(reqBody))
			require.NoError(t, err)

			// Set headers if provided
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Send request
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Validate response status
			require.Equal(t, tt.expectedStatus, w.Code)

			// Validate response body if needed
			if tt.name == "Valid Machine Creation" {
				var response createMachineResponse
				err = json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
			} else if tt.name == "Find Existing Machine" {
				response3 := findMachineResponse{}
				err = json.Unmarshal(w.Body.Bytes(), &response3)
				require.NoError(t, err)
				require.NotNil(t, response3.Machine)
				require.Equal(t, tt.expectedKey, response3.Machine.InitialKey)
			} else {
				if tt.expectedStatus == http.StatusOK {
					response4 := decryptDataResponse{}
					err = json.Unmarshal(w.Body.Bytes(), &response4)

					require.NoError(t, err)
					require.NotNil(t, response4.Data)
					require.Equal(t, tt.expectedKey, response4.Data)
				}
			}
		})
	}
}
