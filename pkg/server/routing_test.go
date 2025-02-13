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
	require.Equal(t, "afeaf5aed5ed4a6a", response1.IK)

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
	require.Equal(t, "afeaf5aed5ed4a6a", response2.Machines[0].InitialKey)

	req = httptest.NewRequest("GET", "/machine/afeaf5aed5ed4a6a", nil)
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
	require.Equal(t, "afeaf5aed5ed4a6a", response3.Machine.InitialKey)
}
