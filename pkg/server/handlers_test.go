package server

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Sample struct for testing JSON binding
type TestParams struct {
	Name  string `json:"name"`
	Age   int    `json:"age"`
	Email string `json:"email,omitempty"`
}

// Test cases for bindJSON
func TestBindJSON(t *testing.T) {
	tests := []struct {
		name          string
		requestBody   string
		expectedError error
		expectedData  TestParams
	}{
		{
			name:          "Valid JSON",
			requestBody:   `{"name":"John","age":30}`,
			expectedError: nil,
			expectedData:  TestParams{Name: "John", Age: 30},
		},
		{
			name:          "Valid JSON with optional field",
			requestBody:   `{"name":"Alice","age":25,"email":"alice@example.com"}`,
			expectedError: nil,
			expectedData:  TestParams{Name: "Alice", Age: 25, Email: "alice@example.com"},
		},
		{
			name:          "Invalid JSON format",
			requestBody:   `{"name":"Invalid", "age":}`,
			expectedError: errors.New("could not parse json request"),
		},
		{
			name:          "Empty JSON",
			requestBody:   `{}`,
			expectedError: nil,
			expectedData:  TestParams{},
		},
		{
			name:          "Extra Fields Ignored",
			requestBody:   `{"name":"Charlie","age":40,"extraField":"ignored"}`,
			expectedError: nil,
			expectedData:  TestParams{Name: "Charlie", Age: 40},
		},
		{
			name:          "Missing Required Fields",
			requestBody:   `{"age":50}`,
			expectedError: nil,
			expectedData:  TestParams{Age: 50}, // Name is empty
		},
		{
			name:          "Empty Body",
			requestBody:   ``,
			expectedError: errors.New("could not parse json request"),
		},
		{
			name:          "Malformed JSON - No closing bracket",
			requestBody:   `{"name":"John"`,
			expectedError: errors.New("could not parse json request"),
		},
		{
			name:          "Incorrect Data Type",
			requestBody:   `{"name":"John","age":"notanumber"}`,
			expectedError: errors.New("could not parse json request"),
		},
		{
			name:          "Whitespace and Valid JSON",
			requestBody:   `  {  "name" : "Emily" , "age" : 28 }  `,
			expectedError: nil,
			expectedData:  TestParams{Name: "Emily", Age: 28},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(tc.requestBody))
			req.Header.Set("Content-Type", "application/json")

			var params TestParams
			err := bindJSON(req, &params)

			// Check for expected error
			if tc.expectedError != nil {
				if err == nil || err.Error()[:28] != tc.expectedError.Error()[:28] {
					t.Errorf("Expected error '%v', got '%v'", tc.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				// Check if the parsed data matches expected data
				if params != tc.expectedData {
					t.Errorf("Expected %+v, got %+v", tc.expectedData, params)
				}
			}
		})
	}
}
