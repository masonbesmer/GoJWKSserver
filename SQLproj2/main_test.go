package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestAuthHandler(t *testing.T) {
	tt := []struct {
		name       string
		method     string
		input      []byte
		expired    bool
		statusCode int
	}{
		{
			name:       "request expired jwt without payload",
			method:     http.MethodPost,
			input:      nil,
			expired:    true,
			statusCode: http.StatusOK,
		},
		{
			name:       "request valid jwt without payload",
			method:     http.MethodPost,
			input:      nil,
			expired:    false,
			statusCode: http.StatusOK,
		},
		{
			name:       "request expired jwt with payload",
			method:     http.MethodPost,
			input:      []byte(`{"username":"test","password":"test"}`),
			expired:    true,
			statusCode: http.StatusOK,
		},
		{
			name:       "request valid jwt with payload",
			method:     http.MethodPost,
			input:      []byte(`{"username":"test","password":"test"}`),
			expired:    false,
			statusCode: http.StatusOK,
		},
		{
			name:       "invalid method",
			method:     http.MethodDelete,
			input:      nil,
			expired:    false,
			statusCode: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, "/auth?expired="+strconv.FormatBool(tc.expired), nil)
			responseRecorder := httptest.NewRecorder()
			pregame()
			AuthHandler(responseRecorder, request)

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("expected status code %d, got %d", tc.statusCode, responseRecorder.Code)
			}
		})
	}
}

func TestJWKSHandler(t *testing.T) {
	tt := []struct {
		name       string
		method     string
		statusCode int
	}{
		{
			name:       "valid method",
			method:     http.MethodGet,
			statusCode: http.StatusOK,
		},
		{
			name:       "invalid method",
			method:     http.MethodPost,
			statusCode: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, "/jwks", nil)
			responseRecorder := httptest.NewRecorder()
			pregame()
			JWKSHandler(responseRecorder, request)

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("expected status code %d, got %d", tc.statusCode, responseRecorder.Code)
			}
		})
	}
}

func TestKeypairGeneration(t *testing.T) {
	genKeys()
}
