package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	router := newRouter(nil)

	request := httptest.NewRequest(http.MethodGet, "/url_api/healthz", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("health check status = %d, want %d", response.Code, http.StatusOK)
	}

	if response.Body.String() != `{"status":"ok"}` {
		t.Fatalf("health check body = %q, want %q", response.Body.String(), `{"status":"ok"}`)
	}
}
