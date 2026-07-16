package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	writeJSON(response{Message: "ok", Time: "2026-07-16T00:00:00Z"})(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("content type = %q, want application/json", contentType)
	}
	if body := recorder.Body.String(); !strings.Contains(body, `"message":"ok"`) {
		t.Fatalf("body = %q, want ok message", body)
	}
}
