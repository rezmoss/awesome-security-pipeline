package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

type response struct {
	Message string `json:"message"`
	Time    string `json:"time"`
}

func main() {
	address := os.Getenv("LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", writeJSON(response{Message: "security pipeline demo", Time: time.Now().UTC().Format(time.RFC3339)}))
	mux.HandleFunc("/healthz", writeJSON(response{Message: "ok", Time: time.Now().UTC().Format(time.RFC3339)}))

	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf("security demo listening on %s", address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func writeJSON(payload response) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if err := json.NewEncoder(writer).Encode(payload); err != nil {
			http.Error(writer, "response encoding failed", http.StatusInternalServerError)
		}
	}
}
