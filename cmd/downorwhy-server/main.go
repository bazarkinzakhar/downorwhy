package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/downorwhy/downorwhy/internal/core/renderers"
	"github.com/downorwhy/downorwhy/internal/core/scanner"
	"github.com/downorwhy/downorwhy/internal/core/types"
	"github.com/downorwhy/downorwhy/internal/shared"
	dowurl "github.com/downorwhy/downorwhy/internal/core/url"
)

type scanRequest struct {
	URL string `json:"url"`
}

func main() {
	port := 8787
	if p, err := strconv.Atoi(os.Getenv("PORT")); err == nil && p > 0 {
		port = p
	}
	for _, arg := range os.Args[1:] {
		if arg == "--port" {
			continue
		}
		if v, err := strconv.Atoi(arg); err == nil && v > 0 {
			port = v
		}
	}

	logger := shared.NewLogger(os.Stderr, os.Getenv("VERBOSE") == "1")

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	r.Post("/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		var req scanRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		if req.URL == "" {
			writeError(w, http.StatusBadRequest, "url field is required")
			return
		}

		// Validate target safety before spending any resources on scanning.
		target, err := dowurl.Normalize(req.URL)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid url: "+err.Error())
			return
		}
		if err := dowurl.DefaultPolicy().CheckTarget(target); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "unsafe target rejected")
			return
		}

		cfg := types.DefaultConfig()
		cfg.UserAgent = fmt.Sprintf(shared.UserAgentTemplate, shared.Version)

		report, err := scanner.Scan(r.Context(), req.URL, cfg, logger)
		if err != nil {
			// Report may still be populated. Return it with error note.
			if report == nil {
				writeError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = renderers.JSON(w, report)
	})

	addr := fmt.Sprintf(":%d", port)
	logger.Info().Str("addr", addr).Msg("downorwhy-server starting")

	if err := http.ListenAndServe(addr, r); err != nil {
		logger.Fatal().Err(err).Msg("server stopped")
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
