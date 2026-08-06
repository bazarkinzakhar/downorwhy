package scanner_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/downorwhy/downorwhy/internal/core/scanner"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

func testLogger() zerolog.Logger {
	return zerolog.New(os.Stderr).Level(zerolog.Disabled)
}

func testConfig() types.Config {
	cfg := types.DefaultConfig()
	cfg.Timeout = 5 * time.Second
	cfg.AllowPrivateTargets = true
	return cfg
}

func TestScanInvalidURL(t *testing.T) {
	_, err := scanner.Scan(context.Background(), "not a url", testConfig(), testLogger())
	require.Error(t, err)
}

func TestScanUnsafeTarget(t *testing.T) {
	cfg := testConfig()
	cfg.AllowPrivateTargets = false
	_, err := scanner.Scan(context.Background(), "http://127.0.0.1:8080/", cfg, testLogger())
	require.Error(t, err)
}

func TestScanValidHTTPServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	report, err := scanner.Scan(context.Background(), srv.URL, testConfig(), testLogger())
	require.NoError(t, err)
	require.NotNil(t, report)
	require.True(t, report.Reachable)

	require.Equal(t, types.StatusDegraded, report.OverallStatus)
	require.GreaterOrEqual(t, report.HealthScore, 50)
}

func TestScanProducesReportForUnreachableTarget(t *testing.T) {
	cfg := testConfig()
	cfg.Timeout = 200 * time.Millisecond
	cfg.AllowPrivateTargets = true

	// This will fail to connect because nothing listens on this port, but
	// localhost is allowed by AllowPrivateTargets.
	report, err := scanner.Scan(context.Background(), "http://127.0.0.1:1/", cfg, testLogger())
	// Scanner returns a report even when the target is unreachable.
	require.NoError(t, err)
	require.False(t, report.Reachable)
	require.NotNil(t, report)
}
