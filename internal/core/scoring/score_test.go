package scoring_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/downorwhy/downorwhy/internal/core/scoring"
	"github.com/downorwhy/downorwhy/internal/core/types"
)

func TestScoreUnreachable(t *testing.T) {
	score, status := scoring.Score(types.NewChecks(), false)
	require.Equal(t, 0, score)
	require.Equal(t, types.StatusDown, status)
}

func TestScoreAllPass(t *testing.T) {
	checks := types.NewChecks()
	for _, name := range []string{"dns", "tls", "http", "redirects", "headers", "cdnCache", "performance", "security", "ipv46"} {
		setStatus(&checks, name, types.CheckStatusPass)
	}
	score, status := scoring.Score(checks, true)
	require.Equal(t, 100, score)
	require.Equal(t, types.StatusHealthy, status)
}

func TestScoreMixed(t *testing.T) {
	checks := types.NewChecks()
	// Three fails: 3 × 25 = 75 penalty → 25 score → down
	for _, name := range []string{"dns", "tls", "http"} {
		setStatus(&checks, name, types.CheckStatusFail)
	}
	score, status := scoring.Score(checks, true)
	require.Equal(t, 25, score)
	require.Equal(t, types.StatusDown, status)
}

func TestScoreSkippedNotPenalised(t *testing.T) {
	checks := types.NewChecks()
	// Everything skipped (default state) is 100, not penalised.
	score, _ := scoring.Score(checks, true)
	require.Equal(t, 100, score)
}

func TestScoreOneFailOneWarn(t *testing.T) {
	checks := types.NewChecks()
	setStatus(&checks, "tls", types.CheckStatusFail)
	setStatus(&checks, "headers", types.CheckStatusWarn)
	// 25 + 10 = 35 penalty → 65 score → degraded
	score, status := scoring.Score(checks, true)
	require.Equal(t, 65, score)
	require.Equal(t, types.StatusDegraded, status)
}

func setStatus(c *types.Checks, name string, status string) {
	switch name {
	case "dns":
		c.DNS.Status = status
	case "tls":
		c.TLS.Status = status
	case "http":
		c.HTTP.Status = status
	case "redirects":
		c.Redirects.Status = status
	case "headers":
		c.Headers.Status = status
	case "cdnCache":
		c.CDNCache.Status = status
	case "performance":
		c.Performance.Status = status
	case "security":
		c.Security.Status = status
	case "ipv46":
		c.IPv46.Status = status
	}
}
