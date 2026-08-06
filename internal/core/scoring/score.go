package scoring

import (
	"github.com/downorwhy/downorwhy/internal/core/types"
)

func Score(checks types.Checks, reachable bool) (int, string) {
	if !reachable {
		return 0, types.StatusDown
	}

	penalty := 0
	for _, r := range checks.All() {
		switch r.Status {
		case types.CheckStatusFail:
			penalty += 25
		case types.CheckStatusWarn:
			penalty += 10
		}
	}

	score := 100 - penalty
	if score < 0 {
		score = 0
	}

	switch {
	case score >= 85:
		return score, types.StatusHealthy
	case score >= 50:
		return score, types.StatusDegraded
	default:
		return score, types.StatusDown
	}
}
