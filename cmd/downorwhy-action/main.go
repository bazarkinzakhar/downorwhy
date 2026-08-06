package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sethvargo/go-githubactions"

	"github.com/downorwhy/downorwhy/internal/core/renderers"
	"github.com/downorwhy/downorwhy/internal/core/scanner"
	"github.com/downorwhy/downorwhy/internal/core/types"
	"github.com/downorwhy/downorwhy/internal/shared"
)

func main() {
	action := githubactions.New()

	url := action.GetInput("url")
	if url == "" {
		action.Fatalf("input 'url' is required")
	}

	format := action.GetInput("format")
	if format == "" {
		format = "markdown"
	}

	failOn := action.GetInput("fail-on")
	if failOn == "" {
		failOn = types.FailOnCritical
	}

	outputFile := action.GetInput("output")

	cfg := types.DefaultConfig()
	cfg.Format = format
	cfg.FailOn = failOn
	cfg.Timeout = 30000 * time.Millisecond
	cfg.UserAgent = fmt.Sprintf(shared.UserAgentTemplate, shared.Version)

	if cfg.Validate() != nil {
		action.Fatalf("invalid configuration")
	}

	report, err := scanner.Scan(context.Background(), url, cfg, shared.NewLogger(os.Stderr, false))
	if err != nil {
		action.Errorf("scan error: %s", err)
		if report == nil {
			os.Exit(1)
		}
	}

	// Write report to output file if specified.
	if outputFile != "" {
		data, merr := json.MarshalIndent(report, "", "  ")
		var writeErr error
		if merr == nil {
			if format == "markdown" {
				f, ferr := os.Create(outputFile)
				if ferr == nil {
					defer f.Close()
					writeErr = renderers.Markdown(f, report)
				} else {
					writeErr = ferr
				}
			} else {
				writeErr = os.WriteFile(outputFile, data, 0644)
			}
		}
		if writeErr != nil {
			action.Warningf("could not write output file: %s", writeErr)
		}
	}

	// Write job summary.
	summary := fmt.Sprintf("## DownOrWhy scan: %s\n\n**Status:** %s | **Score:** %d/100 | **Reachable:** %v\n\n",
		report.InputURL, report.OverallStatus, report.HealthScore, report.Reachable)

	if len(report.Critical) > 0 {
		summary += "### Critical findings\n\n"
		for _, f := range report.Critical {
			summary += fmt.Sprintf("- **%s** (%s): %s\n", f.Title, f.Owner, f.Description)
		}
	}
	if len(report.Warnings) > 0 {
		summary += "### Warnings\n\n"
		for _, f := range report.Warnings {
			summary += fmt.Sprintf("- **%s** (%s): %s\n", f.Title, f.Owner, f.Description)
		}
	}

	action.AddStepSummary(summary)

	if cfg.ShouldFail(report) {
		action.Fatalf("scan completed with findings at or above %s threshold", failOn)
	}
	action.Infof("scan complete: %s", report.OverallStatus)
}
