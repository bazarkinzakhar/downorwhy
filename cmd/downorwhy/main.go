package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/downorwhy/downorwhy/internal/core/renderers"
	"github.com/downorwhy/downorwhy/internal/core/scanner"
	"github.com/downorwhy/downorwhy/internal/core/types"
	"github.com/downorwhy/downorwhy/internal/shared"
)

var rootCmd = &cobra.Command{
	Use:   "downorwhy [url]",
	Short: "Explain why a site is down, slow, blocked or misconfigured",
	Long: `DownOrWhy performs read-only checks against a public URL and produces a human-readable
engineering report that explains what is broken, the probable root cause, the
affected layer, who should fix it, and the exact commands to verify the problem.

If no subcommand is given, "scan" is assumed.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

var (
	formatFlag  string
	outputFlag  string
	failOnFlag  string
	timeoutFlag int
	redactFlag  *bool
	verboseFlag bool
	servePort   int
)

var scanCmd = &cobra.Command{
	Use:   "scan [url]",
	Short: "Scan a public URL and produce a report",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a local stateless API server",
	RunE:  runServe,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&formatFlag, "format", "f", "",
		"Output format: json, markdown, html, text (default: markdown for TTY, json for pipe)")
	rootCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "",
		"Write report to file instead of stdout")
	rootCmd.PersistentFlags().StringVar(&failOnFlag, "fail-on", types.FailOnCritical,
		"Exit code threshold: never, critical, warning")
	rootCmd.PersistentFlags().IntVarP(&timeoutFlag, "timeout", "t", 15000,
		"Total scan timeout in milliseconds")
	rootCmd.PersistentFlags().IntVar(&servePort, "port", 8787,
		"Port for the API server")
	redactFlag = rootCmd.PersistentFlags().Bool("redact", true,
		"Redact query parameter values in reports")
	rootCmd.PersistentFlags().Bool("no-redact", false,
		"Disable query parameter redaction")
	rootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false,
		"Enable debug logging to stderr")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(serveCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("url is required")
	}

	cfg := types.DefaultConfig()
	cfg.Verbose = verboseFlag

	// Redaction: default is true. --no-redact sets it to false.
	noRedact, _ := cmd.Flags().GetBool("no-redact")
	if noRedact {
		cfg.Redact = false
	}

	if formatFlag != "" {
		cfg.Format = formatFlag
	} else if isPiped() {
		cfg.Format = types.FormatJSON
	}

	cfg.FailOn = failOnFlag
	cfg.Timeout = time.Duration(timeoutFlag) * time.Millisecond
	cfg.UserAgent = fmt.Sprintf(shared.UserAgentTemplate, shared.Version)

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "downorwhy: invalid configuration: %s\n", err)
		os.Exit(types.ExitInvalidUse)
	}

	logger := shared.NewLogger(os.Stderr, verboseFlag)

	report, err := scanner.Scan(context.Background(), args[0], cfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "downorwhy: %s\n", err)
		if report != nil {
			writeOutput(report, cfg)
		}
		os.Exit(types.ExitCodeOf(err))
	}

	writeOutput(report, cfg)

	if cfg.ShouldFail(report) {
		os.Exit(types.ExitCritical)
	}
	return nil
}

func runServe(cmd *cobra.Command, args []string) error {
	fmt.Fprintf(os.Stderr, "downorwhy-server is built as a separate binary.\n")
	fmt.Fprintf(os.Stderr, "Run: go run ./cmd/downorwhy-server --port %d\n", servePort)
	return nil
}

func isPiped() bool {
	return !term.IsTerminal(int(os.Stdout.Fd()))
}

func writeOutput(report *types.Report, cfg types.Config) {
	var w io.Writer = os.Stdout
	if outputFlag != "" {
		f, err := os.Create(outputFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "downorwhy: cannot open output file: %s\n", err)
			os.Exit(types.ExitInternal)
		}
		defer f.Close()
		w = f
	}

	var err error
	switch cfg.Format {
	case types.FormatJSON:
		err = renderers.JSON(w, report)
	case types.FormatHTML:
		err = renderers.HTML(w, report)
	case types.FormatText:
		err = renderers.Text(w, report)
	default:
		err = renderers.Markdown(w, report)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "downorwhy: cannot write report: %s\n", err)
		os.Exit(types.ExitInternal)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
