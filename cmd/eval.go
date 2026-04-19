package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/adibiton/rego-debug/internal/evaluator"
	"github.com/adibiton/rego-debug/internal/trace"
	"github.com/spf13/cobra"
)

var (
	dataPath  string
	inputPath string
	query     string
	rulePath  string
)

var rootCmd = &cobra.Command{
	Use:   "rego-debug",
	Short: "Evaluate Rego policies and explain why they pass or fail",
	Long: `rego-debug evaluates OPA/Rego policies against a JSON input and
produces a human-readable diagnostic trace explaining the result.

Examples:
  rego-debug -d ./policy -i input.json -q "data.authz.allow"
  rego-debug -d ./policy -i input.json -q "data.authz.allow" -r "data.authz.allow"`,
	RunE: runEval,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&dataPath, "data", "d", "", "Folder path containing .rego policy files (required)")
	rootCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to JSON input file (required)")
	rootCmd.Flags().StringVarP(&query, "query", "q", "", `Rego query string, e.g. "data.authz.allow" (required)`)
	rootCmd.Flags().StringVarP(&rulePath, "rule", "r", "", `Specific rule path for drill-down explanation, e.g. "data.authz.allow"`)

	_ = rootCmd.MarkFlagRequired("data")
	_ = rootCmd.MarkFlagRequired("input")
	_ = rootCmd.MarkFlagRequired("query")
}

func runEval(cmd *cobra.Command, args []string) error {
	// Suppress usage on runtime errors — the error message is already descriptive.
	cmd.SilenceUsage = true

	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		return fmt.Errorf("--data path %q does not exist", dataPath)
	}

	inputBytes, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("cannot read input file %q: %w", inputPath, err)
	}

	var inputDoc interface{}
	if err := json.Unmarshal(inputBytes, &inputDoc); err != nil {
		return fmt.Errorf("invalid JSON in input file %q: %w", inputPath, err)
	}

	result, err := evaluator.Evaluate(context.Background(), evaluator.Options{
		DataPath:  dataPath,
		InputDoc:  inputDoc,
		Query:     query,
		DrillRule: rulePath,
	})
	if err != nil {
		return err
	}

	formatter := trace.NewFormatter(os.Stdout)
	formatter.Print(result)
	return nil
}
