package trace

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/adibiton/rego-debug/internal/evaluator"
	"github.com/fatih/color"
)

// Formatter writes diagnostic output to a writer.
type Formatter struct {
	w      io.Writer
	green  *color.Color
	red    *color.Color
	yellow *color.Color
	bold   *color.Color
	dim    *color.Color
	cyan   *color.Color
}

// NewFormatter creates a Formatter that writes to w.
func NewFormatter(w io.Writer) *Formatter {
	return &Formatter{
		w:      w,
		green:  color.New(color.FgGreen, color.Bold),
		red:    color.New(color.FgRed, color.Bold),
		yellow: color.New(color.FgYellow),
		bold:   color.New(color.Bold),
		dim:    color.New(color.Faint),
		cyan:   color.New(color.FgCyan),
	}
}

// Print renders the diagnostic result to the formatter's writer.
func (f *Formatter) Print(result *evaluator.Result) {
	if result.DrillRule != nil {
		f.printDrillDown(result)
		return
	}
	if result.Passed {
		f.printPass(result)
	} else {
		f.printFail(result)
	}
}

func (f *Formatter) printPass(result *evaluator.Result) {
	f.green.Fprintf(f.w, "✓ PASS: %s\n", result.Query)

	for _, rule := range result.Rules {
		if !allPassed(rule) {
			continue
		}
		fmt.Fprintf(f.w, "  Rule: %s (%s:%d)\n", rule.RulePath, rule.File, rule.Row)
		for _, expr := range rule.Exprs {
			if expr.Reached {
				f.green.Fprintf(f.w, "  Matched expression: %s\n", expr.Text)
			}
		}
		break
	}
}

func (f *Formatter) printFail(result *evaluator.Result) {
	f.red.Fprintf(f.w, "✗ FAIL: %s\n", result.Query)
	fmt.Fprintf(f.w, "  Attempted rules:\n")

	for _, rule := range result.Rules {
		fmt.Fprintf(f.w, "    %s", rule.RulePath)
		if rule.File != "" {
			fmt.Fprintf(f.w, " (%s:%d)", rule.File, rule.Row)
		}
		fmt.Fprintln(f.w)

		firstFail := true
		for _, expr := range rule.Exprs {
			if expr.Text == "" {
				continue
			}
			if !expr.Reached {
				f.dim.Fprintf(f.w, "      %s  <-- not reached\n", expr.Text)
				continue
			}
			if !expr.Passed {
				if firstFail {
					firstFail = false
					if expr.GotValue != "" && expr.ExpectedValue != "" {
						f.red.Fprintf(f.w, "      %s  <-- FAILED (got %s, expected %s)\n",
							expr.Text, expr.GotValue, expr.ExpectedValue)
					} else {
						f.red.Fprintf(f.w, "      %s  <-- FAILED\n", expr.Text)
					}
				} else {
					f.yellow.Fprintf(f.w, "      %s  <-- not reached\n", expr.Text)
				}
			} else {
				fmt.Fprintf(f.w, "      %s\n", expr.Text)
			}
		}
	}
}

func (f *Formatter) printDrillDown(result *evaluator.Result) {
	d := result.DrillRule
	fmt.Fprintln(f.w)
	f.bold.Fprintf(f.w, "Drill-down: Why does the input NOT satisfy %s?\n", d.RulePath)
	if d.File != "" {
		f.dim.Fprintf(f.w, "  Defined at %s:%d\n", d.File, d.Row)
	}
	fmt.Fprintln(f.w)

	foundFirstFail := false
	for i, expr := range d.Exprs {
		prefix := fmt.Sprintf("  [%d] ", i+1)
		if !expr.Reached {
			f.dim.Fprintf(f.w, "%s%s\n", prefix, expr.Text)
			f.dim.Fprintf(f.w, "      status: not reached (earlier expression failed)\n\n")
			continue
		}
		if expr.Passed {
			f.green.Fprintf(f.w, "%s%s\n", prefix, expr.Text)
			fmt.Fprintf(f.w, "      status: PASSED\n\n")
		} else {
			if !foundFirstFail {
				foundFirstFail = true
				f.red.Fprintf(f.w, "%s%s\n", prefix, expr.Text)
				f.red.Fprintf(f.w, "  ^^^ FIRST FAILING EXPRESSION\n")
				if expr.GotValue != "" {
					fmt.Fprintf(f.w, "      compared: %s  vs  %s\n", expr.GotValue, expr.ExpectedValue)
				}
				f.red.Fprintf(f.w, "      status: FAILED\n\n")
			} else {
				f.yellow.Fprintf(f.w, "%s%s\n", prefix, expr.Text)
				fmt.Fprintf(f.w, "      status: also failing (evaluation stopped at first failure)\n\n")
			}
		}
	}

	// Count stats
	passing, failing, notReached := 0, 0, 0
	for _, e := range d.Exprs {
		switch {
		case !e.Reached:
			notReached++
		case e.Passed:
			passing++
		default:
			failing++
		}
	}

	f.bold.Fprintf(f.w, "Summary: rule %q has %d expression(s):\n", d.RulePath, len(d.Exprs))
	if passing > 0 {
		f.green.Fprintf(f.w, "  %d passed\n", passing)
	}
	if failing > 0 {
		f.red.Fprintf(f.w, "  %d failed\n", failing)
	}
	if notReached > 0 {
		f.dim.Fprintf(f.w, "  %d not reached\n", notReached)
	}

	// Source context around first failing expression
	for _, expr := range d.Exprs {
		if !expr.Passed && expr.Reached && expr.File != "" {
			fmt.Fprintf(f.w, "\nSource context (%s:%d):\n", expr.File, expr.Row)
			printSourceContext(f.w, expr.File, expr.Row, 2, f.red, f.dim)
			break
		}
	}

	fmt.Fprintln(f.w)
	f.cyan.Fprintf(f.w, "Tip: Re-run without --rule to see all attempted rules.\n")
}

func printSourceContext(w io.Writer, file string, targetRow, ctx int, highlight, normal *color.Color) {
	content, err := os.ReadFile(file)
	if err != nil {
		return
	}
	lines := strings.Split(string(content), "\n")
	start := targetRow - 1 - ctx
	if start < 0 {
		start = 0
	}
	end := targetRow - 1 + ctx
	if end >= len(lines) {
		end = len(lines) - 1
	}
	for i := start; i <= end; i++ {
		lineNum := i + 1
		if lineNum == targetRow {
			highlight.Fprintf(w, "  %4d | %s\n", lineNum, lines[i])
		} else {
			normal.Fprintf(w, "  %4d | %s\n", lineNum, lines[i])
		}
	}
}

func allPassed(rule evaluator.RuleDiagnostic) bool {
	for _, e := range rule.Exprs {
		if !e.Passed {
			return false
		}
	}
	return true
}
