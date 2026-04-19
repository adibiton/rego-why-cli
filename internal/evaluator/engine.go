package evaluator

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
)

// ExprDiagnostic holds the evaluation result for a single expression in a rule body.
type ExprDiagnostic struct {
	Text          string
	File          string
	Row           int
	Passed        bool
	Reached       bool
	GotValue      string
	ExpectedValue string
}

// RuleDiagnostic groups the per-expression results for a single rule attempt.
type RuleDiagnostic struct {
	RulePath string
	File     string
	Row      int
	Exprs    []ExprDiagnostic
}

// Result holds everything needed to render the diagnostic output.
type Result struct {
	Query     string
	Passed    bool
	Rules     []RuleDiagnostic
	DrillRule *RuleDiagnostic // non-nil only in --rule mode
}

// Options carries the inputs to Evaluate.
type Options struct {
	DataPath  string
	InputDoc  interface{}
	Query     string
	DrillRule string
}

// Evaluate runs the Rego query and returns a structured diagnostic Result.
func Evaluate(ctx context.Context, opts Options) (*Result, error) {
	tracer := topdown.NewBufferTracer()

	r := rego.New(
		rego.Query(opts.Query),
		rego.Load([]string{opts.DataPath}, nil),
		rego.Input(opts.InputDoc),
		rego.QueryTracer(tracer),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, formatOPAError(err)
	}

	result := &Result{
		Query:  opts.Query,
		Passed: len(rs) > 0 && rs.Allowed(),
	}

	events := []*topdown.Event(*tracer)

	if result.Passed {
		// Trace events capture passing rule bodies fully (OPA doesn't skip them).
		result.Rules = extractPassingRules(events, opts.Query)
	} else {
		// OPA's rule index optimization skips evaluation of failing rule bodies,
		// so we analyze the AST directly and evaluate each expression individually.
		rules, err := analyzeRules(ctx, opts)
		if err == nil {
			result.Rules = rules
		}
	}

	if opts.DrillRule != "" {
		result.DrillRule = findDrillRule(result.Rules, opts.DrillRule)
		if result.DrillRule == nil {
			return nil, buildRuleNotFoundError(result.Rules, opts.DrillRule)
		}
	}

	return result, nil
}

// extractPassingRules builds RuleDiagnostics from trace events (used for the pass case).
func extractPassingRules(events []*topdown.Event, query string) []RuleDiagnostic {
	var rules []RuleDiagnostic
	var current *RuleDiagnostic

	for _, evt := range events {
		switch evt.Op {
		case topdown.EnterOp:
			if rule, ok := evt.Node.(*ast.Rule); ok {
				if rule.Default {
					current = nil
					continue
				}
				loc := ruleLoc(rule, evt)
				current = &RuleDiagnostic{
					// Use the query path since the non-default rule corresponds to the query.
					RulePath: query,
					File:     loc.File,
					Row:      loc.Row,
				}
			}

		case topdown.EvalOp:
			if current == nil {
				continue
			}
			if expr, ok := evt.Node.(*ast.Expr); ok {
				loc := exprLoc(expr, evt)
				line := readFileLine(loc.File, loc.Row)
				current.Exprs = append(current.Exprs, ExprDiagnostic{
					Text:    strings.TrimSpace(line),
					File:    loc.File,
					Row:     loc.Row,
					Reached: true,
				})
			}

		case topdown.ExitOp:
			if rule, ok := evt.Node.(*ast.Rule); ok && current != nil && !rule.Default {
				for i := range current.Exprs {
					current.Exprs[i].Passed = true
				}
				rules = append(rules, *current)
				current = nil
			}

		case topdown.FailOp:
			if rule, ok := evt.Node.(*ast.Rule); ok && current != nil && !rule.Default {
				rules = append(rules, *current)
				current = nil
			}
		}
	}

	if current != nil {
		rules = append(rules, *current)
	}
	return rules
}

// analyzeRules loads .rego files, finds rules matching the query, and evaluates
// each body expression individually to pinpoint failures.
func analyzeRules(ctx context.Context, opts Options) ([]RuleDiagnostic, error) {
	loaded, err := loader.All([]string{opts.DataPath})
	if err != nil {
		return nil, fmt.Errorf("loading policy files: %w", err)
	}

	targetPkg, targetRule := parseQueryPath(opts.Query)

	var ruleDiags []RuleDiagnostic
	for _, regoFile := range loaded.Modules {
		module := regoFile.Parsed
		pkgPath := strings.TrimPrefix(module.Package.Path.String(), "data.")
		if pkgPath != targetPkg {
			continue
		}
		for _, rule := range module.Rules {
			if string(rule.Head.Name) != targetRule || rule.Default {
				continue
			}
			diag := RuleDiagnostic{
				RulePath: opts.Query,
				File:     rule.Loc().File,
				Row:      rule.Loc().Row,
			}
			diag.Exprs = evaluateBodyExprs(ctx, rule.Body, opts)
			ruleDiags = append(ruleDiags, diag)
		}
	}
	return ruleDiags, nil
}

// evaluateBodyExprs evaluates each expression in a rule body, stopping after the first failure.
func evaluateBodyExprs(ctx context.Context, body ast.Body, opts Options) []ExprDiagnostic {
	var exprs []ExprDiagnostic
	failed := false

	for _, expr := range body {
		loc := expr.Loc()
		if loc == nil {
			loc = &ast.Location{}
		}
		line := readFileLine(loc.File, loc.Row)

		d := ExprDiagnostic{
			Text:    strings.TrimSpace(line),
			File:    loc.File,
			Row:     loc.Row,
			Reached: !failed,
		}

		if !failed {
			passed := evalSingleExpr(ctx, expr, opts)
			d.Passed = passed
			if !passed {
				failed = true
				d.GotValue, d.ExpectedValue = extractExprOperands(expr, opts.InputDoc)
			}
		}

		exprs = append(exprs, d)
	}
	return exprs
}

// evalSingleExpr evaluates one body expression against the given input.
// It returns true only when the expression is satisfied.
func evalSingleExpr(ctx context.Context, expr *ast.Expr, opts Options) bool {
	r := rego.New(
		rego.Query(expr.String()),
		rego.Load([]string{opts.DataPath}, nil),
		rego.Input(opts.InputDoc),
	)
	rs, err := r.Eval(ctx)
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false
	}
	// Check the actual boolean value returned by the expression.
	// OPA returns {[false]} for equality expressions that don't match,
	// so we can't rely on len(rs) > 0 alone.
	if boolVal, ok := rs[0].Expressions[0].Value.(bool); ok {
		return boolVal
	}
	// Non-boolean result (e.g., a set or object) means the expression produced a value → truthy.
	return true
}

// extractExprOperands returns human-readable got/expected strings for binary expressions.
// It resolves input references against inputDoc for the "got" side.
func extractExprOperands(expr *ast.Expr, inputDoc interface{}) (got, expected string) {
	ops := expr.Operands()
	if len(ops) < 2 {
		return "", ""
	}
	lhs := ops[0].String()
	rhs := ops[1].String()

	// Try to resolve the LHS against the input document (e.g. input.role → "viewer").
	if strings.HasPrefix(lhs, "input.") {
		if resolved := resolveInputPath(lhs, inputDoc); resolved != "" {
			return resolved, rhs
		}
	}
	return lhs, rhs
}

// resolveInputPath navigates inputDoc following a dotted path like "input.role".
func resolveInputPath(ref string, inputDoc interface{}) string {
	path := strings.TrimPrefix(ref, "input.")
	parts := strings.Split(path, ".")
	current := inputDoc
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current = m[part]
	}
	if current == nil {
		return "undefined"
	}
	switch v := current.(type) {
	case string:
		return fmt.Sprintf("%q", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func findDrillRule(rules []RuleDiagnostic, target string) *RuleDiagnostic {
	for _, d := range rules {
		if d.RulePath == target || strings.HasSuffix(d.RulePath, "."+strings.TrimPrefix(target, "data.")) {
			for _, e := range d.Exprs {
				if !e.Passed && e.Reached {
					copy := d
					return &copy
				}
			}
		}
	}
	return nil
}

func buildRuleNotFoundError(rules []RuleDiagnostic, target string) error {
	seen := make([]string, 0, len(rules))
	for _, r := range rules {
		seen = append(seen, r.RulePath)
	}
	if len(seen) == 0 {
		return fmt.Errorf("rule %q not found in evaluation", target)
	}
	return fmt.Errorf("rule %q not found.\nAvailable rules: %s", target, strings.Join(seen, ", "))
}

func parseQueryPath(query string) (pkg, rule string) {
	trimmed := strings.TrimPrefix(query, "data.")
	parts := strings.Split(trimmed, ".")
	if len(parts) < 2 {
		return "", trimmed
	}
	return strings.Join(parts[:len(parts)-1], "."), parts[len(parts)-1]
}

func ruleLoc(rule *ast.Rule, evt *topdown.Event) *ast.Location {
	if loc := rule.Loc(); loc != nil {
		return loc
	}
	if evt != nil && evt.Location != nil {
		return evt.Location
	}
	return &ast.Location{}
}

func exprLoc(expr *ast.Expr, evt *topdown.Event) *ast.Location {
	if loc := expr.Loc(); loc != nil {
		return loc
	}
	if evt != nil && evt.Location != nil {
		return evt.Location
	}
	return &ast.Location{}
}

func readFileLine(file string, row int) string {
	if file == "" || row <= 0 {
		return ""
	}
	f, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for i := 1; scanner.Scan(); i++ {
		if i == row {
			return scanner.Text()
		}
	}
	return ""
}

func formatOPAError(err error) error {
	type locationer interface {
		Loc() *ast.Location
	}
	if le, ok := err.(locationer); ok {
		if loc := le.Loc(); loc != nil {
			return fmt.Errorf("OPA compile error at %s:%d: %w", loc.File, loc.Row, err)
		}
	}
	return fmt.Errorf("OPA error: %w", err)
}
