# rego-debug

A Go CLI tool that evaluates local [OPA/Rego](https://www.openpolicyagent.org/) policies and explains **why** a policy passed or failed — in human-readable, Git-diff-style output pointing directly to your `.rego` source files.

## Features

- **Pass output** — shows which rule matched and which expressions were satisfied
- **Fail output** — lists every attempted rule, annotates the first failing expression with the actual vs. expected value, and marks subsequent expressions as "not reached"
- **Drill-down mode** (`--rule`) — walks through each expression in a specific rule step-by-step, highlights the first failure, shows source context, and explains exactly why the input doesn't satisfy the rule
- Uses the OPA Go SDK directly (no external `opa` binary required)

## Installation

```bash
git clone https://github.com/adibiton/rego-why-cli
cd rego-why-cli
go build -o rego-debug .
```

## Usage

```
rego-debug --data <policy-dir> --input <input.json> --query <rego-query> [--rule <rule-path>]
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--data` | `-d` | ✓ | Folder containing `.rego` policy files |
| `--input` | `-i` | ✓ | Path to a JSON input file |
| `--query` | `-q` | ✓ | Rego query string, e.g. `data.authz.allow` |
| `--rule` | `-r` |  | Specific rule path for drill-down explanation |

## Examples

Given this policy (`policy/authz.rego`):

```rego
package authz

default allow = false

allow {
    input.role == "admin"
    input.action == "write"
}
```

### Pass

```bash
rego-debug -d policy -i input.json -q "data.authz.allow"
# input.json: {"role": "admin", "action": "write"}
```

```
✓ PASS: data.authz.allow
  Rule: data.authz.allow (policy/authz.rego:5)
  Matched expression: input.role == "admin"
  Matched expression: input.action == "write"
```

### Fail

```bash
rego-debug -d policy -i input.json -q "data.authz.allow"
# input.json: {"role": "viewer", "action": "read"}
```

```
✗ FAIL: data.authz.allow
  Attempted rules:
    data.authz.allow (policy/authz.rego:5)
      input.role == "admin"  <-- FAILED (got "viewer", expected "admin")
      input.action == "write"  <-- not reached
```

### Drill-down (`--rule`)

```bash
rego-debug -d policy -i input.json -q "data.authz.allow" -r "data.authz.allow"
```

```
Drill-down: Why does the input NOT satisfy data.authz.allow?
  Defined at policy/authz.rego:5

  [1] input.role == "admin"
  ^^^ FIRST FAILING EXPRESSION
      compared: "viewer"  vs  "admin"
      status: FAILED

  [2] input.action == "write"
      status: not reached (earlier expression failed)

Summary: rule "data.authz.allow" has 2 expression(s):
  1 failed
  1 not reached

Source context (policy/authz.rego:6):
     4 |
     5 | allow {
     6 |     input.role == "admin"
     7 |     input.action == "write"
     8 | }

Tip: Re-run without --rule to see all attempted rules.
```

## Project Structure

```
.
├── main.go                        # Entry point
├── cmd/
│   └── eval.go                    # Cobra CLI — flags, input loading, orchestration
├── internal/
│   ├── evaluator/
│   │   └── engine.go              # OPA evaluation + trace/AST analysis
│   └── trace/
│       └── formatter.go           # Human-readable colored output
└── testdata/
    ├── policy/authz.rego
    ├── input_pass.json
    └── input_fail.json
```

## How It Works

The tool uses `github.com/open-policy-agent/opa` (Go SDK) with `topdown.BufferTracer` to capture evaluation events.

One subtlety: OPA's **rule index optimization** skips evaluating failing rule bodies entirely (they never appear in the trace). To work around this, the tool uses a dual strategy:

- **Pass case** — trace events from `BufferTracer` are sufficient; `EnterOp`/`EvalOp`/`ExitOp` events capture the full evaluation path
- **Fail case** — modules are loaded via `loader.All`, matching non-default rules are found in the AST, and each body expression is evaluated individually to locate the failure point
