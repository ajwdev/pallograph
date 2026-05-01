package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/mangle/ast"
)

// Violation is a single match of a policy predicate.
type Violation struct {
	// Policy is the predicate name, e.g. "orphaned_sa".
	Policy string
	// Args are the matched argument values from the query result.
	Args []ast.BaseTerm
}

// ArgStrings returns the string representation of each argument.
func (v Violation) ArgStrings() []string {
	out := make([]string, len(v.Args))
	for i, a := range v.Args {
		out[i] = a.String()
	}
	return out
}

// Handler processes a policy violation.
type Handler interface {
	Handle(ctx context.Context, v Violation) error
}

// LogHandler emits a structured log line for each violation.
type LogHandler struct {
	Logger *slog.Logger
}

func (h *LogHandler) Handle(_ context.Context, v Violation) error {
	logger := h.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("policy violation",
		"policy", v.Policy,
		"args", strings.Join(v.ArgStrings(), ", "),
	)
	return nil
}

// WebhookHandler POSTs a JSON payload to a URL for each violation.
type WebhookHandler struct {
	URL    string
	Client *http.Client
}

type webhookPayload struct {
	Policy string   `json:"policy"`
	Args   []string `json:"args"`
}

func (h *WebhookHandler) Handle(ctx context.Context, v Violation) error {
	payload := webhookPayload{
		Policy: v.Policy,
		Args:   v.ArgStrings(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// DryRunCollector accumulates violations without taking action.
// Call Summary() after Evaluate() to inspect results.
type DryRunCollector struct {
	violations []Violation
}

func (c *DryRunCollector) Handle(_ context.Context, v Violation) error {
	c.violations = append(c.violations, v)
	return nil
}

// Violations returns all collected violations.
func (c *DryRunCollector) Violations() []Violation {
	return c.violations
}

// PrintSummary writes a human-readable report to stdout.
func (c *DryRunCollector) PrintSummary() {
	if len(c.violations) == 0 {
		fmt.Println("No policy violations found.")
		return
	}
	fmt.Printf("Policy violations (%d):\n", len(c.violations))
	for _, v := range c.violations {
		fmt.Printf("  [%s] %s\n", v.Policy, strings.Join(v.ArgStrings(), ", "))
	}
}
