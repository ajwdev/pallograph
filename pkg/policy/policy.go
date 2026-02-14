package policy

import (
	"context"
	"fmt"

	"github.com/google/mangle/analysis"
	"github.com/google/mangle/ast"
	mangleengine "github.com/google/mangle/engine"
	"github.com/google/mangle/factstore"
	"github.com/google/mangle/parse"
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

type policyEntry struct {
	// query is the atom used for GetFacts. Constants in the query act as filters;
	// variables match anything. Produced by ast.NewQuery for Register, or parsed
	// from a query string for RegisterQuery.
	query    ast.Atom
	handlers []Handler
}

// Engine evaluates registered policy predicates and dispatches violations to handlers.
//
// Rules are analyzed once at construction time. On each Evaluate call, a fresh
// derived-fact overlay is computed from the current base store and discarded
// afterward — making it safe to mutate the store between calls (e.g. from a
// controller reconcile loop).
type Engine struct {
	// Store is the base fact store. Callers add and remove facts here directly.
	Store       factstore.SimpleInMemoryStore
	programInfo *analysis.ProgramInfo
	policies    map[string]policyEntry
}

// New compiles ruleUnits into a ProgramInfo and returns an Engine ready to evaluate.
func New(store factstore.SimpleInMemoryStore, ruleUnits []parse.SourceUnit, knownPredicates map[ast.PredicateSym]ast.Decl) (*Engine, error) {
	programInfo, err := analysis.AnalyzeAndCheckBounds(ruleUnits, knownPredicates, analysis.ErrorForBoundsMismatch)
	if err != nil {
		return nil, fmt.Errorf("policy engine: analyze rules: %w", err)
	}
	return &Engine{
		Store:       store,
		programInfo: programInfo,
		policies:    make(map[string]policyEntry),
	}, nil
}

// Register fires handlers for every match of the named predicate.
// The predicate must be defined in the rules passed to New.
func (e *Engine) Register(predicate string, handlers ...Handler) error {
	sym, err := e.lookupPredicate(predicate)
	if err != nil {
		return err
	}
	return e.addEntry(predicate, ast.NewQuery(sym), handlers)
}

// RegisterQuery fires handlers only for matches of the given Datalog query string.
// Constants in the query act as filters; variables (or _) match anything.
// Example: `orphaned_sa("kube-system", _)`
func (e *Engine) RegisterQuery(query string, handlers ...Handler) error {
	atom, err := parse.Atom(query)
	if err != nil {
		return fmt.Errorf("RegisterQuery: parse %q: %w", query, err)
	}
	if _, err := e.lookupPredicate(atom.Predicate.Symbol); err != nil {
		return err
	}
	// Use the predicate symbol as the map key, but with the query string appended
	// so multiple RegisterQuery calls for the same predicate can coexist.
	key := fmt.Sprintf("%s|%s", atom.Predicate.Symbol, query)
	return e.addEntry(key, atom, handlers)
}

func (e *Engine) addEntry(key string, query ast.Atom, handlers []Handler) error {
	entry := e.policies[key]
	entry.query = query
	entry.handlers = append(entry.handlers, handlers...)
	e.policies[key] = entry
	return nil
}

// lookupPredicate finds the PredicateSym (including arity) for a predicate name
// from the analyzed program info, so callers don't have to supply arity manually.
func (e *Engine) lookupPredicate(predicate string) (ast.PredicateSym, error) {
	for sym := range e.programInfo.IdbPredicates {
		if sym.Symbol == predicate {
			return sym, nil
		}
	}
	return ast.PredicateSym{}, fmt.Errorf("predicate %q not found in rules (must be an IDB predicate)", predicate)
}

// Evaluate derives all facts from the current base store, then queries each
// registered policy predicate and fires handlers for every match.
//
// Derived facts are written to an ephemeral overlay that is discarded after
// this call, so the base store remains unmodified.
func (e *Engine) Evaluate(ctx context.Context) error {
	// Overlay for derived facts; base store is read-only from the engine's perspective.
	evalStore := factstore.NewTeeingStore(e.Store)

	if err := mangleengine.EvalProgram(e.programInfo, evalStore); err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	for _, entry := range e.policies {
		if err := e.fireHandlers(ctx, evalStore, entry); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) fireHandlers(ctx context.Context, store factstore.FactStore, entry policyEntry) error {
	predicate := entry.query.Predicate.Symbol
	return store.GetFacts(entry.query, func(atom ast.Atom) error {
		v := Violation{Policy: predicate, Args: atom.Args}
		for _, h := range entry.handlers {
			if err := h.Handle(ctx, v); err != nil {
				return fmt.Errorf("predicate %q handler: %w", predicate, err)
			}
		}
		return nil
	})
}
