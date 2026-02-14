package policy_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ajwdev/pallograph/pkg/policy"
	"github.com/google/mangle/ast"
	"github.com/google/mangle/factstore"
	"github.com/google/mangle/parse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// strAtom builds a fact atom from string arguments.
func strAtom(pred string, args ...string) ast.Atom {
	terms := make([]ast.BaseTerm, len(args))
	for i, a := range args {
		terms[i] = ast.String(a)
	}
	return ast.Atom{
		Predicate: ast.PredicateSym{Symbol: pred, Arity: len(args)},
		Args:      terms,
	}
}

// makeStore creates a store pre-populated with the given facts.
func makeStore(facts ...ast.Atom) factstore.SimpleInMemoryStore {
	store := factstore.NewSimpleInMemoryStore()
	for _, f := range facts {
		store.Add(f)
	}
	return store
}

// parseRules parses an inline Datalog rule string into a SourceUnit slice.
func parseRules(t *testing.T, src string) []parse.SourceUnit {
	t.Helper()
	unit, err := parse.Unit(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}
	return []parse.SourceUnit{unit}
}

// knownPred declares a single EDB predicate so rules can reference it.
func knownPred(sym string, arity int) map[ast.PredicateSym]ast.Decl {
	pred := ast.PredicateSym{Symbol: sym, Arity: arity}
	return map[ast.PredicateSym]ast.Decl{
		pred: {DeclaredAtom: ast.Atom{Predicate: pred}},
	}
}

// collectHandler accumulates violations for inspection in tests.
type collectHandler struct {
	violations []policy.Violation
}

func (h *collectHandler) Handle(_ context.Context, v policy.Violation) error {
	h.violations = append(h.violations, v)
	return nil
}

// errorHandler always returns an error, for testing error propagation.
type errorHandler struct{ err error }

func (h *errorHandler) Handle(_ context.Context, _ policy.Violation) error { return h.err }

// --- Tests ---

func TestNew_InvalidRules(t *testing.T) {
	store := makeStore()
	rules := parseRules(t, `bad_rule(X) :- unknown_pred(X).`)
	_, err := policy.New(store, rules, nil)
	assert.Error(t, err)
}

func TestRegister_UnknownPredicate(t *testing.T) {
	store := makeStore()
	rules := parseRules(t, `resident(Name) :- person(Name, "New York").`)
	engine, err := policy.New(store, rules, knownPred("person", 2))
	require.NoError(t, err) // engine would be nil, causing a panic below

	err = engine.Register("does_not_exist")
	assert.Error(t, err)
}

func TestEvaluate_FiresHandlerForEachMatch(t *testing.T) {
	store := makeStore(
		strAtom("person", "alice", "New York"),
		strAtom("person", "bob", "London"),
		strAtom("person", "charlie", "New York"),
	)
	rules := parseRules(t, `resident(Name) :- person(Name, "New York").`)
	engine, err := policy.New(store, rules, knownPred("person", 2))
	require.NoError(t, err) // engine would be nil, causing a panic below

	h := &collectHandler{}
	assert.NoError(t, engine.Register("resident", h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, h.violations, 2)
	for _, v := range h.violations {
		assert.Equal(t, "resident", v.Policy)
	}
}

func TestEvaluate_NoMatchesMeansNoHandlerCalls(t *testing.T) {
	// Only people outside New York — resident predicate should be empty.
	store := makeStore(
		strAtom("person", "bob", "London"),
		strAtom("person", "dave", "Paris"),
	)
	rules := parseRules(t, `resident(Name) :- person(Name, "New York").`)
	engine, err := policy.New(store, rules, knownPred("person", 2))
	require.NoError(t, err) // engine would be nil, causing a panic below

	h := &collectHandler{}
	assert.NoError(t, engine.Register("resident", h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Empty(t, h.violations)
}

func TestEvaluate_MultipleHandlersFire(t *testing.T) {
	store := makeStore(strAtom("person", "alice", "New York"))
	rules := parseRules(t, `resident(Name) :- person(Name, "New York").`)
	engine, err := policy.New(store, rules, knownPred("person", 2))
	require.NoError(t, err) // engine would be nil, causing a panic below

	h1, h2 := &collectHandler{}, &collectHandler{}
	assert.NoError(t, engine.Register("resident", h1, h2))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, h1.violations, 1)
	assert.Len(t, h2.violations, 1)
}

func TestEvaluate_HandlerErrorPropagates(t *testing.T) {
	store := makeStore(strAtom("person", "alice", "New York"))
	rules := parseRules(t, `resident(Name) :- person(Name, "New York").`)
	engine, err := policy.New(store, rules, knownPred("person", 2))
	require.NoError(t, err) // engine would be nil, causing a panic below

	sentinel := errors.New("handler failed")
	assert.NoError(t, engine.Register("resident", &errorHandler{sentinel}))

	err = engine.Evaluate(context.Background())
	assert.ErrorIs(t, err, sentinel)
}

func TestRegisterQuery_ConstantFiltersResults(t *testing.T) {
	store := makeStore(
		strAtom("person", "alice", "New York"),
		strAtom("person", "bob", "London"),
		strAtom("person", "charlie", "New York"),
	)
	rules := parseRules(t, `resident(Name, City) :- person(Name, City).`)
	engine, err := policy.New(store, rules, knownPred("person", 2))
	require.NoError(t, err) // engine would be nil, causing a panic below

	all := &collectHandler{}
	nyOnly := &collectHandler{}
	assert.NoError(t, engine.Register("resident", all))
	assert.NoError(t, engine.RegisterQuery(`resident(X0, "New York")`, nyOnly))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, all.violations, 3)
	assert.Len(t, nyOnly.violations, 2)
}

func TestRegisterQuery_InvalidPredicate(t *testing.T) {
	store := makeStore()
	rules := parseRules(t, `resident(Name) :- person(Name, "New York").`)
	engine, err := policy.New(store, rules, knownPred("person", 2))
	require.NoError(t, err) // engine would be nil, causing a panic below

	err = engine.RegisterQuery(`does_not_exist("foo")`, &collectHandler{})
	assert.Error(t, err)
}

func TestEvaluate_ReflectsStoreUpdates(t *testing.T) {
	// Start with one person, evaluate, then add another and re-evaluate.
	// Demonstrates the reconcile-loop pattern.
	store := makeStore(strAtom("person", "alice", "New York"))
	rules := parseRules(t, `resident(Name) :- person(Name, "New York").`)
	engine, err := policy.New(store, rules, knownPred("person", 2))
	require.NoError(t, err) // engine would be nil, causing a panic below

	h := &collectHandler{}
	assert.NoError(t, engine.Register("resident", h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Len(t, h.violations, 1)

	// Simulate a new object arriving via an informer.
	engine.Store.Add(strAtom("person", "charlie", "New York"))
	h.violations = nil

	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Len(t, h.violations, 2)
}
