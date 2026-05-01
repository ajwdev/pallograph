package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ajwdev/pallograph/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorHandler always returns an error, for testing error propagation.
type errorHandler struct{ err error }

func (h *errorHandler) Handle(_ context.Context, _ policy.Violation) error { return h.err }

func TestEvaluate_MultipleHandlersFire(t *testing.T) {
	store := makeStore(strAtom("person", "alice", "New York"))
	rules := parseRules(t, `resident(Name) :- person(Name, "New York").`)
	engine, err := policy.New(store, rules, knownPred("person", 2))
	require.NoError(t, err)

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
	require.NoError(t, err)

	sentinel := errors.New("handler failed")
	assert.NoError(t, engine.Register("resident", &errorHandler{sentinel}))

	err = engine.Evaluate(context.Background())
	assert.ErrorIs(t, err, sentinel)
}
