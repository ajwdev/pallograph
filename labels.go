package main

import (
	"github.com/google/mangle/ast"
	"github.com/google/mangle/factstore"
)

// extractLabelsAndSelectors inserts EDB facts into the store for the labels
// on an object and any label selector it declares under .spec.selector.
//
// Labels become object_label/6 facts; selectors become selector_match_label/6
// or selector_expr_{in,notin,exists,notexists} facts depending on their type.
//
// Objects with a flat .spec.selector map (Services) are treated as matchLabels.
//
// Returns the number of facts inserted.
func extractLabelsAndSelectors(store factstore.SimpleInMemoryStore, apiVersion, kind, namespace, name string, obj map[string]any) int {
	count := 0
	owner := []ast.BaseTerm{
		ast.String(apiVersion), ast.String(kind),
		ast.String(namespace), ast.String(name),
	}

	// metadata.labels → object_label/6
	if metadata, ok := obj["metadata"].(map[string]any); ok {
		if labels, ok := metadata["labels"].(map[string]any); ok {
			for k, v := range labels {
				if vStr, ok := v.(string); ok {
					store.Add(ast.Atom{
						Predicate: ast.PredicateSym{Symbol: "object_label", Arity: 6},
						Args:      append(owner, ast.String(k), ast.String(vStr)),
					})
					count++
				}
			}
		}
	}

	// .spec.selector
	spec, _ := obj["spec"].(map[string]any)
	if spec == nil {
		return count
	}
	selector, _ := spec["selector"].(map[string]any)
	if selector == nil {
		return count
	}

	matchLabels, hasMatchLabels := selector["matchLabels"].(map[string]any)
	matchExprs, hasMatchExprs := selector["matchExpressions"].([]any)

	// matchLabels → selector_match_label/6
	for k, v := range matchLabels {
		if vStr, ok := v.(string); ok {
			store.Add(ast.Atom{
				Predicate: ast.PredicateSym{Symbol: "selector_match_label", Arity: 6},
				Args:      append(owner, ast.String(k), ast.String(vStr)),
			})
			count++
		}
	}

	// matchExpressions → selector_expr_{in,notin,exists,notexists}
	for _, e := range matchExprs {
		expr, ok := e.(map[string]any)
		if !ok {
			continue
		}
		key, _ := expr["key"].(string)
		operator, _ := expr["operator"].(string)
		values, _ := expr["values"].([]any)

		switch operator {
		case "In":
			for _, v := range values {
				if vStr, ok := v.(string); ok {
					store.Add(ast.Atom{
						Predicate: ast.PredicateSym{Symbol: "selector_expr_in", Arity: 6},
						Args:      append(owner, ast.String(key), ast.String(vStr)),
					})
					count++
				}
			}
		case "NotIn":
			for _, v := range values {
				if vStr, ok := v.(string); ok {
					store.Add(ast.Atom{
						Predicate: ast.PredicateSym{Symbol: "selector_expr_notin", Arity: 6},
						Args:      append(owner, ast.String(key), ast.String(vStr)),
					})
					count++
				}
			}
		case "Exists":
			store.Add(ast.Atom{
				Predicate: ast.PredicateSym{Symbol: "selector_expr_exists", Arity: 5},
				Args:      append(owner, ast.String(key)),
			})
			count++
		case "DoesNotExist":
			store.Add(ast.Atom{
				Predicate: ast.PredicateSym{Symbol: "selector_expr_notexists", Arity: 5},
				Args:      append(owner, ast.String(key)),
			})
			count++
		}
	}

	// Flat .spec.selector (Service style) → treat as matchLabels.
	// Only applies when neither matchLabels nor matchExpressions were present.
	if !hasMatchLabels && !hasMatchExprs {
		for k, v := range selector {
			if vStr, ok := v.(string); ok {
				store.Add(ast.Atom{
					Predicate: ast.PredicateSym{Symbol: "selector_match_label", Arity: 6},
					Args:      append(owner, ast.String(k), ast.String(vStr)),
				})
				count++
			}
		}
	}

	return count
}
