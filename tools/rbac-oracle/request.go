package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// Request is one question, one line of requests.ndjson. Kind says which:
//
//   - "" (accessKind): an authorization request, decided by the RBAC
//     authorizer alone. A non-empty Path makes it a non-resource request,
//     and the resource fields are then ignored.
//   - "impersonate": may User impersonate the identity named by Resource
//     (users, groups or serviceaccounts), Name and, for a ServiceAccount,
//     Namespace? Decided by the API server's impersonation filter (see
//     impersonation.go).
//   - "write": may User create or update (Verb) the RBAC object of type
//     Resource named Name in Namespace? A binding write carries the
//     binding's RoleRef, a role write the role's Rules. Decided by the
//     authorizer and the RBAC registry's escalation checks (see
//     rbacwrite.go).
type Request struct {
	ID          int      `json:"id"`
	Kind        string   `json:"kind,omitempty"`
	User        string   `json:"user"`
	Groups      []string `json:"groups"`
	Namespace   string   `json:"namespace"`
	APIGroup    string   `json:"apiGroup"`
	Resource    string   `json:"resource"`
	Subresource string   `json:"subresource"`
	Name        string   `json:"name"`
	Verb        string   `json:"verb"`
	Path        string   `json:"path"`

	RoleRef *rbacv1.RoleRef     `json:"roleRef,omitempty"`
	Rules   []rbacv1.PolicyRule `json:"rules,omitempty"`
}

// The request kinds; see Request.
const (
	accessKind      = ""
	impersonateKind = "impersonate"
	writeKind       = "write"
)

// Decision is one line of oracle.ndjson.
type Decision struct {
	ID      int      `json:"id"`
	Allowed bool     `json:"allowed"`
	Reason  string   `json:"reason,omitempty"`
	Tags    []string `json:"tags"`
}

func (r *Request) attributes() authorizer.AttributesRecord {
	attributes := authorizer.AttributesRecord{
		User:      &user.DefaultInfo{Name: r.User, Groups: r.Groups},
		Verb:      r.Verb,
		Namespace: r.Namespace,
	}
	if r.Path != "" {
		attributes.Path = r.Path
		return attributes
	}
	attributes.ResourceRequest = true
	attributes.APIGroup = r.APIGroup
	attributes.Resource = r.Resource
	attributes.Subresource = r.Subresource
	attributes.Name = r.Name
	return attributes
}

// authenticatedGroups returns the groups the authenticator attaches to a
// username: service accounts get their namespace and global SA groups,
// everyone except system:anonymous is system:authenticated.
func authenticatedGroups(username string, extra ...string) []string {
	if username == user.Anonymous {
		return []string{user.AllUnauthenticated}
	}
	groups := append([]string{}, extra...)
	if namespace, _, ok := splitServiceAccount(username); ok {
		groups = append(groups, "system:serviceaccounts", "system:serviceaccounts:"+namespace)
	}
	return append(groups, user.AllAuthenticated)
}

func splitServiceAccount(username string) (namespace, name string, ok bool) {
	rest, found := strings.CutPrefix(username, "system:serviceaccount:")
	if !found {
		return "", "", false
	}
	namespace, name, ok = strings.Cut(rest, ":")
	return namespace, name, ok
}

// The files a world's requests and the oracle's decisions are written to,
// as NDJSON. They are generated (hack/rbac-compat-gen.sh), never committed.
const (
	requestsFile = "requests.ndjson"
	oracleFile   = "oracle.ndjson"
)

func readRequests(path string) ([]Request, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var requests []Request
	decoder := json.NewDecoder(bufio.NewReader(file))
	for {
		var request Request
		if err := decoder.Decode(&request); err == io.EOF {
			return requests, nil
		} else if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		requests = append(requests, request)
	}
}

// writeNDJSON writes each value as one JSON line.
func writeNDJSON[T any](path string, values []T) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)
	for i := range values {
		if err := encoder.Encode(&values[i]); err != nil {
			file.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
