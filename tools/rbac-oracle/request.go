package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// Request is one authorization question, one line of requests.ndjson.
// A non-empty Path makes it a non-resource request, and the resource
// fields are then ignored.
type Request struct {
	ID          int      `json:"id"`
	User        string   `json:"user"`
	Groups      []string `json:"groups"`
	Namespace   string   `json:"namespace"`
	APIGroup    string   `json:"apiGroup"`
	Resource    string   `json:"resource"`
	Subresource string   `json:"subresource"`
	Name        string   `json:"name"`
	Verb        string   `json:"verb"`
	Path        string   `json:"path"`
}

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
			return nil, err
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
