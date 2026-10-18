// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secretstest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// AWS is a fake AWS Secrets Manager: the AWS JSON 1.1 protocol's
// GetSecretValue and ListSecrets, with name-prefix, tag-key and tag-value
// filters (prefix matches, values ORed, filters ANDed, as the service
// documents) and pages of PageSize. It does not check request signatures,
// but it records the access key id each request was signed with.
type AWS struct {
	*httptest.Server
	// PageSize is the number of secrets per ListSecrets page.
	PageSize int

	mu      sync.Mutex
	secrets []awsSecret
	// AccessKeys are the access key ids of the requests' signatures.
	AccessKeys []string
	// Lists counts the ListSecrets calls.
	Lists int
	// ListError, when set, is the error code every ListSecrets call
	// answers with, such as AccessDeniedException (which the SDK does not
	// retry).
	ListError string
}

type awsSecret struct {
	name   string
	value  *string
	binary []byte
	tags   map[string]string
}

// NewAWS starts a fake Secrets Manager and stops it when t ends.
func NewAWS(t testing.TB) *AWS {
	t.Helper()
	a := &AWS{PageSize: 2}
	a.Server = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.Close)
	return a
}

// Put stores a string secret with tags, replacing one of the same name.
func (a *AWS) Put(name, value string, tags map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.secrets = slices.DeleteFunc(a.secrets, func(s awsSecret) bool { return s.name == name })
	a.secrets = append(a.secrets, awsSecret{name: name, value: &value, tags: tags})
}

// Delete removes a secret.
func (a *AWS) Delete(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.secrets = slices.DeleteFunc(a.secrets, func(s awsSecret) bool { return s.name == name })
}

// SetListError sets ListError.
func (a *AWS) SetListError(code string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ListError = code
}

// PutBinary stores a binary secret.
func (a *AWS) PutBinary(name string, value []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.secrets = append(a.secrets, awsSecret{name: name, binary: value})
}

type awsFilter struct {
	Key    string
	Values []string
}

func (a *AWS) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if auth := r.Header.Get("Authorization"); strings.Contains(auth, "Credential=") {
		cred := strings.SplitN(strings.SplitN(auth, "Credential=", 2)[1], "/", 2)[0]
		a.AccessKeys = append(a.AccessKeys, cred)
	}
	var req struct {
		SecretID  string `json:"SecretId"`
		Filters   []awsFilter
		NextToken string
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		awsError(w, "SerializationException", "bad request body")
		return
	}
	switch r.Header.Get("X-Amz-Target") {
	case "secretsmanager.GetSecretValue":
		for _, s := range a.secrets {
			if s.name == req.SecretID {
				out := map[string]any{"ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:" + s.name,
					"Name": s.name, "VersionId": "v1", "VersionStages": []string{"AWSCURRENT"}}
				if s.value != nil {
					out["SecretString"] = *s.value
				} else {
					out["SecretBinary"] = s.binary
				}
				awsJSON(w, http.StatusOK, out)
				return
			}
		}
		awsError(w, "ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
	case "secretsmanager.ListSecrets":
		a.Lists++
		if a.ListError != "" {
			awsError(w, a.ListError, "the fake refuses ListSecrets")
			return
		}
		var match []awsSecret
		for _, s := range a.secrets {
			if awsMatches(s, req.Filters) {
				match = append(match, s)
			}
		}
		start := 0
		if req.NextToken != "" {
			start = slices.IndexFunc(match, func(s awsSecret) bool { return s.name == req.NextToken })
		}
		end := min(len(match), start+a.PageSize)
		var list []map[string]any
		for _, s := range match[start:end] {
			var tags []map[string]string
			for k, v := range s.tags {
				tags = append(tags, map[string]string{"Key": k, "Value": v})
			}
			list = append(list, map[string]any{"Name": s.name, "Tags": tags})
		}
		out := map[string]any{"SecretList": list}
		if end < len(match) {
			out["NextToken"] = match[end].name
		}
		awsJSON(w, http.StatusOK, out)
	default:
		awsError(w, "UnknownOperationException", "unsupported")
	}
}

func awsMatches(s awsSecret, filters []awsFilter) bool {
	for _, f := range filters {
		ok := false
		for _, v := range f.Values {
			switch f.Key {
			case "name":
				ok = ok || strings.HasPrefix(s.name, v)
			case "tag-key":
				for k := range s.tags {
					ok = ok || strings.HasPrefix(k, v)
				}
			case "tag-value":
				for _, tv := range s.tags {
					ok = ok || strings.HasPrefix(tv, v)
				}
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func awsJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func awsError(w http.ResponseWriter, code, msg string) {
	w.Header().Set("X-Amzn-ErrorType", code)
	awsJSON(w, http.StatusBadRequest, map[string]string{"__type": code, "message": msg})
}
