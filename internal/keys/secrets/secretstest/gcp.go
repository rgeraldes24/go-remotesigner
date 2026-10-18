// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package secretstest

import (
	"context"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GCP is a fake GCP Secret Manager: the generated gRPC service of the SDK,
// with ListSecrets (pages of PageSize; a filter of labels.<key>=<value>
// terms joined by AND, or empty) and AccessSecretVersion of
// versions/latest. Endpoint is its address as an http:// override, which
// the client reaches without TLS or credentials.
type GCP struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
	Endpoint string
	PageSize int

	mu      sync.Mutex
	secrets []gcpSecret
	// Filters records the filter of each ListSecrets call.
	Filters []string
}

type gcpSecret struct {
	name    string // full resource name
	payload []byte // nil: no version
	labels  map[string]string
}

// NewGCP starts a fake Secret Manager and stops it when t ends.
func NewGCP(t testing.TB) *GCP {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &GCP{Endpoint: "http://" + l.Addr().String(), PageSize: 2}
	srv := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(srv, g)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return g
}

// Put stores a secret of project with one version holding payload (nil:
// no version) and labels.
func (g *GCP) Put(project, name string, payload []byte, labels map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.secrets = append(g.secrets, gcpSecret{name: "projects/" + project + "/secrets/" + name, payload: payload, labels: labels})
}

// ListSecrets implements the service.
func (g *GCP) ListSecrets(_ context.Context, req *secretmanagerpb.ListSecretsRequest) (*secretmanagerpb.ListSecretsResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Filters = append(g.Filters, req.GetFilter())
	want := map[string]string{}
	if f := req.GetFilter(); f != "" {
		for _, term := range strings.Split(f, " AND ") {
			k, v, ok := strings.Cut(strings.TrimPrefix(term, "labels."), "=")
			if !ok || !strings.HasPrefix(term, "labels.") {
				return nil, status.Errorf(codes.InvalidArgument, "the fake supports labels.<key>=<value> filters only")
			}
			want[k] = v
		}
	}
	var match []*secretmanagerpb.Secret
	for _, s := range g.secrets {
		if !strings.HasPrefix(s.name, req.GetParent()+"/secrets/") {
			continue
		}
		ok := true
		for k, v := range want {
			ok = ok && s.labels[k] == v
		}
		if ok {
			match = append(match, &secretmanagerpb.Secret{Name: s.name, Labels: s.labels})
		}
	}
	start := 0
	if tok := req.GetPageToken(); tok != "" {
		start, _ = strconv.Atoi(tok)
	}
	end := min(len(match), start+g.PageSize)
	resp := &secretmanagerpb.ListSecretsResponse{Secrets: match[start:end], TotalSize: int32(len(match))}
	if end < len(match) {
		resp.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

// AccessSecretVersion implements the service.
func (g *GCP) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (
	*secretmanagerpb.AccessSecretVersionResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	name, ok := strings.CutSuffix(req.GetName(), "/versions/latest")
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "the fake serves versions/latest only")
	}
	i := slices.IndexFunc(g.secrets, func(s gcpSecret) bool { return s.name == name })
	if i < 0 {
		return nil, status.Errorf(codes.NotFound, "Secret [%s] not found or has no versions.", name)
	}
	if g.secrets[i].payload == nil {
		return nil, status.Errorf(codes.NotFound, "Secret Version [%s/versions/latest] not found.", name)
	}
	return &secretmanagerpb.AccessSecretVersionResponse{Name: name + "/versions/1",
		Payload: &secretmanagerpb.SecretPayload{Data: slices.Clone(g.secrets[i].payload)}}, nil
}
