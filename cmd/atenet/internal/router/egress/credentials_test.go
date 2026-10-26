// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/agent-substrate/substrate/cmd/atenet/internal/router/extproc"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/agent-substrate/substrate/pkg/proto/credproviderpb"
)

const injectionProviderName = "k8s"

type fakeProvider struct {
	resp *credproviderpb.FetchSecretResponse
	err  error
	got  *credproviderpb.FetchSecretRequest
}

func (f *fakeProvider) FetchSecret(_ context.Context, req *credproviderpb.FetchSecretRequest, _ ...grpc.CallOption) (*credproviderpb.FetchSecretResponse, error) {
	f.got = req
	return f.resp, f.err
}

func bearerTokenResponse(token string) *credproviderpb.FetchSecretResponse {
	return &credproviderpb.FetchSecretResponse{OpaqueBytes: []byte(token)}
}

func injectionHandlerFor(policy *ateapipb.EgressPolicy, provider credproviderpb.CredentialProviderClient, providerName string) *Handler {
	return New(&egressMockClient{actor: runningActor(), policy: policy}, nil, 0, provider, providerName)
}

func withAuthorization(md *extproc.RequestMetadata) *extproc.RequestMetadata {
	md.Headers["authorization"] = "Bearer placeholder"
	return md
}

func TestInjectionOnRequestLegs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		leg    string
		policy *ateapipb.EgressPolicy
	}{
		{name: "https", leg: extproc.EgressTLSMITMFilterChainName, policy: credentialInjectionPolicySample("api.example.com")},
		{name: "http", leg: extproc.EgressCleartextFilterChainName, policy: cleartextInjectionPolicy("api.example.com")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &fakeProvider{resp: bearerTokenResponse("s3cr3t\n")}
			h := injectionHandlerFor(tc.policy, provider, injectionProviderName)

			res, err := h.HandleRequestHeaders(context.Background(),
				withAuthorization(innerMetadata(tc.leg, "GET", "api.example.com", nil)))
			if err != nil {
				t.Fatalf("HandleRequestHeaders: %v", err)
			}

			setHeaders := res.Response.GetResponse().GetHeaderMutation().GetSetHeaders()
			if len(setHeaders) != 1 {
				t.Fatalf("got %d header mutations, want 1", len(setHeaders))
			}
			h0 := setHeaders[0]
			if got := h0.GetHeader().GetKey(); got != "authorization" {
				t.Errorf("header key = %q, want authorization", got)
			}
			if got := string(h0.GetHeader().GetRawValue()); got != "Bearer s3cr3t" {
				t.Errorf("header value = %q, want %q (trailing newline trimmed)", got, "Bearer s3cr3t")
			}
			if h0.GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
				t.Errorf("append action = %v, want OVERWRITE_IF_EXISTS_OR_ADD", h0.GetAppendAction())
			}
			if got := provider.got.GetUri(); got != "ate-secret://k8s/default/token" {
				t.Errorf("provider URI = %q", got)
			}
			wantActorSPIFFEID := "spiffe://substrate-actor.local/actor/default/my-actor"
			if got := provider.got.GetActorSpiffeId(); got != wantActorSPIFFEID {
				t.Errorf("actor identity = %q, want %q", got, wantActorSPIFFEID)
			}
		})
	}
}

func TestInjectionSkippedWithoutHeader(t *testing.T) {
	jwtPolicy := &ateapipb.EgressPolicy{Rules: []*ateapipb.EgressRule{{Https: &ateapipb.HTTPSRule{
		Hostnames: []string{"api.example.com"},
		Effects: &ateapipb.HttpRuleEffects{ReplaceHeaders: []*ateapipb.CredentialHeader{{
			Header:   "authorization",
			ActorJwt: &ateapipb.ActorJWTSource{Audiences: []string{"https://api.example.com"}},
		}}},
	}}}}
	for _, tc := range []struct {
		name     string
		policy   *ateapipb.EgressPolicy
		provider *fakeProvider // nil means no provider configured
	}{
		{name: "provider configured", policy: credentialInjectionPolicySample("api.example.com"), provider: &fakeProvider{resp: bearerTokenResponse("s3cr3t")}},
		{name: "no provider configured", policy: credentialInjectionPolicySample("api.example.com")},
		{name: "actor JWT", policy: jwtPolicy, provider: &fakeProvider{resp: bearerTokenResponse("s3cr3t")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var provider credproviderpb.CredentialProviderClient
			if tc.provider != nil {
				provider = tc.provider
			}
			h := injectionHandlerFor(tc.policy, provider, injectionProviderName)
			res, err := h.HandleRequestHeaders(context.Background(),
				innerMetadata(extproc.EgressTLSMITMFilterChainName, "GET", "api.example.com", nil))
			if err != nil {
				t.Fatalf("HandleRequestHeaders: %v", err)
			}
			if got := res.Response.GetResponse().GetHeaderMutation().GetSetHeaders(); len(got) != 0 {
				t.Errorf("got %d injected headers, want 0", len(got))
			}
			if tc.provider != nil && tc.provider.got != nil {
				t.Errorf("provider was asked for %v, want no fetch", tc.provider.got)
			}
		})
	}
}

func TestInjectionReplacesOnlyCarriedHeaders(t *testing.T) {
	policy := &ateapipb.EgressPolicy{Rules: []*ateapipb.EgressRule{{Https: &ateapipb.HTTPSRule{
		Hostnames: []string{"api.example.com"},
		Effects: &ateapipb.HttpRuleEffects{ReplaceHeaders: []*ateapipb.CredentialHeader{
			{Header: "authorization", Prefix: "Bearer ", CredentialUri: "ate-secret://k8s/default/token"},
			{Header: "X-Api-Key", CredentialUri: "ate-secret://k8s/default/api-key"},
		}},
	}}}}
	provider := &fakeProvider{resp: bearerTokenResponse("s3cr3t")}
	h := injectionHandlerFor(policy, provider, injectionProviderName)
	md := innerMetadata(extproc.EgressTLSMITMFilterChainName, "GET", "api.example.com", nil)
	md.Headers["x-api-key"] = "placeholder"

	res, err := h.HandleRequestHeaders(context.Background(), md)
	if err != nil {
		t.Fatalf("HandleRequestHeaders: %v", err)
	}
	setHeaders := res.Response.GetResponse().GetHeaderMutation().GetSetHeaders()
	if len(setHeaders) != 1 {
		t.Fatalf("got %d header mutations, want only the carried X-Api-Key", len(setHeaders))
	}
	if got := setHeaders[0].GetHeader().GetKey(); got != "X-Api-Key" {
		t.Errorf("header key = %q, want X-Api-Key", got)
	}
	if got := provider.got.GetUri(); got != "ate-secret://k8s/default/api-key" {
		t.Errorf("provider URI = %q, want the X-Api-Key credential", got)
	}
}

func TestInjectionDenials(t *testing.T) {
	tests := []struct {
		name         string
		provider     credproviderpb.CredentialProviderClient
		providerName string
		want         envoy_type.StatusCode
	}{
		{
			name:         "no provider configured is refused",
			providerName: injectionProviderName,
			want:         envoy_type.StatusCode_InternalServerError,
		},
		{
			name:         "credential URI for another provider is refused",
			provider:     &fakeProvider{resp: bearerTokenResponse("s3cr3t")},
			providerName: "vault",
			want:         envoy_type.StatusCode_InternalServerError,
		},
		{
			name:         "provider unavailable fails closed as retryable",
			provider:     &fakeProvider{err: status.Error(codes.Unavailable, "provider down")},
			providerName: injectionProviderName,
			want:         envoy_type.StatusCode_ServiceUnavailable,
		},
		{
			name:         "secret not found denies as non-retryable",
			provider:     &fakeProvider{err: status.Error(codes.NotFound, "no such secret")},
			providerName: injectionProviderName,
			want:         envoy_type.StatusCode_Forbidden,
		},
		{
			name:         "provider refuses the actor denies as non-retryable",
			provider:     &fakeProvider{err: status.Error(codes.PermissionDenied, "atespace not allowed")},
			providerName: injectionProviderName,
			want:         envoy_type.StatusCode_Forbidden,
		},
		{
			name:         "unexpected provider error denies",
			provider:     &fakeProvider{err: errors.New("provider down")},
			providerName: injectionProviderName,
			want:         envoy_type.StatusCode_Forbidden,
		},
		{
			name:         "empty secret fails closed",
			provider:     &fakeProvider{resp: bearerTokenResponse("")},
			providerName: injectionProviderName,
			want:         envoy_type.StatusCode_ServiceUnavailable,
		},
	}
	for _, leg := range []string{extproc.EgressTLSMITMFilterChainName, extproc.EgressCleartextFilterChainName} {
		t.Run(leg, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					policy := credentialInjectionPolicySample("api.example.com")
					if leg == extproc.EgressCleartextFilterChainName {
						policy = cleartextInjectionPolicy("api.example.com")
					}
					h := injectionHandlerFor(policy, tc.provider, tc.providerName)
					_, err := h.HandleRequestHeaders(context.Background(),
						withAuthorization(innerMetadata(leg, "GET", "api.example.com", nil)))
					wantStatus(t, err, tc.want)
				})
			}
		})
	}
}

type jwtControlClient struct {
	*egressMockClient
	requests []*ateapipb.MintActorJWTRequest
	tokens   []string
	err      error
	wait     bool
	deadline time.Time
}

func (c *jwtControlClient) MintActorJWT(ctx context.Context, req *ateapipb.MintActorJWTRequest, _ ...grpc.CallOption) (*ateapipb.MintActorJWTResponse, error) {
	c.requests = append(c.requests, req)
	c.deadline, _ = ctx.Deadline()
	if c.wait {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	if c.err != nil {
		return nil, c.err
	}
	if c.tokens == nil {
		return &ateapipb.MintActorJWTResponse{ActorJwt: c.actor.GetMetadata().GetUid() + "-jwt"}, nil
	}
	return &ateapipb.MintActorJWTResponse{ActorJwt: c.tokens[len(c.requests)-1]}, nil
}

func jwtInjectionPolicy(leg string, audiences []string) *ateapipb.EgressPolicy {
	effects := &ateapipb.HttpRuleEffects{ReplaceHeaders: []*ateapipb.CredentialHeader{{
		Header: "authorization", ActorJwt: &ateapipb.ActorJWTSource{Audiences: audiences, ExpirationSeconds: 900},
	}}}
	if leg == extproc.EgressCleartextFilterChainName {
		return &ateapipb.EgressPolicy{Rules: []*ateapipb.EgressRule{{Http: &ateapipb.HTTPRule{Hostnames: []string{"api.example.com"}, Effects: effects}}}}
	}
	return &ateapipb.EgressPolicy{Rules: []*ateapipb.EgressRule{{Https: &ateapipb.HTTPSRule{Hostnames: []string{"api.example.com"}, Effects: effects}}}}
}

func TestActorJWTInjection(t *testing.T) {
	maxAudiences := make([]string, 16)
	for i := range maxAudiences {
		maxAudiences[i] = fmt.Sprintf("https://api-%d.example.com", i)
	}
	for _, leg := range []string{extproc.EgressTLSMITMFilterChainName, extproc.EgressCleartextFilterChainName} {
		for _, audiences := range [][]string{{"https://api.example.com"}, {"https://api.example.com", "https://other.example.com"}, maxAudiences} {
			actor := runningActor()
			actor.Metadata.Uid = "old-uid"
			client := &jwtControlClient{egressMockClient: &egressMockClient{actor: actor, policy: jwtInjectionPolicy(leg, audiences)}}
			h := New(client, nil, 0, nil, "")
			md := withAuthorization(innerMetadata(leg, "GET", "api.example.com", nil))
			for i, want := range []string{"Bearer old-uid-jwt", "Bearer new-uid-jwt"} {
				if i == 1 {
					client.actor.Metadata.Uid = "new-uid"
				}
				res, err := h.HandleRequestHeaders(context.Background(), md)
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				got := res.Response.GetResponse().GetHeaderMutation().GetSetHeaders()
				if len(got) != 1 || got[0].GetHeader().GetKey() != "authorization" || string(got[0].GetHeader().GetRawValue()) != want || got[0].GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
					t.Fatalf("request %d mutation = %v, want authorization %q with overwrite", i, got, want)
				}
			}
			if len(client.requests) != 2 {
				t.Fatalf("mint calls = %d, want 2 after same-name Actor recreation", len(client.requests))
			}
			for _, req := range client.requests {
				if req.GetActor().GetAtespace() != "default" || req.GetActor().GetName() != "my-actor" || req.GetExpirationSeconds() != 900 || !slices.Equal(req.GetAudience(), audiences) {
					t.Fatalf("mint request = %v, want actor default/my-actor, audiences %v, expiry 900", req, audiences)
				}
			}
			if client.deadline.IsZero() || time.Until(client.deadline) > 4*time.Second {
				t.Fatalf("mint deadline = %v, want within four seconds", client.deadline)
			}
		}
	}
}

func TestActorJWTAbsentHeaderDoesNotMint(t *testing.T) {
	client := &jwtControlClient{egressMockClient: &egressMockClient{actor: runningActor(), policy: jwtInjectionPolicy(extproc.EgressTLSMITMFilterChainName, []string{"https://api.example.com"})}}
	h := New(client, nil, 0, nil, "")
	res, err := h.HandleRequestHeaders(context.Background(), innerMetadata(extproc.EgressTLSMITMFilterChainName, "GET", "api.example.com", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 0 || len(res.Response.GetResponse().GetHeaderMutation().GetSetHeaders()) != 0 {
		t.Fatalf("absent header minted %d times or mutated headers", len(client.requests))
	}
}

func TestActorJWTMintFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		token     string
		audiences []string
		want      envoy_type.StatusCode
		calls     int
	}{
		{"not found", status.Error(codes.NotFound, "missing"), "", []string{"https://api.example.com"}, envoy_type.StatusCode_Forbidden, 1},
		{"permission denied", status.Error(codes.PermissionDenied, "denied"), "", []string{"https://api.example.com"}, envoy_type.StatusCode_Forbidden, 1},
		{"unavailable", status.Error(codes.Unavailable, "down"), "", []string{"https://api.example.com"}, envoy_type.StatusCode_ServiceUnavailable, 1},
		{"deadline", status.Error(codes.DeadlineExceeded, "late"), "", []string{"https://api.example.com"}, envoy_type.StatusCode_ServiceUnavailable, 1},
		{"raw deadline", context.DeadlineExceeded, "", []string{"https://api.example.com"}, envoy_type.StatusCode_ServiceUnavailable, 1},
		{"unexpected", errors.New("mint broke"), "", []string{"https://api.example.com"}, envoy_type.StatusCode_InternalServerError, 1},
		{"empty token", nil, "", []string{"https://api.example.com"}, envoy_type.StatusCode_InternalServerError, 1},
		{"bad token", nil, "secret\nvalue", []string{"https://api.example.com"}, envoy_type.StatusCode_InternalServerError, 1},
		{"no audience", nil, "", nil, envoy_type.StatusCode_InternalServerError, 0},
		{"duplicate audience", nil, "", []string{"same", "same"}, envoy_type.StatusCode_InternalServerError, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &jwtControlClient{egressMockClient: &egressMockClient{actor: runningActor(), policy: jwtInjectionPolicy(extproc.EgressTLSMITMFilterChainName, tc.audiences)}, tokens: []string{tc.token}, err: tc.err}
			h := New(client, nil, 0, nil, "")
			var logs bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(old)
			_, err := h.HandleRequestHeaders(context.Background(), withAuthorization(innerMetadata(extproc.EgressTLSMITMFilterChainName, "GET", "api.example.com", nil)))
			wantStatus(t, err, tc.want)
			if len(client.requests) != tc.calls {
				t.Errorf("mint calls = %d, want %d", len(client.requests), tc.calls)
			}
			if strings.Contains(logs.String(), "secret\nvalue") || strings.Contains(logs.String(), "Bearer placeholder") || strings.Contains(logs.String(), "mint broke") {
				t.Errorf("credential or backend text leaked into logs: %q", logs.String())
			}
		})
	}
}

func TestActorJWTTooManyAudiences(t *testing.T) {
	audiences := make([]string, 17)
	for i := range audiences {
		audiences[i] = fmt.Sprintf("https://api-%d.example.com", i)
	}
	client := &jwtControlClient{egressMockClient: &egressMockClient{actor: runningActor(), policy: jwtInjectionPolicy(extproc.EgressTLSMITMFilterChainName, audiences)}}
	h := New(client, nil, 0, nil, "")
	_, err := h.HandleRequestHeaders(context.Background(), withAuthorization(innerMetadata(extproc.EgressTLSMITMFilterChainName, "GET", "api.example.com", nil)))
	wantStatus(t, err, envoy_type.StatusCode_InternalServerError)
	if len(client.requests) != 0 {
		t.Fatalf("mint calls = %d, want none for invalid policy", len(client.requests))
	}
}

func TestActorJWTMintCancellation(t *testing.T) {
	client := &jwtControlClient{egressMockClient: &egressMockClient{actor: runningActor(), policy: jwtInjectionPolicy(extproc.EgressTLSMITMFilterChainName, []string{"https://api.example.com"})}, wait: true}
	h := New(client, nil, 0, nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := h.HandleRequestHeaders(ctx, withAuthorization(innerMetadata(extproc.EgressTLSMITMFilterChainName, "GET", "api.example.com", nil)))
	wantStatus(t, err, envoy_type.StatusCode_RequestTimeout)
	if len(client.requests) != 1 {
		t.Fatalf("mint calls = %d, want 1", len(client.requests))
	}
}

func TestActorJWTMintTimeout(t *testing.T) {
	client := &jwtControlClient{egressMockClient: &egressMockClient{actor: runningActor(), policy: jwtInjectionPolicy(extproc.EgressTLSMITMFilterChainName, []string{"https://api.example.com"})}, wait: true}
	h := New(client, nil, 0, nil, "")
	_, err := h.HandleRequestHeaders(context.Background(), withAuthorization(innerMetadata(extproc.EgressTLSMITMFilterChainName, "GET", "api.example.com", nil)))
	wantStatus(t, err, envoy_type.StatusCode_ServiceUnavailable)
	if len(client.requests) != 1 {
		t.Fatalf("mint calls = %d, want 1", len(client.requests))
	}
}
