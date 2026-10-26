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

package authz

import (
	"context"
	"slices"
	"testing"

	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/openfga/language/pkg/go/transformer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func TestRPCRegistryCoversServedMethods(t *testing.T) {
	served := make(map[string]bool)
	services := ateapipb.File_ateapi_proto.Services()
	for i := 0; i < services.Len(); i++ {
		service := services.Get(i)
		for j := 0; j < service.Methods().Len(); j++ {
			method := service.Methods().Get(j)
			full := "/" + string(service.FullName()) + "/" + string(method.Name())
			served[full] = true
			rule, ok := defaultRPCPermissions[full]
			if !ok {
				t.Errorf("served method %s has no rule", full)
				continue
			}
			if (rule.extract == nil) == (rule.authorizedInHandler == "") {
				t.Errorf("%s must have exactly one authorization path", full)
			}
		}
	}
	for method := range defaultRPCPermissions {
		if !served[method] {
			t.Errorf("rule %s has no served method", method)
		}
	}
}

func TestPortedModelCompiles(t *testing.T) {
	if _, err := transformer.TransformDSLToProto(modelDSL); err != nil {
		t.Fatalf("compile authorization model: %v", err)
	}
}

func TestPortedActorRules(t *testing.T) {
	actor := &ateapipb.ObjectRef{Atespace: "team-a", Name: "one"}
	for _, tc := range []struct {
		method   string
		req      any
		relation string
	}{
		{ateapipb.Control_PauseActor_FullMethodName, &ateapipb.PauseActorRequest{Actor: actor}, RelationCanSuspend},
		{ateapipb.Control_ResumeActor_FullMethodName, &ateapipb.ResumeActorRequest{Actor: actor}, RelationCanResume},
		{ateapipb.Control_MintActorJWT_FullMethodName, &ateapipb.MintActorJWTRequest{Actor: actor}, RelationCanMintActorJWT},
		{ateapipb.Control_MintActorCertificate_FullMethodName, &ateapipb.MintActorCertificateRequest{Actor: actor}, RelationCanMintActorCertificate},
		{ateapipb.Control_GetActorEgressPolicy_FullMethodName, &ateapipb.GetActorEgressPolicyRequest{Actor: actor}, RelationCanGetEgressPolicy},
	} {
		checks, err := defaultRPCPermissions[tc.method].extract(tc.req)
		if err != nil || !slices.Equal(checks, []check{{tc.relation, "actor:team-a/one"}}) {
			t.Errorf("%s checks = %v, error = %v", tc.method, checks, err)
		}
		if _, err := defaultRPCPermissions[tc.method].extract(&ateapipb.GetWorkerRequest{}); apierror.Code(err) != codes.Internal {
			t.Errorf("%s wrong type error = %v", tc.method, err)
		}
	}
	for _, tc := range []struct {
		method string
		req    any
	}{
		{ateapipb.Control_PauseActor_FullMethodName, &ateapipb.PauseActorRequest{}},
		{ateapipb.Control_MintActorJWT_FullMethodName, &ateapipb.MintActorJWTRequest{Actor: &ateapipb.ObjectRef{Atespace: "team-a", Name: "bad/name"}}},
		{ateapipb.Control_GetWorker_FullMethodName, &ateapipb.GetWorkerRequest{}},
		{ateapipb.Control_CreateTag_FullMethodName, &ateapipb.CreateTagRequest{}},
	} {
		if _, err := defaultRPCPermissions[tc.method].extract(tc.req); apierror.Code(err) != codes.InvalidArgument {
			t.Errorf("%s malformed request error = %v", tc.method, err)
		}
	}
}

func TestPortedTagAndWorkerRules(t *testing.T) {
	actor := &ateapipb.ObjectRef{Atespace: "team-a", Name: "one"}
	tag := &ateapipb.ObjectRef{Atespace: "shared", Name: "snapshot"}
	createTag := &ateapipb.CreateTagRequest{Tag: &ateapipb.Tag{
		Metadata:    &ateapipb.ResourceMetadata{Atespace: "team-a", Name: "snapshot"},
		SourceActor: actor,
	}}
	checks, err := defaultRPCPermissions[ateapipb.Control_CreateTag_FullMethodName].extract(createTag)
	want := []check{{RelationCanCreateTag, "atespace:team-a"}, {RelationCanGet, "actor:team-a/one"}}
	if err != nil || !slices.Equal(checks, want) {
		t.Errorf("CreateTag checks = %v, error = %v, want %v", checks, err, want)
	}
	createActor := &ateapipb.CreateActorRequest{Actor: &ateapipb.Actor{
		Metadata:      &ateapipb.ResourceMetadata{Atespace: "team-a", Name: "new"},
		ActorTemplate: &ateapipb.ObjectRef{Atespace: "team-a", Name: "template"},
		SourceTag:     tag,
	}}
	checks, err = defaultRPCPermissions[ateapipb.Control_CreateActor_FullMethodName].extract(createActor)
	want = []check{{RelationCanCreateActor, "atespace:team-a"}, {RelationCanUseTemplate, "actor_template:team-a/template"}}
	if err != nil || !slices.Equal(checks, want) {
		t.Errorf("CreateActor source tag checks = %v, error = %v, want %v", checks, err, want)
	}
	checks, err = defaultRPCPermissions[ateapipb.Control_ListWorkerActorAssignments_FullMethodName].extract(
		&ateapipb.ListWorkerActorAssignmentsRequest{Worker: &ateapipb.ObjectRef{Name: "worker-1"}})
	want = []check{{RelationCanListActorAssignments, "worker:worker-1"}}
	if err != nil || !slices.Equal(checks, want) {
		t.Errorf("ListWorkerActorAssignments checks = %v, error = %v, want %v", checks, err, want)
	}
}

type scopedChecker struct {
	calls []check
}

func (f *scopedChecker) Check(_ context.Context, relation, object string) error {
	f.calls = append(f.calls, check{relation, object})
	if object != "actor:team-a/one" {
		return apierror.PermissionDenied("unrelated actor")
	}
	return nil
}

func TestPortedInterceptorDenials(t *testing.T) {
	checker := &scopedChecker{}
	intercept := UnaryServerInterceptor(checker, true)
	authed := principal.InjectContext(context.Background(), principal.PrincipalInfo{ID: "alice", Kind: principal.KindJWT})
	for _, method := range []string{
		ateapipb.Control_ResumeActor_FullMethodName,
		ateapipb.Control_MintActorJWT_FullMethodName,
		ateapipb.Control_MintActorCertificate_FullMethodName,
	} {
		for _, name := range []string{"one", "two"} {
			ref := &ateapipb.ObjectRef{Atespace: "team-a", Name: name}
			var req any = &ateapipb.ResumeActorRequest{Actor: ref}
			if method == ateapipb.Control_MintActorJWT_FullMethodName {
				req = &ateapipb.MintActorJWTRequest{Actor: ref}
			} else if method == ateapipb.Control_MintActorCertificate_FullMethodName {
				req = &ateapipb.MintActorCertificateRequest{Actor: ref}
			}
			called := false
			_, err := intercept(authed, req, &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, any) (any, error) {
				called = true
				return nil, nil
			})
			if name == "one" && (err != nil || !called) {
				t.Errorf("%s same Actor: error %v, called %t", method, err, called)
			}
			if name == "two" && (apierror.Code(err) != codes.PermissionDenied || called) {
				t.Errorf("%s unrelated Actor: error %v, called %t", method, err, called)
			}
		}
	}
	called := false
	handler := func(context.Context, any) (any, error) { called = true; return nil, nil }
	_, err := intercept(authed, nil, &grpc.UnaryServerInfo{FullMethod: "/ateapi.Control/Unknown"}, handler)
	if apierror.Code(err) != codes.PermissionDenied || called {
		t.Errorf("unknown method: error %v, called %t", err, called)
	}
	_, err = intercept(context.Background(), &ateapipb.MintActorJWTRequest{}, &grpc.UnaryServerInfo{FullMethod: ateapipb.Control_MintActorJWT_FullMethodName}, handler)
	if apierror.Code(err) != codes.Unauthenticated || called {
		t.Errorf("unauthenticated before extraction: error %v, called %t", err, called)
	}
	if len(checker.calls) != 6 {
		t.Errorf("checker called %d times, want 6", len(checker.calls))
	}
}

func TestPortedInterceptorFlagAndHandlerPaths(t *testing.T) {
	checker := &scopedChecker{}
	flagOff := UnaryServerInterceptor(checker, false)
	called := false
	handler := func(context.Context, any) (any, error) { called = true; return nil, nil }
	_, err := flagOff(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/ateapi.Control/Unknown"}, handler)
	if err != nil || !called {
		t.Errorf("flag-off unknown RPC: error %v, called %t", err, called)
	}
	called = false
	_, err = flagOff(context.Background(), &ateapipb.ResumeActorRequest{}, &grpc.UnaryServerInfo{FullMethod: ateapipb.Control_ResumeActor_FullMethodName}, handler)
	if err != nil || !called {
		t.Errorf("flag-off ordinary RPC: error %v, called %t", err, called)
	}
	called = false
	_, err = flagOff(context.Background(), &ateapipb.CreateGlobalAccessPolicyRequest{}, &grpc.UnaryServerInfo{FullMethod: ateapipb.Control_CreateGlobalAccessPolicy_FullMethodName}, handler)
	if apierror.Code(err) != codes.Unauthenticated || called {
		t.Errorf("flag-off governance RPC: error %v, called %t", err, called)
	}
	called = false
	enforced := UnaryServerInterceptor(checker, true)
	_, err = enforced(context.Background(), &ateapipb.RegisterWorkerRequest{}, &grpc.UnaryServerInfo{FullMethod: ateapipb.WorkerService_RegisterWorker_FullMethodName}, handler)
	if err != nil || !called {
		t.Errorf("handler-authorized RPC: error %v, called %t", err, called)
	}
	if len(checker.calls) != 0 {
		t.Errorf("checker called for bypass paths: %v", checker.calls)
	}
	called = false
	_, err = enforced(WithBypass(context.Background()), nil, &grpc.UnaryServerInfo{FullMethod: "/ateapi.Control/Unknown"}, handler)
	if err != nil || !called {
		t.Errorf("in-process bypass: error %v, called %t", err, called)
	}
}
