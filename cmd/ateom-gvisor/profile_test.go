//go:build linux

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

package main

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
	"google.golang.org/grpc/codes"
)

func TestParseGvisorProfile(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    gvisorProfile
		invalid bool
	}{
		{"", gvisorProfileDefault, false}, {"default", gvisorProfileDefault, false},
		{"systrap-20260831-v1", gvisorProfileSystrap20260831V1, false},
		{"systrap", gvisorProfileDefault, true}, {"systrap-20260831-v2", gvisorProfileDefault, true},
	} {
		got, err := parseGvisorProfile(tc.value)
		if got != tc.want || (err != nil) != tc.invalid {
			t.Errorf("parseGvisorProfile(%q) = %v, %v", tc.value, got, err)
		}
	}
}

func TestProfileArgs(t *testing.T) {
	for _, profile := range []gvisorProfile{gvisorProfileDefault, gvisorProfileSystrap20260831V1} {
		r := &runsc{actorDirs: testActorDirs, profile: profile}
		prefix := []string{"-log-format", "json", "--alsologtostderr", "-root", "/node/actors/test-actor-123/runsc-state", "--cpu-num-from-quota"}
		if profile == gvisorProfileSystrap20260831V1 {
			prefix = append(prefix, "--platform=systrap", "--network=sandbox", "--overlay2=none", "--directfs=false")
		}
		wantCreate := append(append([]string{}, prefix...), "create", "-bundle", "/node/actors/test-actor-123/bundle/container", "-pid-file", "/node/actors/test-actor-123/pidfiles/container.pid", "--console-socket", "/socket", "container")
		if got := r.createArgs("container", []string{"--console-socket", "/socket"}); !reflect.DeepEqual(got, wantCreate) {
			t.Errorf("create profile %d = %v, want %v", profile, got, wantCreate)
		}
		wantRestore := append(append([]string{}, prefix...), "restore", "-bundle", "/node/actors/test-actor-123/bundle/container", "-image-path", "/checkpoint", "-pid-file", "/node/actors/test-actor-123/pidfiles/container.pid", "-background", "-detach", "container")
		if got := r.restoreArgs("container", "/checkpoint"); !reflect.DeepEqual(got, wantRestore) {
			t.Errorf("restore profile %d = %v, want %v", profile, got, wantRestore)
		}
	}
}

func TestProfileRunscPath(t *testing.T) {
	for _, tc := range []struct {
		profile gvisorProfile
		path    string
		invalid bool
	}{
		{gvisorProfileDefault, "/var/lib/ate/static-files/other/runsc", false},
		{gvisorProfileSystrap20260831V1, systrap20260831RunscPath, false},
		{gvisorProfileSystrap20260831V1, "/var/lib/ate/static-files/other/runsc", true},
		{gvisorProfileSystrap20260831V1, systrap20260831RunscPath + "/../runsc", true},
		{gvisorProfile(99), systrap20260831RunscPath, true},
	} {
		if err := tc.profile.validateRunscPath(tc.path); (err != nil) != tc.invalid {
			t.Errorf("profile %d path %q: %v", tc.profile, tc.path, err)
		}
	}
}

func TestProfileRejectsRequestsBeforeSideEffects(t *testing.T) {
	s := &AteomService{profile: gvisorProfileSystrap20260831V1}
	dirs := &ateompb.ActorDirs{RootDir: "/actor", OciBundleDir: "/actor/bundle", CheckpointDir: "/actor/checkpoint", RestoreDir: "/actor/restore", DurableDirVolumeMountsDir: "/actor/durable", SystemInfoVolumeRootsDir: "/actor/system", VolumesDir: "/actor/volumes"}
	_, runErr := s.RunWorkload(context.Background(), &ateompb.RunWorkloadRequest{ActorDirs: dirs, RunscPath: "/var/lib/ate/static-files/other/runsc"})
	_, restoreErr := s.RestoreWorkload(context.Background(), &ateompb.RestoreWorkloadRequest{ActorDirs: dirs, RunscPath: "/var/lib/ate/static-files/other/runsc"})
	_, checkpointErr := s.CheckpointWorkload(context.Background(), &ateompb.CheckpointWorkloadRequest{ActorDirs: dirs, RunscPath: "/var/lib/ate/static-files/other/runsc"})
	_, terminateErr := s.TerminateWorkload(context.Background(), &ateompb.TerminateWorkloadRequest{ActorDirs: dirs, RunscPath: "/var/lib/ate/static-files/other/runsc"})
	for _, err := range []error{runErr, restoreErr, checkpointErr, terminateErr} {
		if apierror.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "systrap-20260831-v1 requires runsc_path") {
			t.Errorf("code = %v, want InvalidArgument: %v", apierror.Code(err), err)
		}
	}
}
