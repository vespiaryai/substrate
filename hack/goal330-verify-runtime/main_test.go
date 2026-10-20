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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRefusesRuntimeOverrides(t *testing.T) {
	for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "TESTCONTAINERS_SESSION_ID", "TESTCONTAINERS_HUB_IMAGE_NAME_PREFIX", "RYUK_CONNECTION_TIMEOUT"} {
		t.Run(key, func(t *testing.T) {
			for _, entry := range os.Environ() {
				name, _, _ := strings.Cut(entry, "=")
				if strings.HasPrefix(name, "DOCKER_") || strings.HasPrefix(name, "TESTCONTAINERS_") || strings.HasPrefix(name, "RYUK_") {
					old := os.Getenv(name)
					if err := os.Unsetenv(name); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := os.Setenv(name, old); err != nil {
							t.Error(err)
						}
					})
				}
			}
			in := invocation{endpoint: "unix:///run/user/1000/vesverify0123456789abcdef0123456789abcdef/docker.sock", daemonID: "owned-fixture", mode: "guard"}
			home := t.TempDir()
			t.Setenv("HOME", home)
			if err := os.WriteFile(filepath.Join(home, ".testcontainers.properties"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("DOCKER_HOST", in.endpoint)
			t.Setenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", strings.TrimPrefix(in.endpoint, "unix://"))
			t.Setenv("TESTCONTAINERS_HOST_OVERRIDE", "127.0.0.1")
			t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "false")
			t.Setenv("TESTCONTAINERS_RYUK_CONTAINER_PRIVILEGED", "false")
			if err := validate(in); err != nil {
				t.Fatal(err)
			}
			t.Setenv(key, "conflict")
			if err := validate(in); err == nil {
				t.Fatalf("accepted %s override", key)
			}
		})
	}
}

func TestValidateRefusesSharedEndpoint(t *testing.T) {
	in := invocation{endpoint: "unix:///var/run/docker.sock", daemonID: "shared", mode: "postgres"}
	if err := validate(in); err == nil {
		t.Fatal("accepted shared endpoint")
	}
}
