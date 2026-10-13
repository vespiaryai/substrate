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

package steps

import "testing"

func TestSharedMount(t *testing.T) {
	for _, tc := range []struct {
		name, mounts, path string
		want               bool
	}{
		{"shared root", "20 1 0:1 / / rw shared:1 - btrfs /dev/root rw", "/var/lib/ate", true},
		{"private child", "20 1 0:1 / / rw shared:1 - btrfs /dev/root rw\n21 20 0:2 / /var/lib rw - tmpfs tmpfs rw", "/var/lib/ate", false},
		{"shared child", "20 1 0:1 / / rw - btrfs /dev/root rw\n21 20 0:2 / /var/lib rw shared:2 - tmpfs tmpfs rw", "/var/lib/ate", true},
		{"prefix is not parent", "20 1 0:1 / /var/lib/ate-old rw shared:1 - tmpfs tmpfs rw", "/var/lib/ate", false},
		{"missing", "", "/var/lib/ate", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sharedMount(tc.mounts, tc.path); got != tc.want {
				t.Fatalf("sharedMount = %v, want %v", got, tc.want)
			}
		})
	}
}
