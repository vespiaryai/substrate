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
	"fmt"

	"github.com/agent-substrate/substrate/internal/apierror"
)

type gvisorProfile uint8

const (
	gvisorProfileDefault gvisorProfile = iota
	gvisorProfileSystrap20260831V1
)

const systrap20260831RunscPath = "/var/lib/ate/static-files/gvisor-b9ccc6e14ca4eb2c2e65ff66e011f3b7e79d3275fb12eab747b19f95caf8e891/runsc"

func parseGvisorProfile(value string) (gvisorProfile, error) {
	switch value {
	case "", "default":
		return gvisorProfileDefault, nil
	case "systrap-20260831-v1":
		return gvisorProfileSystrap20260831V1, nil
	default:
		return gvisorProfileDefault, fmt.Errorf("unknown --gvisor-profile %q", value)
	}
}

func (p gvisorProfile) validateRunscPath(path string) error {
	switch p {
	case gvisorProfileDefault:
		return nil
	case gvisorProfileSystrap20260831V1:
		if path != systrap20260831RunscPath {
			return apierror.InvalidArgument("systrap-20260831-v1 requires runsc_path %q", systrap20260831RunscPath)
		}
		return nil
	default:
		return apierror.InvalidArgument("unknown gVisor profile %d", p)
	}
}

func (p gvisorProfile) flags() []string {
	if p == gvisorProfileSystrap20260831V1 {
		return []string{"--platform=systrap", "--network=sandbox", "--overlay2=none", "--directfs=false"}
	}
	return nil
}
