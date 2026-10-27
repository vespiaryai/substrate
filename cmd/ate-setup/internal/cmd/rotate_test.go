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

package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/config"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/log"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/steps"
)

func TestS3InspectWritesOneJSONDocumentToStdout(t *testing.T) {
	inspect, _, err := rootCmd.Find([]string{"rotate", "s3", "inspect"})
	if err != nil {
		t.Fatal(err)
	}
	preRun, run := rootCmd.PersistentPreRunE, inspect.RunE
	t.Cleanup(func() {
		rootCmd.PersistentPreRunE, inspect.RunE = preRun, run
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		log.SetOutput(os.Stdout)
	})
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.LoadFlags(cmd.Flags(), config.LoadOptions{NoDevEnv: true})
		if err != nil {
			return err
		}
		routeCommandOutput(cmd)
		cfg.Resolved().Report(log.Writer(), config.ReportOptions{OmitDefaults: true})
		return nil
	}
	inspect.RunE = func(cmd *cobra.Command, _ []string) error {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(steps.S3RotationExpected{Context: "rotation-test"})
	}
	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{"--no-dev-env", "--no-report-defaults", "rotate", "s3", "inspect", "--client", "Deployment/a=u", "--client", "DaemonSet/b=v"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var state steps.S3RotationExpected
	decoder := json.NewDecoder(&stdout)
	if err := decoder.Decode(&state); err != nil {
		t.Fatalf("stdout is not JSON: %v; output %q", err, stdout.String())
	}
	if state.Context != "rotation-test" {
		t.Fatalf("unexpected JSON state: %+v", state)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("stdout contains a second document: %v", err)
	}
	if !strings.HasPrefix(stderr.String(), "configuration:") {
		t.Fatalf("configuration report absent from stderr: %q", stderr.String())
	}
}
