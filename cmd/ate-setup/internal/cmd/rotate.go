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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/steps"
)

func init() {
	rotate := &cobra.Command{Use: "rotate", Short: "Rotate installer-owned resources"}
	s3 := &cobra.Command{Use: "s3", Short: "Rotate the k3s S3 client trust and endpoint"}
	var expectedPath, caPath, receiptPath string
	var clients []string
	inspect := &cobra.Command{Use: "inspect", Short: "Print the current S3 rotation identities as JSON", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		inventory := make([]steps.S3RotationClient, 0, len(clients))
		for _, client := range clients {
			name, uid, ok := strings.Cut(client, "=")
			kind, name, kindOK := strings.Cut(name, "/")
			if !ok || !kindOK || uid == "" || name == "" || (kind != "Deployment" && kind != "DaemonSet") {
				return fmt.Errorf("invalid --client %q; use Deployment/name=UID or DaemonSet/name=UID", client)
			}
			inventory = append(inventory, steps.S3RotationClient{Kind: kind, Name: name, UID: uid})
		}
		state, err := env.InspectS3Rotation(cmd.Context(), inventory)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(state)
	}}
	inspect.Flags().StringArrayVar(&clients, "client", nil, "Independently verified installed client Kind/name=UID; repeat for every client")
	_ = inspect.MarkFlagRequired("client")
	trust := &cobra.Command{Use: "trust", Short: "Stage old and new public S3 roots", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		data, err := os.ReadFile(expectedPath)
		if err != nil {
			return err
		}
		var expected steps.S3RotationExpected
		if err := json.Unmarshal(data, &expected); err != nil {
			return fmt.Errorf("decode expected S3 state: %w", err)
		}
		ca, err := os.ReadFile(caPath)
		if err != nil {
			return err
		}
		_, err = env.RotateS3Trust(cmd.Context(), steps.S3TrustRotation{Expected: expected, CAPEM: ca, ReceiptPath: receiptPath})
		return err
	}}
	trust.Flags().StringVar(&expectedPath, "expected", "", "Path to the JSON state from rotate s3 inspect")
	trust.Flags().StringVar(&caPath, "ca-file", "", "Path to the public old and new CA PEM bundle")
	trust.Flags().StringVar(&receiptPath, "rotation-receipt", "", "Clean absolute path for the new rotation receipt")
	for _, name := range []string{"expected", "ca-file", "rotation-receipt"} {
		_ = trust.MarkFlagRequired(name)
	}
	s3.AddCommand(inspect, trust)
	rotate.AddCommand(s3)
	rootCmd.AddCommand(rotate)
}
