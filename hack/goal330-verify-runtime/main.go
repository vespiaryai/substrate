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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

type invocation struct {
	endpoint string
	daemonID string
	mode     string
	pause    string
}

func main() {
	var in invocation
	flag.StringVar(&in.endpoint, "endpoint", "", "literal owned unix endpoint")
	flag.StringVar(&in.daemonID, "daemon-id", "", "inventoried private daemon ID")
	flag.StringVar(&in.mode, "case", "", "guard or postgres")
	flag.StringVar(&in.pause, "pause-at", "", "native-info, first-provider, guarded, or postgres-ping; resume with continue plus newline")
	flag.Parse()
	if err := run(in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func validate(in invocation) error {
	if !regexp.MustCompile(`^unix:///run/user/1000/vesverify[0-9a-f]{32}/docker.sock$`).MatchString(in.endpoint) || in.daemonID == "" {
		return errors.New("require an owned canonical endpoint and inventoried daemon ID")
	}
	if in.mode != "guard" && in.mode != "postgres" {
		return errors.New("case must be guard or postgres")
	}
	switch in.pause {
	case "", "native-info", "first-provider", "guarded", "postgres-ping":
	default:
		return errors.New("unknown pause checkpoint")
	}
	if in.mode == "guard" && in.pause == "postgres-ping" {
		return errors.New("guard case cannot reach postgres-ping")
	}
	expected := map[string]string{
		"DOCKER_HOST":                              in.endpoint,
		"TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE":    strings.TrimPrefix(in.endpoint, "unix://"),
		"TESTCONTAINERS_HOST_OVERRIDE":             "127.0.0.1",
		"TESTCONTAINERS_RYUK_DISABLED":             "false",
		"TESTCONTAINERS_RYUK_CONTAINER_PRIVILEGED": "false",
	}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if want, ok := expected[key]; ok {
			if value != want {
				return fmt.Errorf("conflicting %s", key)
			}
			delete(expected, key)
		} else if strings.HasPrefix(key, "DOCKER_") || strings.HasPrefix(key, "TESTCONTAINERS_") || strings.HasPrefix(key, "RYUK_") {
			if key != "DOCKER_CONFIG" {
				return fmt.Errorf("unexpected runtime setting %s", key)
			}
		}
	}
	if len(expected) != 0 {
		return errors.New("required runtime settings missing")
	}
	properties, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".testcontainers.properties"))
	if err != nil {
		return err
	}
	if len(properties) != 0 {
		return errors.New("testcontainers properties must be empty")
	}
	return nil
}

func checkpoint(in invocation, stage string) error {
	fmt.Println(stage)
	if in.pause != stage {
		return nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if line != "continue\n" {
		return errors.New("checkpoint refused")
	}
	return nil
}

func guard(ctx context.Context, in invocation) (err error) {
	native, err := client.New(client.WithHost(in.endpoint))
	if err != nil {
		return err
	}
	info, infoErr := native.Info(ctx, client.InfoOptions{})
	closeErr := native.Close()
	if err := errors.Join(infoErr, closeErr); err != nil {
		return err
	}
	if info.Info.ID != in.daemonID {
		return errors.New("native daemon identity mismatch")
	}
	if err := checkpoint(in, "native-info"); err != nil {
		return err
	}
	first, err := testcontainers.NewDockerProvider()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, first.Close()) }()
	if first.Client().DaemonHost() != in.endpoint {
		return errors.New("first provider endpoint mismatch")
	}
	info, err = first.Client().Info(ctx, client.InfoOptions{})
	if err != nil {
		return err
	}
	if info.Info.ID != in.daemonID {
		return errors.New("wrapper daemon identity mismatch")
	}
	if err := checkpoint(in, "first-provider"); err != nil {
		return err
	}
	second, err := testcontainers.NewDockerProvider()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, second.Close()) }()
	if second.Client().DaemonHost() != in.endpoint {
		return errors.New("second provider endpoint mismatch")
	}
	return nil
}

func run(in invocation) (err error) {
	if err := validate(in); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := guard(ctx, in); err != nil {
		return err
	}
	if err := checkpoint(in, "guarded"); err != nil {
		return err
	}
	if in.mode == "guard" {
		return nil
	}
	if err := validate(in); err != nil {
		return err
	}
	native, err := client.New(client.WithHost(in.endpoint))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, native.Close()) }()
	for tag, id := range map[string]string{
		"postgres:18-alpine":         "sha256:c293117fcecda7344b5480222e813b9f673d7abd69b1dd95eff239b768b04f59",
		"testcontainers/ryuk:0.14.0": "sha256:9a5f93e8f9300530b91866bcf41c0b8a5d72f0e5a7b4365167a48df9816cd36e",
	} {
		image, err := native.ImageInspect(ctx, tag)
		if err != nil {
			return err
		}
		if image.ID != id || image.Os != "linux" || image.Architecture != "amd64" {
			return fmt.Errorf("image identity mismatch for %s", tag)
		}
	}
	before, err := native.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return err
	}
	if len(before.Items) != 0 {
		return errors.New("private daemon already has containers")
	}
	pg, err := postgres.Run(ctx, "postgres:18-alpine", postgres.BasicWaitStrategies())
	if pg != nil {
		fmt.Printf("postgres-id=%s\n", pg.GetContainerID())
		defer func() {
			cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			err = errors.Join(err, pg.Terminate(cleanupCtx))
		}()
	}
	if err != nil {
		return err
	}
	inspection, err := pg.Inspect(ctx)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(inspection); err != nil {
		return err
	}
	objects, err := native.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return err
	}
	if len(objects.Items) != 2 {
		return errors.New("expected exactly PostgreSQL and ordinary Ryuk")
	}
	ryukCount := 0
	for _, object := range objects.Items {
		if object.ID == pg.GetContainerID() {
			continue
		}
		if object.Labels["org.testcontainers.ryuk"] != "true" || object.Labels["org.testcontainers.sessionId"] != inspection.Config.Labels["org.testcontainers.sessionId"] {
			return errors.New("unexpected private container")
		}
		ryuk, err := native.ContainerInspect(ctx, object.ID, client.ContainerInspectOptions{})
		if err != nil {
			return err
		}
		if !ryuk.Container.State.Running || ryuk.Container.HostConfig.Privileged || ryuk.Container.Config.Image != "testcontainers/ryuk:0.14.0" {
			return errors.New("Ryuk is not active and ordinary")
		}
		if err := json.NewEncoder(os.Stdout).Encode(ryuk.Container); err != nil {
			return err
		}
		ryukCount++
	}
	if ryukCount != 1 {
		return errors.New("expected one Ryuk")
	}
	uri, err := pg.ConnectionString(ctx, "sslmode=disable", "connect_timeout=5")
	if err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, uri)
	if err != nil {
		return err
	}
	pingErr := conn.Ping(ctx)
	closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	closeErr := conn.Close(closeCtx)
	stop()
	if err := errors.Join(pingErr, closeErr); err != nil {
		return err
	}
	return checkpoint(in, "postgres-ping")
}
