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

// Package storetest provides isolated PostgreSQL-backed stores for tests.
//
// One PostgreSQL container is shared by every test in a package; each test gets
// its own database. Nothing stops that container when the test binary exits, so
// packages using this package must call [Shutdown] from their TestMain.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/authz"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store/atepg"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store/dockerenv"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	containerOnce sync.Once
	adminPool     *pgxpool.Pool
	containerPG   *postgres.PostgresContainer
	containerErr  error
	databaseCount atomic.Uint64
)

// SetupTestStore returns a real PostgreSQL-backed store with a database unique
// to this test. A shared container keeps this suitable for packages that run
// subtests in parallel; databases are dropped during cleanup.
func SetupTestStore(t *testing.T) (store.Interface, func()) {
	t.Helper()
	return SetupPostgresPersistence(t), func() {}
}

// SetupPostgresPersistence returns an isolated atepg persistence instance.
func SetupPostgresPersistence(t *testing.T) *atepg.Persistence {
	t.Helper()
	ctx := context.Background()
	admin := requireAdminPool(t)
	databaseName := fmt.Sprintf("ateapi_test_%d", databaseCount.Add(1))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatalf("creating PostgreSQL test database: %v", err)
	}

	config := admin.Config().Copy()
	config.ConnConfig.Database = databaseName
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connecting to PostgreSQL test database: %v", err)
	}
	persistence, err := atepg.NewPersistence(ctx, pool)
	if err != nil {
		pool.Close()
		t.Fatalf("creating PostgreSQL persistence: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+databaseName); err != nil {
			t.Errorf("dropping PostgreSQL test database: %v", err)
		}
	})
	// The server always wires a PolicyManager, so test stores do too.
	fgaServer, err := authz.NewOpenFGAServer(pool)
	if err != nil {
		t.Fatalf("creating OpenFGA server: %v", err)
	}
	t.Cleanup(fgaServer.Close)
	_, policyManager, err := authz.New(ctx, pool, fgaServer, nil)
	if err != nil {
		t.Fatalf("initializing OpenFGA authz: %v", err)
	}
	persistence.SetPolicyManager(policyManager)
	return persistence
}

// MustCreateAtespace creates name unless it already exists. PostgreSQL enforces
// the parent relationship for actor and snapshot records, so test fixtures use
// this before seeding those resources.
func MustCreateAtespace(t *testing.T, ctx context.Context, s store.Interface, name string) {
	t.Helper()
	_, err := s.CreateAtespace(ctx, &ateapipb.Atespace{Metadata: &ateapipb.ResourceMetadata{Name: name}})
	if err != nil && !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("creating test atespace %q: %v", name, err)
	}
}

// MustCreateActor ensures actor's parent atespace exists, then creates actor.
// Use the store method directly only in tests that exercise missing-parent
// behavior.
func MustCreateActor(t *testing.T, ctx context.Context, s store.Interface, actor *ateapipb.Actor) *ateapipb.Actor {
	t.Helper()
	atespace := actor.GetMetadata().GetAtespace()
	MustCreateAtespace(t, ctx, s, atespace)
	created, err := s.CreateActor(ctx, actor)
	if err != nil {
		t.Fatalf("creating test actor %q/%q: %v", atespace, actor.GetMetadata().GetName(), err)
	}
	return created
}

// MustCreateTag ensures tag's parent atespace exists, then stores
// tag as given — ready or still pending, whichever state the test needs to
// start from. Use the store method directly only in tests that exercise
// missing-parent behavior.
func MustCreateTag(t *testing.T, ctx context.Context, s store.Interface, tag *ateapipb.Tag) *ateapipb.Tag {
	t.Helper()
	atespace := tag.GetMetadata().GetAtespace()
	name := tag.GetMetadata().GetName()
	MustCreateAtespace(t, ctx, s, atespace)
	created, err := s.CreateTag(ctx, tag)
	if err != nil {
		t.Fatalf("creating test tag %q/%q: %v", atespace, name, err)
	}
	return created
}

// RunTests runs m and terminates the shared PostgreSQL container afterwards.
// Packages with no other TestMain work should use it as their whole TestMain;
// the rest must call [Shutdown] themselves.
func RunTests(m *testing.M) {
	code := m.Run()
	Shutdown()
	os.Exit(code)
}

// Shutdown terminates the shared PostgreSQL container, if one was started.
func Shutdown() {
	if adminPool != nil {
		adminPool.Close()
		adminPool = nil
	}
	if containerPG != nil {
		if err := containerPG.Terminate(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "terminating PostgreSQL testcontainer: %v\n", err)
		}
		containerPG = nil
	}
}

func requireAdminPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	containerOnce.Do(func() {
		ctx := context.Background()
		if err := dockerenv.Configure(ctx); err != nil {
			containerErr = err
			return
		}
		const memoryLimit = int64(512 << 20)
		const cpuLimit = int64(500_000_000)
		const pidsLimit = int64(128)
		port := network.MustParsePort("5432/tcp")
		loopback := netip.MustParseAddr("127.0.0.1")
		owner := os.Getenv("ATE_TEST_POSTGRES_OWNER")
		if owner == "" {
			owner = fmt.Sprintf("pid-%d", os.Getpid())
		}
		containerPG, containerErr = postgres.Run(ctx, "postgres:18-alpine",
			postgres.WithDatabase("postgres"),
			postgres.WithUsername("postgres"),
			postgres.WithPassword("postgres"),
			testcontainers.WithLabels(map[string]string{"ate.test.postgres.owner": owner}),
			testcontainers.WithHostConfigModifier(func(host *container.HostConfig) {
				host.Resources.NanoCPUs = cpuLimit
				host.Resources.Memory = memoryLimit
				host.Resources.MemorySwap = memoryLimit
				host.Resources.PidsLimit = new(int64)
				*host.Resources.PidsLimit = pidsLimit
				host.PortBindings = network.PortMap{port: {{HostIP: loopback, HostPort: "0"}}}
			}),
		)
		if containerErr != nil {
			return
		}
		inspect, err := containerPG.Inspect(ctx)
		if err != nil {
			containerErr = fmt.Errorf("inspecting PostgreSQL testcontainer: %w", err)
			return
		}
		if inspect.HostConfig == nil || inspect.Config == nil || inspect.NetworkSettings == nil ||
			inspect.HostConfig.Resources.NanoCPUs != cpuLimit ||
			inspect.HostConfig.Resources.Memory != memoryLimit ||
			inspect.HostConfig.Resources.MemorySwap != memoryLimit ||
			inspect.HostConfig.Resources.PidsLimit == nil || *inspect.HostConfig.Resources.PidsLimit != pidsLimit ||
			inspect.Config.Labels["ate.test.postgres.owner"] != owner ||
			len(inspect.HostConfig.PortBindings[port]) != 1 || inspect.HostConfig.PortBindings[port][0].HostIP != loopback ||
			len(inspect.NetworkSettings.Ports[port]) != 1 || inspect.NetworkSettings.Ports[port][0].HostIP != loopback {
			containerErr = fmt.Errorf("PostgreSQL testcontainer resource or loopback binding readback differs from the bounded fixture")
			return
		}
		fmt.Fprintf(os.Stderr, "PostgreSQL testcontainer %s: CPU=%d memory=%d swap=%d pids=%d loopback=%s\n",
			inspect.ID, inspect.HostConfig.Resources.NanoCPUs, inspect.HostConfig.Resources.Memory,
			inspect.HostConfig.Resources.MemorySwap, *inspect.HostConfig.Resources.PidsLimit, inspect.NetworkSettings.Ports[port][0].HostIP)
		dsn, err := containerPG.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			containerErr = err
			return
		}
		adminPool, containerErr = pgxpool.New(ctx, dsn)
		if containerErr != nil {
			return
		}
		var pingErr error
		for i := 0; i < 30; i++ {
			pingErr = adminPool.Ping(ctx)
			if pingErr == nil {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		adminPool.Close()
		adminPool = nil
		containerErr = fmt.Errorf("pinging PostgreSQL testcontainer after retries: %w", pingErr)
	})
	if containerErr != nil {
		if dockerenv.Required() {
			t.Fatalf("PostgreSQL testcontainer unavailable and required (CI or REQUIRE_DOCKER is set): %v", containerErr)
		}
		t.Skipf("PostgreSQL testcontainer unavailable (requires Docker): %v", containerErr)
	}
	return adminPool
}
