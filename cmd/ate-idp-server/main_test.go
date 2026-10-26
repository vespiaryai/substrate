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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/localjwtauthority"
	"github.com/google/go-cmp/cmp"
)

func TestMissingFlags(t *testing.T) {
	tests := []struct {
		flags map[string]string
		want  []string
	}{
		{flags: map[string]string{"--issuer": "https://idp.ate-system.svc", "--actor-id-jwt-pool": "/run/actor-id-jwt-pool/pool.json"}, want: nil},
		{flags: map[string]string{"--actor-id-jwt-pool": "", "--issuer": "", "--server-cred-bundle": "/run/bundle.pem"}, want: []string{"--actor-id-jwt-pool", "--issuer"}},
	}
	for _, tt := range tests {
		if diff := cmp.Diff(tt.want, missingFlags(tt.flags)); diff != "" {
			t.Errorf("missingFlags(%v) (-want +got):\n%s", tt.flags, diff)
		}
	}
}

func TestTLSStartupTrustAndShutdown(t *testing.T) {
	poolBytes, _, err := localjwtauthority.GeneratePool("ES256", "")
	if err != nil {
		t.Fatal(err)
	}
	poolPath := filepath.Join(t.TempDir(), "pool.json")
	if err := os.WriteFile(poolPath, poolBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
	root := writeTestBundle(t, bundlePath, "idp.ate-system.svc")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	oldIssuer, oldPool, oldBundle, oldAddr := *issuer, *poolFile, *serverBundle, *listenAddr
	t.Cleanup(func() { *issuer, *poolFile, *serverBundle, *listenAddr = oldIssuer, oldPool, oldBundle, oldAddr })
	*issuer, *poolFile, *serverBundle, *listenAddr = "https://idp.ate-system.svc", poolPath, bundlePath, address
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	url := "https://" + address + "/.well-known/openid-configuration"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: root, ServerName: "idp.ate-system.svc"}}}
	var response *http.Response
	deadline := time.After(5 * time.Second)
	for {
		response, err = client.Get(url)
		if err == nil {
			break
		}
		select {
		case runErr := <-done:
			t.Fatalf("server stopped during startup: %v", runErr)
		case <-deadline:
			t.Fatalf("HTTPS startup: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if response.StatusCode != http.StatusOK {
		t.Errorf("discovery status = %d", response.StatusCode)
	}
	response.Body.Close()
	client.CloseIdleConnections()
	for name, config := range map[string]*tls.Config{
		"wrong hostname": {RootCAs: root, ServerName: "other.ate-system.svc"},
		"unrelated CA":   {RootCAs: x509.NewCertPool(), ServerName: "idp.ate-system.svc"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
			resp, err := bad.Get(url)
			if err == nil {
				resp.Body.Close()
				t.Fatal("TLS connection succeeded with invalid trust")
			}
		})
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish after cancellation")
	}
}

func writeTestBundle(t *testing.T, path, dnsName string) *x509.CertPool {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{dnsName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...)
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots
}
