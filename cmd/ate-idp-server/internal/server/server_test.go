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

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/agent-substrate/substrate/internal/actoridjwt"
	"github.com/agent-substrate/substrate/internal/localjwtauthority"
)

type fakeKeys struct {
	mu   sync.Mutex
	keys []*localjwtauthority.VerificationKey
	err  error
}

func (f *fakeKeys) VerificationKeys() ([]*localjwtauthority.VerificationKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys, f.err
}

func (f *fakeKeys) set(keys []*localjwtauthority.VerificationKey, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys, f.err = keys, err
}

func verificationKeys(t *testing.T, algorithms ...string) []*localjwtauthority.VerificationKey {
	t.Helper()
	pool := &localjwtauthority.ConcretePool{}
	for _, alg := range algorithms {
		authority, err := localjwtauthority.GenerateAuthority(alg, "")
		if err != nil {
			t.Fatal(err)
		}
		pool.Authorities = append(pool.Authorities, authority)
	}
	keys, err := pool.VerificationKeys()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func keySet(t *testing.T, keys []*localjwtauthority.VerificationKey) string {
	t.Helper()
	jwks, err := localjwtauthority.JWKS(keys)
	if err != nil {
		t.Fatal(err)
	}
	return string(jwks)
}

func newServer(t *testing.T, issuer string, keys KeySource) http.Handler {
	t.Helper()
	s, err := New(issuer, keys)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func get(h http.Handler, method, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, target, nil))
	return w
}

func TestServesDocuments(t *testing.T) {
	keys := verificationKeys(t, "ES256")
	s := newServer(t, "https://idp.ate-system.svc", &fakeKeys{keys: keys})
	tests := []struct {
		target string
		want   string
	}{
		{
			target: "/.well-known/openid-configuration",
			want: `{"issuer":"https://idp.ate-system.svc",` +
				`"jwks_uri":"https://idp.ate-system.svc/openid/v1/jwks",` +
				`"response_types_supported":["id_token"],` +
				`"subject_types_supported":["public"],` +
				`"id_token_signing_alg_values_supported":["ES256"],` +
				`"claims_supported":["iss","sub","aud","exp","nbf","iat","jti","ate.dev"]}`,
		},
		{target: "/openid/v1/jwks", want: keySet(t, keys)},
	}
	for _, tt := range tests {
		w := get(s, http.MethodGet, tt.target)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", tt.target, w.Code)
		}
		if diff := cmp.Diff(tt.want, w.Body.String()); diff != "" {
			t.Errorf("GET %s body (-want +got):\n%s", tt.target, diff)
		}
		if got := w.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("GET %s: Content-Type = %q, want application/json; charset=utf-8", tt.target, got)
		}
	}
}

func TestNewFails(t *testing.T) {
	keys := verificationKeys(t, "ES256")
	tests := map[string]struct {
		issuer string
		keys   KeySource
	}{
		"issuer not https":  {issuer: "http://idp.ate-system.svc", keys: &fakeKeys{keys: keys}},
		"issuer with query": {issuer: "https://idp.example.com/prod?x=1", keys: &fakeKeys{keys: keys}},
		"keys unreadable":   {issuer: "https://idp.ate-system.svc", keys: &fakeKeys{err: os.ErrNotExist}},
		"no keys":           {issuer: "https://idp.ate-system.svc", keys: &fakeKeys{}},
	}
	for name, tt := range tests {
		if _, err := New(tt.issuer, tt.keys); err == nil {
			t.Errorf("%s: New returned nil error", name)
		}
	}
}

func TestFollowsKeyChanges(t *testing.T) {
	first := verificationKeys(t, "ES256")
	keys := &fakeKeys{keys: first}
	s := newServer(t, "https://idp.ate-system.svc", keys)
	if got, want := get(s, http.MethodGet, "/openid/v1/jwks").Body.String(), keySet(t, first); got != want {
		t.Fatalf("served key set = %q, want %q", got, want)
	}

	rotated := append(verificationKeys(t, "RS256"), first...)
	keys.set(rotated, nil)
	if got, want := get(s, http.MethodGet, "/openid/v1/jwks").Body.String(), keySet(t, rotated); got != want {
		t.Errorf("after rotation: served key set = %q, want %q", got, want)
	}

	for name, change := range map[string]func(){
		"read error": func() { keys.set(nil, os.ErrNotExist) },
		"empty pool": func() { keys.set(nil, nil) },
	} {
		change()
		for _, target := range []string{"/.well-known/openid-configuration", "/openid/v1/jwks"} {
			if got := get(s, http.MethodGet, target).Code; got != http.StatusInternalServerError {
				t.Errorf("after %s: GET %s = %d, want 500", name, target, got)
			}
		}
		if got := get(s, http.MethodGet, "/healthz").Code; got != http.StatusOK {
			t.Errorf("after %s: GET /healthz = %d, want 200", name, got)
		}
	}
}

func TestDiscoveryAdvertisesPoolAlgorithms(t *testing.T) {
	s := newServer(t, "https://idp.ate-system.svc", &fakeKeys{keys: verificationKeys(t, "RS256", "ES256", "ES256")})
	var doc struct {
		Algorithms []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(get(s, http.MethodGet, "/.well-known/openid-configuration").Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"ES256", "RS256"}, doc.Algorithms); diff != "" {
		t.Errorf("algorithms (-want +got):\n%s", diff)
	}
}

func TestMethodsAndUnknownPaths(t *testing.T) {
	s := newServer(t, "https://idp.ate-system.svc", &fakeKeys{keys: verificationKeys(t, "ES256")})

	if got := get(s, http.MethodGet, "/healthz").Code; got != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200", got)
	}

	if got := get(s, http.MethodHead, "/openid/v1/jwks").Code; got != http.StatusOK {
		t.Errorf("HEAD = %d, want 200", got)
	}

	w := get(s, http.MethodPost, "/openid/v1/jwks")
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST = %d, Allow %q; want 405, Allow GET, HEAD", w.Code, w.Header().Get("Allow"))
	}

	if got := get(s, http.MethodGet, "/openid/v1/other").Code; got != http.StatusNotFound {
		t.Errorf("GET unknown path = %d, want 404", got)
	}
}

func TestPublishesRefreshingPool(t *testing.T) {
	wire, keyID, err := localjwtauthority.GeneratePool("ES256", "")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "pool.json")
	if err := os.WriteFile(file, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := localjwtauthority.NewRefreshingPool(file)
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(t, "https://idp.ate-system.svc", pool)

	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(get(s, http.MethodGet, "/openid/v1/jwks").Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("served %d keys, want 1", len(set.Keys))
	}
	if k := set.Keys[0]; k["kid"] != keyID || k["alg"] != "ES256" || k["d"] != "" {
		t.Errorf("served key %v; want kid %q, alg ES256, and no private key", k, keyID)
	}
}

func TestIssuerPaths(t *testing.T) {
	keys := &fakeKeys{keys: verificationKeys(t, "ES256")}
	for _, issuer := range []string{
		"https://idp.ate-system.svc/team",
		"https://idp.ate-system.svc/team/",
		"https://idp.ate-system.svc/team%2Fblue",
		"https://idp.ate-system.svc/team//blue",
	} {
		t.Run(issuer, func(t *testing.T) {
			h := newServer(t, issuer, keys)
			base := strings.TrimSuffix(strings.TrimPrefix(issuer, "https://idp.ate-system.svc"), "/")
			discoveryPath := base + "/.well-known/openid-configuration"
			jwksPath := base + "/openid/v1/jwks"
			w := get(h, http.MethodGet, discoveryPath)
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", discoveryPath, w.Code)
			}
			var doc struct {
				Issuer  string `json:"issuer"`
				JWKSURI string `json:"jwks_uri"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Issuer != issuer || doc.JWKSURI != strings.TrimSuffix(issuer, "/")+"/openid/v1/jwks" {
				t.Errorf("discovery issuer = %q, jwks_uri = %q", doc.Issuer, doc.JWKSURI)
			}
			if got := get(h, http.MethodGet, jwksPath).Code; got != http.StatusOK {
				t.Errorf("GET %s = %d, want 200", jwksPath, got)
			}
			ts := httptest.NewServer(h)
			defer ts.Close()
			for _, path := range []string{discoveryPath, jwksPath} {
				resp, err := ts.Client().Get(ts.URL + path)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("HTTP GET %s = %d, want 200", path, resp.StatusCode)
				}
			}
		})
	}
}

func TestServedKeyVerifiesTokenAcrossRotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first, err := localjwtauthority.GenerateAuthority("ES256", "first")
		if err != nil {
			t.Fatal(err)
		}
		second, err := localjwtauthority.GenerateAuthority("ES256", "second")
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "pool.json")
		writePool := func(authorities ...*localjwtauthority.Authority) {
			t.Helper()
			wire, err := localjwtauthority.Marshal(&localjwtauthority.ConcretePool{Authorities: authorities, ActiveForSigning: authorities[0].ID})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, wire, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		writePool(first)
		pool, err := localjwtauthority.NewRefreshingPool(file)
		if err != nil {
			t.Fatal(err)
		}
		issuer := "https://idp.ate-system.svc"
		oldToken, err := pool.SignJWT(&actoridjwt.Claims{Issuer: issuer, Subject: "actor", Audiences: []string{"recipient"}, Expiration: time.Now().Add(time.Hour), Substrate: actoridjwt.SubstrateClaims{Atespace: "space", ActorName: "actor", ActorUID: "uid"}})
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(oldToken, ".")
		if len(parts) != 3 {
			t.Fatalf("JWT has %d parts", len(parts))
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var claims map[string]json.RawMessage
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		if string(claims["iss"]) != `"https://idp.ate-system.svc"` || string(claims["ate.dev"]) != `{"atespace":"space","actorName":"actor","actorUID":"uid"}` {
			t.Errorf("old token claims = %s", payload)
		}
		verifyServedToken(t, newServer(t, issuer, pool), oldToken, "first")

		writePool(second, first)
		time.Sleep(61 * time.Second)
		newToken, err := pool.SignJWT(&actoridjwt.Claims{Issuer: issuer, Subject: "actor", Audiences: []string{"recipient"}, Expiration: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		h := newServer(t, issuer, pool)
		verifyServedToken(t, h, oldToken, "first")
		verifyServedToken(t, h, newToken, "second")
	})
}

func verifyServedToken(t *testing.T, h http.Handler, token, keyID string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	var set struct {
		Keys []struct {
			KeyID string `json:"kid"`
			X     string `json:"x"`
			Y     string `json:"y"`
			D     string `json:"d"`
		} `json:"keys"`
	}
	w := get(h, http.MethodGet, "/openid/v1/jwks")
	if w.Code != http.StatusOK {
		t.Fatalf("JWKS status = %d", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	for _, key := range set.Keys {
		if key.D != "" {
			t.Fatal("JWKS exposed a private key")
		}
		if key.KeyID != keyID {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			t.Fatal(err)
		}
		y, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			t.Fatal(err)
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Fatal("served key did not verify JWT")
		}
		return
	}
	t.Fatalf("JWKS omitted key %q", keyID)
}
