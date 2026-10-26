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

// Package server serves the actor JWT issuer's OpenID discovery document and
// JWK set.
package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/agent-substrate/substrate/internal/localjwtauthority"
	"github.com/agent-substrate/substrate/internal/oidcdiscovery"
)

// KeySource supplies the verification keys to publish.
type KeySource interface {
	VerificationKeys() ([]*localjwtauthority.VerificationKey, error)
}

// Server serves the discovery document and JWK set below the issuer path,
// plus /healthz. It builds both documents from its KeySource on every request
// and answers 500 when that fails.
type Server struct {
	issuer        string
	discoveryPath string
	jwksPath      string
	keys          KeySource
}

// New returns a Server that publishes keys for issuer. It fails if the keys
// cannot be published.
func New(issuer string, keys KeySource) (*Server, error) {
	if err := oidcdiscovery.ValidateIssuer(issuer); err != nil {
		return nil, err
	}
	issuerURL, _ := url.Parse(issuer)
	jwksURL, _ := url.Parse(oidcdiscovery.JWKSURI(issuer))
	basePath := strings.TrimSuffix(issuerURL.EscapedPath(), "/")
	s := &Server{
		issuer:        issuer,
		discoveryPath: basePath + "/.well-known/openid-configuration",
		jwksPath:      jwksURL.EscapedPath(),
		keys:          keys,
	}
	if _, _, err := s.build(); err != nil {
		return nil, fmt.Errorf("cannot publish the keys: %w", err)
	}
	return s, nil
}

// ServeHTTP compares escaped paths directly because ServeMux redirects paths
// with repeated separators that the issuer validator accepts.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	if path != s.discoveryPath && path != s.jwksPath && path != "/healthz" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch path {
	case s.discoveryPath:
		discovery, _, err := s.build()
		serveDocument(w, r, discovery, err)
	case s.jwksPath:
		_, jwks, err := s.build()
		serveDocument(w, r, jwks, err)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) build() (discovery, jwks []byte, err error) {
	verificationKeys, err := s.keys.VerificationKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("reading verification keys: %w", err)
	}
	if jwks, err = localjwtauthority.JWKS(verificationKeys); err != nil {
		return nil, nil, err
	}
	algorithms := make([]string, 0, len(verificationKeys))
	for _, vk := range verificationKeys {
		algorithms = append(algorithms, vk.Algorithm)
	}
	discovery, err = oidcdiscovery.DiscoveryDocument(s.issuer, algorithms)
	if err != nil {
		return nil, nil, err
	}
	return discovery, jwks, nil
}

func serveDocument(w http.ResponseWriter, r *http.Request, doc []byte, err error) {
	if err != nil {
		slog.ErrorContext(r.Context(), "Cannot publish the actor JWT keys", slog.Any("err", err))
		http.Error(w, "cannot publish the key set", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(doc)
}
