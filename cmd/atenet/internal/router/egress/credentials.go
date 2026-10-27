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

package egress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/agent-substrate/substrate/cmd/atenet/internal/router/extproc"
	"github.com/agent-substrate/substrate/internal/egresspolicy"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/agent-substrate/substrate/pkg/proto/credproviderpb"
)

func mapCredentialProviderError(err error) error {
	switch status.Code(err) {
	case codes.NotFound, codes.PermissionDenied:
		return extproc.WrapReqError(envoy_type.StatusCode_Forbidden, err, deniedBody)
	case codes.Unavailable, codes.DeadlineExceeded:
		return extproc.WrapReqError(envoy_type.StatusCode_ServiceUnavailable, err, deniedBody)
	default:
		return extproc.WrapReqError(envoy_type.StatusCode_Forbidden, err, deniedBody)
	}
}

func (h *Handler) applyEffects(ctx context.Context, identity actorIncarnation, dest egresspolicy.Destination, headers map[string]string, effects *ateapipb.HttpRuleEffects) ([]*corev3.HeaderValueOption, error) {
	ref := identity.Ref
	var injections []*ateapipb.CredentialHeader
	for _, inj := range effects.GetReplaceHeaders() {
		if _, ok := headers[strings.ToLower(inj.GetHeader())]; ok {
			injections = append(injections, inj)
		}
	}
	if len(injections) == 0 {
		return nil, nil
	}

	// Atunnel connected to us with an ateom-for-actor SPIFFE ID; translate it
	// to a pure actor SPIFFE ID for plugins to make decisions on.
	actorSpiffeID := resources.ActorSPIFFEID(ref).String()

	setHeaders := make([]*corev3.HeaderValueOption, 0, len(injections))
	for _, inj := range injections {
		if ctx.Err() != nil {
			return nil, extproc.NewReqError(envoy_type.StatusCode_RequestTimeout, deniedBody)
		}
		if err := validateInjectHeader(inj.GetHeader()); err != nil {
			slog.ErrorContext(ctx, "egress denied: policy names an unusable injection header",
				slog.Any("actor", ref), slog.String("host", dest.Hostname), slog.String("header", inj.GetHeader()), slog.Any("err", err))
			return nil, extproc.WrapReqError(envoy_type.StatusCode_InternalServerError, err, deniedBody)
		}
		if src := inj.GetActorJwt(); src != nil {
			token, err := h.actorJWT(ctx, identity, src)
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			if err != nil {
				code := envoy_type.StatusCode_InternalServerError
				switch {
				case ctx.Err() != nil:
					code = envoy_type.StatusCode_RequestTimeout
				case status.Code(err) == codes.NotFound, status.Code(err) == codes.PermissionDenied, status.Code(err) == codes.Aborted:
					code = envoy_type.StatusCode_Forbidden
				case status.Code(err) == codes.Unavailable, status.Code(err) == codes.DeadlineExceeded, errors.Is(err, context.DeadlineExceeded):
					code = envoy_type.StatusCode_ServiceUnavailable
				}
				slog.ErrorContext(ctx, "egress denied: actor JWT mint failed",
					slog.Any("actor", ref), slog.String("host", dest.Hostname), slog.String("header", inj.GetHeader()), slog.String("code", code.String()))
				return nil, extproc.NewReqError(code, deniedBody)
			}
			setHeaders = append(setHeaders, &corev3.HeaderValueOption{
				Header:       &corev3.HeaderValue{Key: inj.GetHeader(), RawValue: []byte(inj.GetPrefix() + token)},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
			continue
		}
		if h.provider == nil {
			slog.ErrorContext(ctx, "egress denied: policy requires credential injection but no credential provider is configured",
				slog.Any("actor", ref), slog.String("host", dest.Hostname))
			return nil, extproc.NewReqError(envoy_type.StatusCode_InternalServerError, deniedBody)
		}

		if h.providerName != "" {
			name, err := providerNameFromURI(inj.GetCredentialUri())
			if err != nil {
				slog.ErrorContext(ctx, "egress denied: policy names an unparseable credential URI",
					slog.Any("actor", ref), slog.String("host", dest.Hostname), slog.String("uri", inj.GetCredentialUri()), slog.Any("err", err))
				return nil, extproc.WrapReqError(envoy_type.StatusCode_InternalServerError, err, deniedBody)
			}
			if name != h.providerName {
				slog.ErrorContext(ctx, "egress denied: credential URI names a provider this gateway does not serve",
					slog.Any("actor", ref), slog.String("host", dest.Hostname), slog.String("uri", inj.GetCredentialUri()),
					slog.String("provider", name), slog.String("serves", h.providerName))
				return nil, extproc.NewReqError(envoy_type.StatusCode_InternalServerError, deniedBody)
			}
		}

		resp, err := h.provider.FetchSecret(ctx, &credproviderpb.FetchSecretRequest{
			Uri:           inj.GetCredentialUri(),
			ActorSpiffeId: actorSpiffeID,
		})
		if err != nil {
			slog.ErrorContext(ctx, "egress denied: credential fetch failed",
				slog.Any("actor", ref), slog.String("host", dest.Hostname), slog.String("uri", inj.GetCredentialUri()), slog.Any("err", err))
			return nil, mapCredentialProviderError(err)
		}
		secret, err := sanitizeSecret(resp.GetOpaqueBytes())
		if err != nil {
			slog.ErrorContext(ctx, "egress denied: unusable credential",
				slog.Any("actor", ref), slog.String("host", dest.Hostname), slog.String("uri", inj.GetCredentialUri()), slog.Any("err", err))
			return nil, extproc.WrapReqError(envoy_type.StatusCode_ServiceUnavailable, err, deniedBody)
		}

		setHeaders = append(setHeaders, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: inj.GetHeader(), RawValue: append([]byte(inj.GetPrefix()), secret...)},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return setHeaders, nil
}

func (h *Handler) actorJWT(ctx context.Context, identity actorIncarnation, src *ateapipb.ActorJWTSource) (string, error) {
	audiences := src.GetAudiences()
	if len(audiences) == 0 || len(audiences) > 16 || src.GetExpirationSeconds() < 300 || src.GetExpirationSeconds() > 3600 {
		return "", fmt.Errorf("invalid actor JWT policy")
	}
	seen := make(map[string]bool, len(audiences))
	for _, audience := range audiences {
		if len(audience) == 0 || len(audience) > 512 || seen[audience] {
			return "", fmt.Errorf("invalid actor JWT audience")
		}
		seen[audience] = true
	}
	mintCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	resp, err := h.apiClient.MintActorJWT(mintCtx, &ateapipb.MintActorJWTRequest{
		Actor:             identity.Ref.ToObjectRef(),
		ExpectedActorUid:  identity.UID,
		Audience:          audiences,
		ExpirationSeconds: src.GetExpirationSeconds(),
	})
	if err != nil {
		return "", err
	}
	token := resp.GetActorJwt()
	clean, err := sanitizeSecret([]byte(token))
	if err != nil || len(clean) != len(token) {
		return "", fmt.Errorf("invalid actor JWT mint response")
	}
	return token, nil
}
