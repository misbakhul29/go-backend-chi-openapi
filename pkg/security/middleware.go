package security

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/misbakhul29/backend-framework/pkg/httpx"
	"github.com/misbakhul29/backend-framework/pkg/observer"
	"github.com/redis/go-redis/v9"
)

type Middleware struct {
	jwtService     *JWTService
	policyResolver *PolicyResolver
	redisClient    *redis.Client
}

func NewMiddleware(jwtService *JWTService, policyResolver *PolicyResolver, redisClient *redis.Client) *Middleware {
	return &Middleware{
		jwtService:     jwtService,
		policyResolver: policyResolver,
		redisClient:    redisClient,
	}
}

func (m *Middleware) Security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy, ok := m.policyResolver.Resolve(r)

		if !ok {
			httpx.WriteError(w, r, httpx.ErrInternal)
			return
		}

		if !policy.Security.Required {
			next.ServeHTTP(w, r)
			return
		}

		switch policy.Security.Scheme {
		case SecurityBearer:
			m.handleBearerAuth(next, w, r, policy)
		default:
			httpx.WriteError(w, r, httpx.ErrInternal)
			return
		}
	})
}

func (m *Middleware) handleBearerAuth(next http.Handler, w http.ResponseWriter, r *http.Request, policy OperationPolicy) {
	token, err := extractBearerToken(r.Header.Get("Authorization"))

	if err != nil {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	principal, err := m.jwtService.Authenticate(
		r.Context(),
		token,
	)

	if err != nil {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	r = r.WithContext(WithPrincipal(r.Context(), principal))

	// 1. RBAC Permission Check
	if policy.Permission != nil {
		requiredPerm := fmt.Sprintf("%s:%s:%s", policy.Permission.Module, policy.Permission.Resource, policy.Permission.Action)
		hasPerm := false
		for _, p := range principal.Permissions {
			if p == requiredPerm {
				hasPerm = true
				break
			}
		}
		if !hasPerm {
			httpx.WriteError(w, r, httpx.ErrForbidden)
			return
		}
	}

	// 2. Data Scopes Check
	if len(policy.DataScopes) > 0 {
		hasScope := false
		for _, reqScope := range policy.DataScopes {
			for _, s := range principal.Scopes {
				if s == reqScope {
					hasScope = true
					break
				}
			}
			if hasScope {
				break
			}
		}
		if !hasScope {
			httpx.WriteError(w, r, httpx.ErrForbidden)
			return
		}
	}

	// 3. Step-Up MFA Check
	if policy.StepUpMFA.Required {
		hasMFA := false
		for _, method := range principal.AMR {
			if method == "mfa" {
				hasMFA = true
				break
			}
		}
		if !hasMFA {
			httpx.WriteError(w, r, httpx.ErrMfaRequired)
			return
		}
	}

	next.ServeHTTP(w, r)
}

func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy, ok := m.policyResolver.Resolve(r)

		limit := 60
		window := 60
		operationID := "default"

		if ok {
			if policy.OperationID != "" {
				operationID = policy.OperationID
			}
			if policy.RateLimit != nil {
				limit = policy.RateLimit.Limit
				window = policy.RateLimit.Window
			}
		} else {
			operationID = r.URL.Path
		}

		if m.redisClient == nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		ip := getClientIP(r)
		redisKey := fmt.Sprintf("ratelimit:%s:%s", ip, operationID)

		pipe := m.redisClient.Pipeline()
		incr := pipe.Incr(ctx, redisKey)
		pipe.TTL(ctx, redisKey)
		_, err := pipe.Exec(ctx)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		count := incr.Val()
		if count == 1 {
			m.redisClient.Expire(ctx, redisKey, time.Duration(window)*time.Second)
		}

		if count > int64(limit) {
			w.Header().Set("Retry-After", strconv.Itoa(window))
			httpx.WriteError(w, r, httpx.ErrRateLimitExceeded)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) Audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy, ok := m.policyResolver.Resolve(r)
		if !ok || !policy.Audit.Required {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		var userIDStr string
		var tenantIDStr string

		if principal, ok := PrincipalFromContext(ctx); ok {
			userIDStr = principal.UserID.String()
			tenantIDStr = principal.TenantID.String()
		}

		observer.Log.InfoContext(ctx, "Crucial endpoint accessed",
			slog.String("operation_id", policy.OperationID),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("user_id", userIDStr),
			slog.String("tenant_id", tenantIDStr),
			slog.String("remote_ip", getClientIP(r)),
		)

		r = r.WithContext(WithAuditLogged(ctx))
		next.ServeHTTP(w, r)
	})
}

func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}
