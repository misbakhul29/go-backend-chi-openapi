package security

import (
	"fmt"
	"net/http"
	"strconv"
)

type Middleware struct {
	jwtService     *JWTService
	policyResolver *PolicyResolver
}

func NewMiddleware(jwtService *JWTService, policyResolver *PolicyResolver) *Middleware {
	return &Middleware{
		jwtService:     jwtService,
		policyResolver: policyResolver,
	}
}

func (m *Middleware) Security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy, ok := m.policyResolver.Resolve(r)

		if !ok {
			writeProblem(
				w,
				http.StatusInternalServerError,
				"SECURITY_POLICY_MISSING",
			)
			return
		}

		if !policy.Security.Required {
			// Even if security is not required, let's still run audit checks if x-audit is configured
			if policy.Audit.Required {
				fmt.Printf("[AUDIT] Public endpoint accessed: %s %s (Operation: %s)\n", r.Method, r.URL.Path, policy.OperationID)
				r = r.WithContext(WithAuditLogged(r.Context()))
			}
			next.ServeHTTP(w, r)
			return
		}

		switch policy.Security.Scheme {
		case SecurityBearer:
			m.handleBearerAuth(next, w, r, policy)
		default:
			writeProblem(
				w,
				http.StatusInternalServerError,
				"UNSUPPORTED_SECURITY_SCHEME",
			)
			return
		}
	})
}

func (m *Middleware) handleBearerAuth(next http.Handler, w http.ResponseWriter, r *http.Request, policy OperationPolicy) {
	token, err := extractBearerToken(r.Header.Get("Authorization"))

	if err != nil {
		writeProblem(
			w,
			http.StatusUnauthorized,
			"UNAUTHORIZED",
		)
		return
	}

	principal, err := m.jwtService.Authenticate(
		r.Context(),
		token,
	)

	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "UNAUTHORIZED")
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
			writeProblem(w, http.StatusForbidden, "FORBIDDEN_INSUFFICIENT_PERMISSIONS")
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
			writeProblem(w, http.StatusForbidden, "FORBIDDEN_INSUFFICIENT_SCOPES")
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
			writeProblem(w, http.StatusForbidden, "MFA_REQUIRED")
			return
		}
	}

	// 4. Audit Logging Check
	if policy.Audit.Required {
		fmt.Printf("[AUDIT] Authenticated endpoint accessed: %s %s (User: %s, Operation: %s)\n", r.Method, r.URL.Path, principal.UserID, policy.OperationID)
		r = r.WithContext(WithAuditLogged(r.Context()))
	}

	next.ServeHTTP(w, r)
}

func writeProblem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")

	w.WriteHeader(status)

	w.Write([]byte(`{
		"type": "about:blank",
		"title": "` + code + `",
		"status": "` + strconv.Itoa(status) + `"
	}`))
}
