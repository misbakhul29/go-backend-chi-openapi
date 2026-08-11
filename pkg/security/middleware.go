package security

import (
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
