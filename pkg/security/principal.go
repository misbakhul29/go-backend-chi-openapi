package security

import (
	"context"

	"github.com/google/uuid"
)

type principalContextKey struct{}

type Principal struct {
	UserID      uuid.UUID
	TenantID    uuid.UUID
	SessionID   uuid.UUID
	JTI         string
	RolesHash   string
	AMR         []string
	Permissions []string
	Scopes      []string
}

// WithPrincipal menambahkan principal ke context
func WithPrincipal(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// PrincipalFromContext mengambil principal dari context
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(*Principal)
	return principal, ok
}

type auditContextKey struct{}

// WithAuditLogged menandai request telah diaudit di context
func WithAuditLogged(ctx context.Context) context.Context {
	return context.WithValue(ctx, auditContextKey{}, true)
}

// AuditLoggedFromContext mengecek apakah request telah diaudit dari context
func AuditLoggedFromContext(ctx context.Context) bool {
	val, ok := ctx.Value(auditContextKey{}).(bool)
	return ok && val
}
