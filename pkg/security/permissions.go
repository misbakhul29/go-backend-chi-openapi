package security

// Centralized list of permissions.
// You can easily add, remove, or modify permissions here.
const (
	PermAuthMeRead = "auth:me:read"
	PermStatusRead = "status:all:read"
	// Example permissions:
	PermUserCreate = "user:all:create"
	PermUserDelete = "user:all:delete"
)

// RegisteredPermissions returns a slice of all valid system permissions.
var RegisteredPermissions = []string{
	PermAuthMeRead,
	PermStatusRead,
	PermUserCreate,
	PermUserDelete,
}
