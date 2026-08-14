package security

// Centralized list of system permissions.
const (
	PermSystemDebugRead = "system:debug:read"
	PermAuthRoleUpdate  = "auth:role:update"
)

// RegisteredPermissions returns a slice of all valid system permissions.
var RegisteredPermissions = []string{
	PermSystemDebugRead,
	PermAuthRoleUpdate,
}
