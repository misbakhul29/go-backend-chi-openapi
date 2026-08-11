package security

import (
	"encoding/json"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

type SecurityScheme string

const (
	SecurityNone   SecurityScheme = "none"
	SecurityBearer SecurityScheme = "bearer"
)

type SecurityPolicy struct {
	Required bool           `json:"required"`
	Scheme   SecurityScheme `json:"scheme"`
}

type PermissionPolicy struct {
	Module   string `json:"module"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type OperationPolicy struct {
	OperationID string            `json:"operationId"`
	APIVersion  string            `json:"apiVersion"`
	Security    SecurityPolicy    `json:"security"`
	Permission  *PermissionPolicy `json:"permission"`
	DataScopes  []string          `json:"dataScopes"`
	Audit       AuditPolicy       `json:"audit"`
	StepUpMFA   StepUpMFAPolicy   `json:"stepUpMfa"`
}

type AuditPolicy struct {
	Required bool `json:"required"`
}

type StepUpMFAPolicy struct {
	Required bool `json:"required"`
}

type PolicyResolver struct {
	router routers.Router
}

func NewPolicyResolver(swagger *openapi3.T) (*PolicyResolver, error) {
	// Initialize gorillamux router which matches request URLs to Swagger paths and server URL prefixes
	router, err := gorillamux.NewRouter(swagger)
	if err != nil {
		return nil, err
	}
	return &PolicyResolver{router: router}, nil
}

func (pr *PolicyResolver) Resolve(r *http.Request) (OperationPolicy, bool) {
	route, _, err := pr.router.FindRoute(r)
	if err != nil {
		// Route not found in Swagger specification
		return OperationPolicy{}, false
	}

	operation := route.Operation

	// Determine if security is required
	securityRequired := false
	securityScheme := SecurityNone

	// Check if security requirements are defined at the operation level or globally
	securityRequirements := operation.Security
	if securityRequirements == nil {
		securityRequirements = &route.Spec.Security
	}

	if securityRequirements != nil {
		for _, req := range *securityRequirements {
			for schemeName := range req {
				if schemeName == "BearerAuth" {
					securityRequired = true
					securityScheme = SecurityBearer
				}
			}
		}
	}

	// Build the policy
	var apiVersion string
	if val, ok := operation.Extensions["x-api-version"].(string); ok {
		apiVersion = val
	}

	policy := OperationPolicy{
		OperationID: operation.OperationID,
		APIVersion:  apiVersion,
		Security: SecurityPolicy{
			Required: securityRequired,
			Scheme:   securityScheme,
		},
	}

	// Extract x-permission extension
	if ext, ok := operation.Extensions["x-permission"]; ok {
		if data, err := json.Marshal(ext); err == nil {
			var perm PermissionPolicy
			if err := json.Unmarshal(data, &perm); err == nil {
				policy.Permission = &perm
			}
		}
	}

	// Extract x-data-scopes extension
	if ext, ok := operation.Extensions["x-data-scopes"]; ok {
		if data, err := json.Marshal(ext); err == nil {
			var scopes []string
			if err := json.Unmarshal(data, &scopes); err == nil {
				policy.DataScopes = scopes
			}
		}
	}

	// Extract x-audit extension
	if ext, ok := operation.Extensions["x-audit"]; ok {
		if data, err := json.Marshal(ext); err == nil {
			// Can handle bool format: x-audit: true
			var auditBool bool
			if err := json.Unmarshal(data, &auditBool); err == nil {
				policy.Audit.Required = auditBool
			} else {
				// Or object format: x-audit: { required: true }
				_ = json.Unmarshal(data, &policy.Audit)
			}
		}
	}

	// Extract x-step-up-mfa extension
	if ext, ok := operation.Extensions["x-step-up-mfa"]; ok {
		if data, err := json.Marshal(ext); err == nil {
			var mfa StepUpMFAPolicy
			// Can handle bool format
			var mfaBool bool
			if err := json.Unmarshal(data, &mfaBool); err == nil {
				policy.StepUpMFA.Required = mfaBool
			} else {
				// Or object format
				_ = json.Unmarshal(data, &mfa)
				policy.StepUpMFA = mfa
			}
		}
	}

	return policy, true
}
