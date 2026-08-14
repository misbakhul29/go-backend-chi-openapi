package errs

// DomainError represents a business/domain-level error that occurred.
// It contains a machine-readable code, developer/user-friendly message,
// and optional metadata details for debugging or structured responses.
type DomainError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func (e *DomainError) Error() string {
	return e.Message
}

// NewDomainError constructs a new DomainError instance.
func NewDomainError(code string, message string, details map[string]any) *DomainError {
	return &DomainError{
		Code:    code,
		Message: message,
		Details: details,
	}
}
