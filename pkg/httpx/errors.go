package httpx

import (
	"errors"
	"fmt"

	"github.com/misbakhul29/backend-framework/pkg/errs"
)

// APIError defines the interface for errors that carry API metadata.
type APIError interface {
	error
	APIErrorCode() string
	APIMessageKey() string
	HTTPStatusCode() int
	APIDetails() map[string]any
	Unwrap() error
}

type apiErrorImpl struct {
	err        error
	code       string
	messageKey string
	statusCode int
	details    map[string]any
}

func (e *apiErrorImpl) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s: %v", e.messageKey, e.err)
	}
	return e.messageKey
}

func (e *apiErrorImpl) APIErrorCode() string       { return e.code }
func (e *apiErrorImpl) APIMessageKey() string      { return e.messageKey }
func (e *apiErrorImpl) HTTPStatusCode() int        { return e.statusCode }
func (e *apiErrorImpl) APIDetails() map[string]any { return e.details }
func (e *apiErrorImpl) Unwrap() error              { return e.err }

// NewAPIError creates a new APIError with details.
func NewAPIError(statusCode int, code string, messageKey string, err error) APIError {
	return &apiErrorImpl{
		err:        err,
		code:       code,
		messageKey: messageKey,
		statusCode: statusCode,
	}
}

// NewAPIErrorWithDetails creates a new APIError with details.
func NewAPIErrorWithDetails(statusCode int, code string, messageKey string, details map[string]any, err error) APIError {
	return &apiErrorImpl{
		err:        err,
		code:       code,
		messageKey: messageKey,
		statusCode: statusCode,
		details:    details,
	}
}

// Sentinel HTTP errors as requested by B-01.
var (
	// Standard HTTP Errors
	ErrNotFound = &apiErrorImpl{
		code:       string(errs.ErrCodeNotFound),
		messageKey: string(errs.ErrCodeNotFound),
		statusCode: 404,
	}
	ErrValidation = &apiErrorImpl{
		code:       string(errs.ErrCodeValidation),
		messageKey: string(errs.ErrCodeValidation),
		statusCode: 400,
	}
	ErrForbidden = &apiErrorImpl{
		code:       string(errs.ErrCodeForbidden),
		messageKey: string(errs.ErrCodeForbidden),
		statusCode: 403,
	}
	ErrConflict = &apiErrorImpl{
		code:       string(errs.ErrCodeConflict),
		messageKey: string(errs.ErrCodeConflict),
		statusCode: 409,
	}
	ErrUnauthorized = &apiErrorImpl{
		code:       string(errs.ErrCodeUnauthorized),
		messageKey: string(errs.ErrCodeUnauthorized),
		statusCode: 401,
	}
	ErrInternal = &apiErrorImpl{
		code:       string(errs.ErrCodeInternalError),
		messageKey: string(errs.ErrCodeInternalError),
		statusCode: 500,
	}
	ErrBadRequest = &apiErrorImpl{
		code:       string(errs.ErrCodeBadRequest),
		messageKey: string(errs.ErrCodeBadRequest),
		statusCode: 400,
	}
	ErrAccountLocked = &apiErrorImpl{
		code:       string(errs.ErrCodeAccountLocked),
		messageKey: string(errs.ErrCodeAccountLocked),
		statusCode: 423,
	}

	// System & Common
	ErrModuleDisabled = &apiErrorImpl{
		code:       string(errs.ErrCodeModuleDisabled),
		messageKey: string(errs.ErrCodeModuleDisabled),
		statusCode: 403,
	}
	ErrTenantSuspended = &apiErrorImpl{
		code:       string(errs.ErrCodeTenantSuspended),
		messageKey: string(errs.ErrCodeTenantSuspended),
		statusCode: 403,
	}
	ErrMfaRequired = &apiErrorImpl{
		code:       string(errs.ErrCodeMfaRequired),
		messageKey: string(errs.ErrCodeMfaRequired),
		statusCode: 403,
	}
	ErrRequestTimeout = &apiErrorImpl{
		code:       string(errs.ErrCodeRequestTimeout),
		messageKey: string(errs.ErrCodeRequestTimeout),
		statusCode: 408,
	}
	ErrServiceUnavailable = &apiErrorImpl{
		code:       string(errs.ErrCodeServiceUnavailable),
		messageKey: string(errs.ErrCodeServiceUnavailable),
		statusCode: 503,
	}
	ErrRateLimitExceeded = &apiErrorImpl{
		code:       string(errs.ErrCodeRateLimitExceeded),
		messageKey: string(errs.ErrCodeRateLimitExceeded),
		statusCode: 429,
	}

	// Organization Module
	ErrCycleDetected = &apiErrorImpl{
		code:       string(errs.ErrCodeCycleDetected),
		messageKey: string(errs.ErrCodeCycleDetected),
		statusCode: 400,
	}
	ErrResourceInUse = &apiErrorImpl{
		code:       string(errs.ErrCodeResourceInUse),
		messageKey: string(errs.ErrCodeResourceInUse),
		statusCode: 409,
	}
	ErrInvalidParent = &apiErrorImpl{
		code:       string(errs.ErrCodeInvalidParent),
		messageKey: string(errs.ErrCodeInvalidParent),
		statusCode: 400,
	}
	ErrInvalidJSON = &apiErrorImpl{
		code:       string(errs.ErrCodeInvalidJSON),
		messageKey: string(errs.ErrCodeInvalidJSON),
		statusCode: 400,
	}
	ErrOverlappingSchedule = &apiErrorImpl{
		code:       string(errs.ErrCodeOverlappingSchedule),
		messageKey: string(errs.ErrCodeOverlappingSchedule),
		statusCode: 409,
	}
	ErrInvalidCoordinates = &apiErrorImpl{
		code:       string(errs.ErrCodeInvalidCoordinates),
		messageKey: string(errs.ErrCodeInvalidCoordinates),
		statusCode: 400,
	}
	ErrInvalidRadius = &apiErrorImpl{
		code:       string(errs.ErrCodeInvalidRadius),
		messageKey: string(errs.ErrCodeInvalidRadius),
		statusCode: 400,
	}
	ErrCalendarNotFound = &apiErrorImpl{
		code:       string(errs.ErrCodeCalendarNotFound),
		messageKey: string(errs.ErrCodeCalendarNotFound),
		statusCode: 404,
	}
	ErrInvalidCSVFormat = &apiErrorImpl{
		code:       string(errs.ErrCodeInvalidCSVFormat),
		messageKey: string(errs.ErrCodeInvalidCSVFormat),
		statusCode: 400,
	}

	// Auth & Identity
	ErrLegacyPasswordResetRequired = &apiErrorImpl{
		code:       string(errs.ErrCodeLegacyPasswordResetRequired),
		messageKey: string(errs.ErrCodeLegacyPasswordResetRequired),
		statusCode: 403,
	}
	ErrMfaEnrollRequired = &apiErrorImpl{
		code:       string(errs.ErrCodeMfaEnrollRequired),
		messageKey: string(errs.ErrCodeMfaEnrollRequired),
		statusCode: 403,
	}
	ErrInvalidCredentials = &apiErrorImpl{
		code:       string(errs.ErrCodeInvalidCredentials),
		messageKey: string(errs.ErrCodeInvalidCredentials),
		statusCode: 401,
	}
	ErrTokenReuseDetected = &apiErrorImpl{
		code:       string(errs.ErrCodeTokenReuseDetected),
		messageKey: string(errs.ErrCodeTokenReuseDetected),
		statusCode: 401,
	}
	ErrDeviceRevoked = &apiErrorImpl{
		code:       string(errs.ErrCodeDeviceRevoked),
		messageKey: string(errs.ErrCodeDeviceRevoked),
		statusCode: 401,
	}
	ErrInvalidMfaTicket = &apiErrorImpl{
		code:       string(errs.ErrCodeInvalidMfaTicket),
		messageKey: string(errs.ErrCodeInvalidMfaTicket),
		statusCode: 401,
	}
	ErrInvalidMfaCode = &apiErrorImpl{
		code:       string(errs.ErrCodeInvalidMfaCode),
		messageKey: string(errs.ErrCodeInvalidMfaCode),
		statusCode: 400,
	}
	ErrMfaSetupFailed = &apiErrorImpl{
		code:       string(errs.ErrCodeMfaSetupFailed),
		messageKey: string(errs.ErrCodeMfaSetupFailed),
		statusCode: 400,
	}
	ErrMfaEnableFailed = &apiErrorImpl{
		code:       string(errs.ErrCodeMfaEnableFailed),
		messageKey: string(errs.ErrCodeMfaEnableFailed),
		statusCode: 400,
	}
	ErrMfaVerifyFailed = &apiErrorImpl{
		code:       string(errs.ErrCodeMfaVerifyFailed),
		messageKey: string(errs.ErrCodeMfaVerifyFailed),
		statusCode: 400,
	}
	ErrMfaDisableFailed = &apiErrorImpl{
		code:       string(errs.ErrCodeMfaDisableFailed),
		messageKey: string(errs.ErrCodeMfaDisableFailed),
		statusCode: 400,
	}
	ErrForgotPasswordFailed = &apiErrorImpl{
		code:       string(errs.ErrCodeForgotPasswordFailed),
		messageKey: string(errs.ErrCodeForgotPasswordFailed),
		statusCode: 400,
	}
	ErrResetPasswordFailed = &apiErrorImpl{
		code:       string(errs.ErrCodeResetPasswordFailed),
		messageKey: string(errs.ErrCodeResetPasswordFailed),
		statusCode: 400,
	}
	ErrChangePasswordFailed = &apiErrorImpl{
		code:       string(errs.ErrCodeChangePasswordFailed),
		messageKey: string(errs.ErrCodeChangePasswordFailed),
		statusCode: 400,
	}
	ErrRevokeDeviceFailed = &apiErrorImpl{
		code:       string(errs.ErrCodeRevokeDeviceFailed),
		messageKey: string(errs.ErrCodeRevokeDeviceFailed),
		statusCode: 400,
	}

	// Generic Fallbacks
	ErrExclusionViolation = &apiErrorImpl{
		code:       string(errs.ErrCodeExclusionViolation),
		messageKey: string(errs.ErrCodeExclusionViolation),
		statusCode: 409,
	}
	ErrStringTooLong = &apiErrorImpl{
		code:       string(errs.ErrCodeStringTooLong),
		messageKey: string(errs.ErrCodeStringTooLong),
		statusCode: 400,
	}
	ErrNumericOutOfRange = &apiErrorImpl{
		code:       string(errs.ErrCodeNumericOutOfRange),
		messageKey: string(errs.ErrCodeNumericOutOfRange),
		statusCode: 400,
	}
	ErrInvalidFormat = &apiErrorImpl{
		code:       string(errs.ErrCodeInvalidFormat),
		messageKey: string(errs.ErrCodeInvalidFormat),
		statusCode: 400,
	}
	ErrDivisionByZero = &apiErrorImpl{
		code:       string(errs.ErrCodeDivisionByZero),
		messageKey: string(errs.ErrCodeDivisionByZero),
		statusCode: 400,
	}
	ErrDatetimeOverflow = &apiErrorImpl{
		code:       string(errs.ErrCodeDatetimeOverflow),
		messageKey: string(errs.ErrCodeDatetimeOverflow),
		statusCode: 400,
	}
	ErrDeadlock = &apiErrorImpl{
		code:       string(errs.ErrCodeDeadlock),
		messageKey: string(errs.ErrCodeDeadlock),
		statusCode: 409,
	}
	ErrFkReferenced = &apiErrorImpl{
		code:       string(errs.ErrCodeFkReferenced),
		messageKey: string(errs.ErrCodeFkReferenced),
		statusCode: 409,
	}
	ErrFkNotFound = &apiErrorImpl{
		code:       string(errs.ErrCodeFkNotFound),
		messageKey: string(errs.ErrCodeFkNotFound),
		statusCode: 400,
	}
	ErrNotNullViolation = &apiErrorImpl{
		code:       string(errs.ErrCodeNotNullViolation),
		messageKey: string(errs.ErrCodeNotNullViolation),
		statusCode: 400,
	}
	ErrCheckViolation = &apiErrorImpl{
		code:       string(errs.ErrCodeCheckViolation),
		messageKey: string(errs.ErrCodeCheckViolation),
		statusCode: 400,
	}
	ErrDuplicateGeneric = &apiErrorImpl{
		code:       string(errs.ErrCodeDuplicateGeneric),
		messageKey: string(errs.ErrCodeDuplicateGeneric),
		statusCode: 409,
	}
	ErrDatabaseError = &apiErrorImpl{
		code:       string(errs.ErrCodeDatabaseError),
		messageKey: string(errs.ErrCodeDatabaseError),
		statusCode: 500,
	}
)

// WithDetails returns a copy of the APIError with the specified details.
func ErrorWithDetails(err APIError, details map[string]any) APIError {
	return &apiErrorImpl{
		err:        err.Unwrap(),
		code:       err.APIErrorCode(),
		messageKey: err.APIMessageKey(),
		statusCode: err.HTTPStatusCode(),
		details:    details,
	}
}

// IsAPIError checks if an error implements APIError.
func IsAPIError(err error) bool {
	var apiErr APIError
	return errors.As(err, &apiErr)
}

// AsAPIError extracts APIError from error chain.
func AsAPIError(err error) (APIError, bool) {
	var apiErr APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}
