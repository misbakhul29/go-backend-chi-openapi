package errs

type ErrorCode string

const (
	// Common & System
	ErrCodeInternalError      ErrorCode = "INTERNAL_ERROR"
	ErrCodeBadRequest         ErrorCode = "BAD_REQUEST"
	ErrCodeUnauthorized       ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden          ErrorCode = "FORBIDDEN"
	ErrCodeModuleDisabled     ErrorCode = "MODULE_DISABLED"
	ErrCodeTenantSuspended    ErrorCode = "TENANT_SUSPENDED"
	ErrCodeMfaRequired        ErrorCode = "MFA_REQUIRED"
	ErrCodeNotFound           ErrorCode = "NOT_FOUND"
	ErrCodeConflict           ErrorCode = "CONFLICT"
	ErrCodeValidation         ErrorCode = "VALIDATION_FAILED"
	ErrCodeRequestTimeout     ErrorCode = "REQUEST_TIMEOUT"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeRateLimitExceeded  ErrorCode = "RATE_LIMIT_EXCEEDED"

	// Organization Module
	ErrCodeCycleDetected       ErrorCode = "CYCLE_DETECTED"
	ErrCodeResourceInUse       ErrorCode = "RESOURCE_IN_USE"
	ErrCodeInvalidParent       ErrorCode = "INVALID_PARENT"
	ErrCodeInvalidJSON         ErrorCode = "INVALID_JSON"
	ErrCodeOverlappingSchedule ErrorCode = "OVERLAPPING_SCHEDULE"
	ErrCodeInvalidCoordinates  ErrorCode = "INVALID_COORDINATES"
	ErrCodeInvalidRadius       ErrorCode = "INVALID_RADIUS"
	ErrCodeCalendarNotFound    ErrorCode = "CALENDAR_NOT_FOUND"
	ErrCodeInvalidCSVFormat    ErrorCode = "INVALID_CSV_FORMAT"

	// Auth & Identity
	ErrCodeAccountLocked               ErrorCode = "ACCOUNT_LOCKED"
	ErrCodeLegacyPasswordResetRequired ErrorCode = "LEGACY_PASSWORD_RESET_REQUIRED"
	ErrCodeMfaEnrollRequired           ErrorCode = "MFA_ENROLL_REQUIRED"
	ErrCodeInvalidCredentials          ErrorCode = "INVALID_CREDENTIALS"
	ErrCodeTokenReuseDetected          ErrorCode = "TOKEN_REUSE_DETECTED"
	ErrCodeDeviceRevoked               ErrorCode = "DEVICE_REVOKED"
	ErrCodeInvalidMfaTicket            ErrorCode = "INVALID_MFA_TICKET"
	ErrCodeInvalidMfaCode              ErrorCode = "INVALID_MFA_CODE"
	ErrCodeMfaSetupFailed              ErrorCode = "MFA_SETUP_FAILED"
	ErrCodeMfaEnableFailed             ErrorCode = "MFA_ENABLE_FAILED"
	ErrCodeMfaVerifyFailed             ErrorCode = "MFA_VERIFY_FAILED"
	ErrCodeMfaDisableFailed            ErrorCode = "MFA_DISABLE_FAILED"
	ErrCodeForgotPasswordFailed        ErrorCode = "FORGOT_PASSWORD_FAILED"
	ErrCodeResetPasswordFailed         ErrorCode = "RESET_PASSWORD_FAILED"
	ErrCodeChangePasswordFailed        ErrorCode = "CHANGE_PASSWORD_FAILED"
	ErrCodeRevokeDeviceFailed          ErrorCode = "REVOKE_DEVICE_FAILED"
	ErrCodeInvalidRefreshToken         ErrorCode = "INVALID_REFRESH_TOKEN"
	ErrCodeInvalidToken                ErrorCode = "INVALID_TOKEN"

	// Database Integrity Constraints
	ErrCodeDbUsersEmailKey                   ErrorCode = "users_email_key"
	ErrCodeDbUsersTenantIdEmailKey           ErrorCode = "users_tenant_id_email_key"
	ErrCodeDbUserDevicesUserIdDeviceCodeKey  ErrorCode = "user_devices_user_id_device_code_key"
	ErrCodeDbRefreshTokensTokenHashKey       ErrorCode = "refresh_tokens_token_hash_key"
	ErrCodeDbTenantsSlugKey                  ErrorCode = "tenants_slug_key"
	ErrCodeDbTenantsDomainKey                ErrorCode = "tenants_domain_key"
	ErrCodeDbDepartmentsTenantIdCodeKey      ErrorCode = "departments_tenant_id_code_key"
	ErrCodeDbLocationsTenantIdCodeKey        ErrorCode = "locations_tenant_id_code_key"
	ErrCodeDbPositionsTenantIdCodeKey        ErrorCode = "positions_tenant_id_code_key"
	ErrCodeDbJobsTenantIdCodeKey             ErrorCode = "jobs_tenant_id_code_key"
	ErrCodeDbLegalEntitiesTenantIdCodeKey    ErrorCode = "legal_entities_tenant_id_code_key"
	ErrCodeDbCostCentersTenantIdCodeKey      ErrorCode = "cost_centers_tenant_id_code_key"
	ErrCodeDbEmployeesTenantIdEmpNumKey      ErrorCode = "employees_tenant_id_employee_number_key"
	ErrCodeDbEmployeesTenantIdNikKey         ErrorCode = "employees_tenant_id_nik_key"
	ErrCodeDbLeaveTypesTenantIdCodeKey       ErrorCode = "leave_types_tenant_id_code_key"
	ErrCodeDbSalaryComponentsTenantIdCodeKey ErrorCode = "salary_components_tenant_id_code_key"

	// Foreign Keys
	ErrCodeFkEmployeesDeptId      ErrorCode = "employees_department_id_fkey"
	ErrCodeFkEmployeesPosId       ErrorCode = "employees_position_id_fkey"
	ErrCodeFkEmployeesLocId       ErrorCode = "employees_location_id_fkey"
	ErrCodeFkEmployeesJobId       ErrorCode = "employees_job_id_fkey"
	ErrCodeFkEmployeesReportingTo ErrorCode = "employees_reporting_to_fkey"
	ErrCodeFkUserRolesRoleId      ErrorCode = "user_roles_role_id_fkey"
	ErrCodeFkUserRolesUserId      ErrorCode = "user_roles_user_id_fkey"
	ErrCodeFkLeaveRequestsType    ErrorCode = "leave_requests_leave_type_fkey"

	// Generic Fallbacks
	ErrCodeExclusionViolation ErrorCode = "EXCLUSION_VIOLATION"
	ErrCodeStringTooLong      ErrorCode = "STRING_TOO_LONG"
	ErrCodeNumericOutOfRange  ErrorCode = "NUMERIC_OUT_OF_RANGE"
	ErrCodeInvalidFormat      ErrorCode = "INVALID_FORMAT"
	ErrCodeDivisionByZero     ErrorCode = "DIVISION_BY_ZERO"
	ErrCodeDatetimeOverflow   ErrorCode = "DATETIME_OVERFLOW"
	ErrCodeDeadlock           ErrorCode = "DEADLOCK"
	ErrCodeFkReferenced       ErrorCode = "FOREIGN_KEY_REFERENCED"
	ErrCodeFkNotFound         ErrorCode = "FOREIGN_KEY_NOT_FOUND"
	ErrCodeNotNullViolation   ErrorCode = "NOT_NULL_VIOLATION"
	ErrCodeCheckViolation     ErrorCode = "CHECK_VIOLATION"
	ErrCodeDuplicateGeneric   ErrorCode = "DUPLICATE_GENERIC"
	ErrCodeDatabaseError      ErrorCode = "DATABASE_ERROR"
)

type MessageCode string

const (
	MsgTenantRegisterSuccess MessageCode = "MSG_TENANT_REGISTER_SUCCESS"
	MsgLoggedOutSuccess      MessageCode = "MSG_LOGGED_OUT_SUCCESS"
	MsgLoggedOutAllSuccess   MessageCode = "MSG_LOGGED_OUT_ALL_SUCCESS"
	MsgForgotPasswordSent    MessageCode = "MSG_FORGOT_PASSWORD_SENT"
	MsgPasswordResetSuccess  MessageCode = "MSG_PASSWORD_SUCCESS"
)
