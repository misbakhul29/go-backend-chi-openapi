package db

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/misbakhul29/backend-framework/pkg/errs"
)

// PostgreSQL SQLSTATE codes
// Reference: https://www.postgresql.org/docs/current/errcodes-appendix.html
const (
	// Class 23 — Integrity Constraint Violation
	PGUniqueViolation     = "23505"
	PGForeignKeyViolation = "23503"
	PGNotNullViolation    = "23502"
	PGCheckViolation      = "23514"
	PGExclusionViolation  = "23P01"

	// Class 22 — Data Exception
	PGDataException       = "22000"
	PGStringDataTooLong   = "22001"
	PGNumericOutOfRange   = "22003"
	PGInvalidTextRepr     = "22P02"
	PGInvalidByteSequence = "22021"
	PGDivisionByZero      = "22012"
	PGDatetimeOverflow    = "22008"

	// Class 42 — Syntax Error or Access Rule Violation
	PGUndefinedTable  = "42P01"
	PGUndefinedColumn = "42703"

	// Class 40 — Transaction Rollback
	PGDeadlockDetected  = "40P01"
	PGSerializationFail = "40001"

	// Class 57 — Operator Intervention
	PGQueryCanceled = "57014"
	PGAdminShutdown = "57P01"

	// Class 53 — Insufficient Resources
	PGDiskFull           = "53100"
	PGOutOfMemory        = "53200"
	PGTooManyConnections = "53300"
)

// DBError is a translated database error safe to expose to clients.
// It wraps the original error for logging while providing a clean user message.
type DBError struct {
	// Original is the raw database error (for logging, never expose to client)
	Original error
	// Code is a machine-stable SCREAMING_SNAKE error code for the client
	Code string
	// MessageKey is the i18n translation key
	MessageKey string
	// Message is the fallback human-friendly message
	Message string
	// HTTPStatus is the suggested HTTP status code
	HTTPStatus int
	// SQLState is the PostgreSQL SQLSTATE code (for diagnostics)
	SQLState string
	// Constraint is the constraint name if available
	Constraint string
	// Column is the column name if available
	Column string
	// Table is the table name if available
	Table string
	// Detail is the PG detail string if available (for logging only)
	Detail string
}

func (e *DBError) Error() string {
	return e.Message
}

func (e *DBError) Unwrap() error {
	return e.Original
}

// Localize returns the localized error message using the given language.
func (e *DBError) Localize(lang errs.Language) string {
	if e.MessageKey != "" {
		if msg := errs.T(e.MessageKey, lang); msg != e.MessageKey {
			return msg
		}
	}
	if e.Constraint != "" {
		if msg := errs.T(e.Constraint, lang); msg != e.Constraint {
			return msg
		}
	}
	if e.Message != "" {
		return e.Message
	}
	return errs.T("DATABASE_ERROR", lang)
}

// IsDBError checks if an error is a translated DBError.
func IsDBError(err error) bool {
	var dbErr *DBError
	return errors.As(err, &dbErr)
}

// AsDBError extracts a DBError from an error chain.
func AsDBError(err error) (*DBError, bool) {
	if dbErr, ok := errors.AsType[*DBError](err); ok {
		return dbErr, true
	}
	return nil, false
}

// TranslateError converts a raw database/GORM error into a user-friendly DBError.
func TranslateError(err error) error {
	if err == nil {
		return nil
	}

	// Already translated
	if IsDBError(err) {
		return err
	}

	// Check for GORM-specific errors first
	if errors.Is(err, errors.New("record not found")) {
		return &DBError{
			Original:   err,
			Code:       "NOT_FOUND",
			MessageKey: "NOT_FOUND",
			Message:    errs.T("NOT_FOUND", errs.DefaultLanguage),
			HTTPStatus: 404,
		}
	}

	// Extract pgconn.PgError
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return &DBError{
			Original:   err,
			Code:       "INTERNAL_ERROR",
			MessageKey: "INTERNAL_ERROR",
			Message:    errs.T("INTERNAL_ERROR", errs.DefaultLanguage),
			HTTPStatus: 500,
		}
	}

	// Translate based on SQLSTATE
	dbErr := &DBError{
		Original:   err,
		SQLState:   pgErr.Code,
		Constraint: pgErr.ConstraintName,
		Column:     pgErr.ColumnName,
		Table:      pgErr.TableName,
		Detail:     pgErr.Detail,
	}

	switch pgErr.Code {
	// ── Integrity Constraint Violations (Class 23) ──────────────────────
	case PGUniqueViolation:
		dbErr.Code = "DUPLICATE"
		dbErr.HTTPStatus = 409
		dbErr.MessageKey, dbErr.Message = translateUniqueViolation(pgErr)

	case PGForeignKeyViolation:
		dbErr.Code = "REFERENCE_ERROR"
		dbErr.HTTPStatus = 409
		dbErr.MessageKey, dbErr.Message = translateForeignKeyViolation(pgErr)

	case PGNotNullViolation:
		dbErr.Code = "VALIDATION_FAILED"
		dbErr.HTTPStatus = 400
		dbErr.MessageKey, dbErr.Message = translateNotNullViolation(pgErr)

	case PGCheckViolation:
		dbErr.Code = "VALIDATION_FAILED"
		dbErr.HTTPStatus = 400
		dbErr.MessageKey = "CHECK_VIOLATION"
		dbErr.Message = errs.T("CHECK_VIOLATION", errs.DefaultLanguage)

	case PGExclusionViolation:
		dbErr.Code = "OVERLAPPING_EFFECTIVE_PERIOD"
		dbErr.HTTPStatus = 409
		dbErr.MessageKey = "EXCLUSION_VIOLATION"
		dbErr.Message = errs.T("EXCLUSION_VIOLATION", errs.DefaultLanguage)

	// ── Data Exceptions (Class 22) ──────────────────────────────────────
	case PGStringDataTooLong:
		dbErr.Code = "VALIDATION_FAILED"
		dbErr.HTTPStatus = 400
		dbErr.MessageKey = "STRING_TOO_LONG"
		dbErr.Message = errs.T("STRING_TOO_LONG", errs.DefaultLanguage)

	case PGNumericOutOfRange:
		dbErr.Code = "VALIDATION_FAILED"
		dbErr.HTTPStatus = 400
		dbErr.MessageKey = "NUMERIC_OUT_OF_RANGE"
		dbErr.Message = errs.T("NUMERIC_OUT_OF_RANGE", errs.DefaultLanguage)

	case PGInvalidTextRepr, PGInvalidByteSequence:
		dbErr.Code = "VALIDATION_FAILED"
		dbErr.HTTPStatus = 400
		dbErr.MessageKey = "INVALID_FORMAT"
		dbErr.Message = errs.T("INVALID_FORMAT", errs.DefaultLanguage)

	case PGDivisionByZero:
		dbErr.Code = "CALCULATION_ERROR"
		dbErr.HTTPStatus = 400
		dbErr.MessageKey = "DIVISION_BY_ZERO"
		dbErr.Message = errs.T("DIVISION_BY_ZERO", errs.DefaultLanguage)

	case PGDatetimeOverflow:
		dbErr.Code = "VALIDATION_FAILED"
		dbErr.HTTPStatus = 400
		dbErr.MessageKey = "DATETIME_OVERFLOW"
		dbErr.Message = errs.T("DATETIME_OVERFLOW", errs.DefaultLanguage)

	// ── Transaction Rollback (Class 40) ─────────────────────────────────
	case PGDeadlockDetected, PGSerializationFail:
		dbErr.Code = "CONFLICT"
		dbErr.HTTPStatus = 409
		dbErr.MessageKey = "DEADLOCK"
		dbErr.Message = errs.T("DEADLOCK", errs.DefaultLanguage)

	// ── Operator Intervention (Class 57) ────────────────────────────────
	case PGQueryCanceled:
		dbErr.Code = "REQUEST_TIMEOUT"
		dbErr.HTTPStatus = 504
		dbErr.MessageKey = "REQUEST_TIMEOUT"
		dbErr.Message = errs.T("REQUEST_TIMEOUT", errs.DefaultLanguage)

	// ── Insufficient Resources (Class 53) ───────────────────────────────
	case PGTooManyConnections:
		dbErr.Code = "SERVICE_UNAVAILABLE"
		dbErr.HTTPStatus = 503
		dbErr.MessageKey = "SERVICE_UNAVAILABLE"
		dbErr.Message = errs.T("SERVICE_UNAVAILABLE", errs.DefaultLanguage)

	// ── Default: any other SQLSTATE ─────────────────────────────────────
	default:
		dbErr.Code = "DATABASE_ERROR"
		dbErr.HTTPStatus = 500
		dbErr.MessageKey = "DATABASE_ERROR"
		dbErr.Message = errs.T("DATABASE_ERROR", errs.DefaultLanguage)
	}

	return dbErr
}

func translateUniqueViolation(pgErr *pgconn.PgError) (string, string) {
	if pgErr.ConstraintName != "" {
		if msg := errs.T(pgErr.ConstraintName, errs.DefaultLanguage); msg != pgErr.ConstraintName {
			return pgErr.ConstraintName, msg
		}

		parts := strings.Split(pgErr.ConstraintName, "_")
		if len(parts) >= 2 {
			col := parts[len(parts)-2]
			return "ALREADY_USED", errs.TWithLabel("ALREADY_USED", col, errs.DefaultLanguage)
		}
	}

	if pgErr.Detail != "" {
		if field := extractFieldFromDetail(pgErr.Detail); field != "" {
			return "ALREADY_USED", errs.TWithLabel("ALREADY_USED", field, errs.DefaultLanguage)
		}
	}

	return "DUPLICATE_GENERIC", errs.T("DUPLICATE_GENERIC", errs.DefaultLanguage)
}

func translateForeignKeyViolation(pgErr *pgconn.PgError) (string, string) {
	if pgErr.ConstraintName != "" {
		if msg := errs.T(pgErr.ConstraintName, errs.DefaultLanguage); msg != pgErr.ConstraintName {
			return pgErr.ConstraintName, msg
		}
	}

	if strings.Contains(pgErr.Detail, "is still referenced") {
		return "FOREIGN_KEY_REFERENCED", errs.T("FOREIGN_KEY_REFERENCED", errs.DefaultLanguage)
	}

	if pgErr.Detail != "" {
		if field := extractFieldFromDetail(pgErr.Detail); field != "" {
			return "NOT_FOUND", errs.TWithLabel("NOT_FOUND", field, errs.DefaultLanguage)
		}
	}

	return "FOREIGN_KEY_NOT_FOUND", errs.T("FOREIGN_KEY_NOT_FOUND", errs.DefaultLanguage)
}

func translateNotNullViolation(pgErr *pgconn.PgError) (string, string) {
	col := pgErr.ColumnName
	if col != "" {
		return "REQUIRED", errs.TWithLabel("REQUIRED", col, errs.DefaultLanguage)
	}
	return "NOT_NULL_VIOLATION", errs.T("NOT_NULL_VIOLATION", errs.DefaultLanguage)
}

func extractFieldFromDetail(detail string) string {
	start := strings.Index(detail, "(")
	if start == -1 {
		return ""
	}
	end := strings.Index(detail[start:], ")")
	if end == -1 {
		return ""
	}
	field := detail[start+1 : start+end]
	if strings.Contains(field, ",") {
		parts := strings.Split(field, ",")
		field = strings.TrimSpace(parts[len(parts)-1])
	}
	return field
}
