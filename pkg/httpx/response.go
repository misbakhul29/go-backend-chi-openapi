package httpx

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/misbakhul29/backend-framework/pkg/db"
	"github.com/misbakhul29/backend-framework/pkg/errs"
	"github.com/misbakhul29/backend-framework/pkg/observer"
)

// ErrorResponse represents the RFC 9457 / standard system error response body structure.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
}

// WriteJSON helper to serialize and write JSON response.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// WriteError translates any error and writes a standard error JSON response.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}

	// 1. Resolve language and request ID
	lang := errs.LanguageFromContext(r.Context())
	reqID := middleware.GetReqID(r.Context())
	if reqID == "" {
		if rid, ok := r.Context().Value(observer.RequestIDKey).(string); ok {
			reqID = rid
		}
	}

	var (
		statusCode = http.StatusInternalServerError
		code       = "INTERNAL_ERROR"
		message    = ""
		details    map[string]any
	)

	// 2. Map the error to details, code, and statusCode

	// Auto-translate raw database errors if not already translated
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) || (err != nil && err.Error() == "record not found") {
		err = db.TranslateError(err)
	}

	if dbErr, ok := errors.AsType[*db.DBError](err); ok {
		statusCode = dbErr.HTTPStatus
		code = dbErr.Code
		message = dbErr.Localize(lang)
		// We could add database details here if needed in non-prod, but standard spec says keep safe
	} else if apiErr, ok := errors.AsType[APIError](err); ok {
		statusCode = apiErr.HTTPStatusCode()
		code = apiErr.APIErrorCode()
		message = errs.T(apiErr.APIMessageKey(), lang)
		if message == apiErr.APIMessageKey() {
			message = errs.T(code, lang)
		}
		details = apiErr.APIDetails()
	} else {
		// Fallback/standard sentinel checks
		switch {
		case errors.Is(err, ErrNotFound):
			statusCode = http.StatusNotFound
			code = "NOT_FOUND"
			message = errs.T("NOT_FOUND", lang)
		case errors.Is(err, ErrValidation):
			statusCode = http.StatusBadRequest
			code = "VALIDATION_FAILED"
			message = errs.T("VALIDATION_FAILED", lang)
		case errors.Is(err, ErrForbidden):
			statusCode = http.StatusForbidden
			code = "FORBIDDEN"
			message = errs.T("FORBIDDEN", lang)
		case errors.Is(err, ErrConflict):
			statusCode = http.StatusConflict
			code = "CONFLICT"
			message = errs.T("CONFLICT", lang)
		case errors.Is(err, ErrUnauthorized):
			statusCode = http.StatusUnauthorized
			code = "UNAUTHORIZED"
			message = errs.T("UNAUTHORIZED", lang)
		case errors.Is(err, ErrBadRequest):
			statusCode = http.StatusBadRequest
			code = "BAD_REQUEST"
			message = errs.T("BAD_REQUEST", lang)
		default:
			// Treat all unhandled errors as Internal Server Error
			statusCode = http.StatusInternalServerError
			code = "INTERNAL_ERROR"
			message = errs.T("INTERNAL_ERROR", lang)
		}
	}

	// 3. Write JSON response
	resp := ErrorResponse{
		Error: ErrorDetail{
			Code:      code,
			Message:   message,
			Details:   details,
			RequestID: reqID,
		},
	}

	WriteJSON(w, statusCode, resp)
}
