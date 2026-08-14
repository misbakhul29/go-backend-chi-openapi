package observer

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

type ContextKey string

const (
	TraceIDKey     ContextKey = "trace_id"
	RequestIDKey   ContextKey = "request_id"
	TenantIDKey    ContextKey = "tenant_id"
	UserIDKey      ContextKey = "user_id"
)

// Log is the global structured logger.
var Log *slog.Logger

type ContextHandler struct {
	slog.Handler
}

func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx != nil {
		if traceID, ok := ctx.Value(TraceIDKey).(string); ok && traceID != "" {
			r.Add("trace_id", traceID)
		}
		if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
			r.Add("request_id", requestID)
		}
		if tenantID, ok := ctx.Value(TenantIDKey).(string); ok && tenantID != "" {
			r.Add("tenant_id", tenantID)
		}
		if userID, ok := ctx.Value(UserIDKey).(string); ok && userID != "" {
			r.Add("user_id", userID)
		}
	}
	return h.Handler.Handle(ctx, r)
}

func init() {
	piiKeys := map[string]bool{
		// Auth & credentials
		"password":       true,
		"passwd":         true,
		"token":          true,
		"access_token":   true,
		"refresh_token":  true,
		"secret":         true,
		"authorization":  true,
		"pin":            true,

		// Identity & tax (Indonesian PII)
		"nik":            true, // Nomor Induk Kependudukan
		"npwp":           true, // Nomor Pokok Wajib Pajak
		"kk":             true, // Nomor Kartu Keluarga
		"passport":       true,
		"passport_no":    true,
		"tax_id":         true,
		"ssn":            true,

		// Financial
		"account_number":  true,
		"bank_account":    true,
		"account_no":      true,
		"rekening":        true,
		"credit_card":     true,
		"cc":              true,
		"cvv":             true,

		// Contact
		"email": true,
	}

	replaceAttr := func(groups []string, a slog.Attr) slog.Attr {
		keyLower := strings.ToLower(a.Key)
		// Check direct map match or contains sensitive keywords
		if piiKeys[keyLower] || strings.Contains(keyLower, "password") || strings.Contains(keyLower, "secret") || strings.Contains(keyLower, "token") {
			return slog.String(a.Key, "[REDACTED]")
		}
		return a
	}

	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: replaceAttr,
	})

	Log = slog.New(&ContextHandler{Handler: jsonHandler})
}

// Logger is a HTTP middleware that logs request and response details using structured slog.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Try to extract trace_id and request_id from headers if present, and add them to context.
		ctx := r.Context()
		traceID := r.Header.Get("X-Trace-Id")
		if traceID == "" {
			traceID = r.Header.Get("X-B3-TraceId")
		}
		if traceID != "" {
			ctx = context.WithValue(ctx, TraceIDKey, traceID)
		}

		requestID := middleware.GetReqID(ctx)
		if requestID != "" {
			ctx = context.WithValue(ctx, RequestIDKey, requestID)
		}

		r = r.WithContext(ctx)

		defer func() {
			Log.InfoContext(ctx, "HTTP request processed",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.Int("bytes", ww.BytesWritten()),
				slog.Duration("duration", time.Since(start)),
				slog.String("remote_ip", r.RemoteAddr),
			)
		}()

		next.ServeHTTP(ww, r)
	})
}

// Recoverer is a HTTP middleware that recovers from panics and logs them via structured slog.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				Log.ErrorContext(r.Context(), "panic recovered",
					slog.Any("error", err),
				)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
