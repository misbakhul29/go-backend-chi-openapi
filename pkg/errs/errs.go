package errs

import (
	"context"
	"net/http"
	"strings"
)

type Language string

const (
	ID Language = "id"
	EN Language = "en"

	DefaultLanguage = ID
)




type ctxKey struct{}

var languageCtxKey = ctxKey{}

// ResolveLanguage extracts preferred language from HTTP Accept-Language header or Query param ("lang").
// Defaults to "id" if unspecified or unsupported.
func ResolveLanguage(r *http.Request) Language {
	if r == nil {
		return DefaultLanguage
	}

	// 1. Query parameter override (?lang=en)
	if langParam := r.URL.Query().Get("lang"); langParam != "" {
		return parseLang(langParam)
	}

	// 2. Accept-Language header (e.g. "en-US,en;q=0.9,id;q=0.8")
	acceptLang := r.Header.Get("Accept-Language")
	if acceptLang != "" {
		parts := strings.Split(acceptLang, ",")
		for _, part := range parts {
			tag := strings.TrimSpace(strings.Split(part, ";")[0])
			if parsed := parseLang(tag); parsed != "" {
				return parsed
			}
		}
	}

	return DefaultLanguage
}

func parseLang(val string) Language {
	val = strings.ToLower(strings.TrimSpace(val))
	if strings.HasPrefix(val, "en") {
		return EN
	}
	if strings.HasPrefix(val, "id") || strings.HasPrefix(val, "in") {
		return ID
	}
	return ""
}

// WithLanguage returns a new context with the given Language attached.
func WithLanguage(ctx context.Context, lang Language) context.Context {
	return context.WithValue(ctx, languageCtxKey, lang)
}

// LanguageFromContext retrieves the Language from context, fallback to DefaultLanguage.
func LanguageFromContext(ctx context.Context) Language {
	if ctx == nil {
		return DefaultLanguage
	}
	if lang, ok := ctx.Value(languageCtxKey).(Language); ok && lang != "" {
		return lang
	}
	return DefaultLanguage
}



// T translates a message key to the specified Language.
// Fallbacks to English if key or language translation is missing.
func T(key string, lang Language) string {
	if msgs, ok := translations[key]; ok {
		if msg, ok := msgs[lang]; ok && msg != "" {
			return msg
		}
		// Fallback to ID then EN
		if msg, ok := msgs[ID]; ok && msg != "" {
			return msg
		}
		if msg, ok := msgs[EN]; ok && msg != "" {
			return msg
		}
	}
	return key
}

// TWithLabel formats a parameterized string like "{Label} already in use".
func TWithLabel(key string, labelKey string, lang Language) string {
	label := T("col_"+labelKey, lang)
	if label == "col_"+labelKey {
		label = labelKey
	}

	if lang == EN {
		switch key {
		case "ALREADY_USED":
			return label + " is already in use"
		case "REQUIRED":
			return label + " is required"
		case "NOT_FOUND":
			return label + " not found"
		}
	}

	// Default ID
	switch key {
	case "ALREADY_USED":
		return label + " sudah digunakan"
	case "REQUIRED":
		return label + " wajib diisi"
	case "NOT_FOUND":
		return label + " tidak ditemukan"
	}

	return T(key, lang)
}
