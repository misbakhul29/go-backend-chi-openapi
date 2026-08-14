package httpx

import (
	"net"
	"net/http"
	"strings"
)

type Meta struct {
	IP        string
	UserAgent string
	Forwarded string
}

func ExtractMeta(r *http.Request) *Meta {
	return &Meta{
		IP:        GetSafeRealIP(r),
		UserAgent: r.UserAgent(),
	}
}

// GetSafeRealIP extracts the real client IP safely. Returns "127.0.0.1" if unresolved.
func GetSafeRealIP(r *http.Request) string {
	var ip string
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		ip = xrip
	} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip = strings.TrimSpace(parts[0])
	} else if r.RemoteAddr != "" {
		ip = r.RemoteAddr
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
	}

	if ip == "" || ip == "::" {
		ip = "127.0.0.1"
	}

	return ip
}
