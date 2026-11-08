package auth

import (
	"net"
	"net/http"
	"strings"
)

// ParseClientInfo extracts IP address, user-agent string, and device identifier from an HTTP request.
func ParseClientInfo(r *http.Request) (ip, userAgent, device string) {
	if r == nil {
		return "", "", "Unknown Device"
	}

	// 1. IP resolution
	rawIP := r.Header.Get("X-Forwarded-For")
	if rawIP != "" {
		parts := strings.Split(rawIP, ",")
		rawIP = strings.TrimSpace(parts[0])
	}
	if rawIP == "" {
		rawIP = r.Header.Get("X-Real-IP")
	}
	if rawIP == "" {
		rawIP = r.RemoteAddr
	}

	if host, _, err := net.SplitHostPort(rawIP); err == nil {
		ip = host
	} else {
		ip = rawIP
	}

	// 2. User Agent
	userAgent = r.UserAgent()

	// 3. Device detection
	if customDevice := r.Header.Get("X-Device-Name"); customDevice != "" {
		device = customDevice
		return
	}
	if platform := r.Header.Get("X-Platform"); platform != "" {
		device = platform
		return
	}

	uaLower := strings.ToLower(userAgent)
	os := "Unknown OS"
	switch {
	case strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipad"):
		os = "iOS"
	case strings.Contains(uaLower, "android"):
		os = "Android"
	case strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "mac os"):
		os = "macOS"
	case strings.Contains(uaLower, "windows"):
		os = "Windows"
	case strings.Contains(uaLower, "linux"):
		os = "Linux"
	}

	client := ""
	switch {
	case strings.Contains(uaLower, "postman"):
		client = "Postman"
	case strings.Contains(uaLower, "curl"):
		client = "curl"
	case strings.Contains(uaLower, "edg/"):
		client = "Edge"
	case strings.Contains(uaLower, "chrome"):
		client = "Chrome"
	case strings.Contains(uaLower, "safari") && !strings.Contains(uaLower, "chrome"):
		client = "Safari"
	case strings.Contains(uaLower, "firefox"):
		client = "Firefox"
	}

	if client != "" && os != "Unknown OS" {
		device = client + " on " + os
	} else if os != "Unknown OS" {
		device = os + " Device"
	} else if client != "" {
		device = client
	} else {
		device = "Unknown Device"
	}

	return ip, userAgent, device
}
