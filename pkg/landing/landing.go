package landing

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/misbakhul29/backend-framework/config"
)

//go:embed landing.html
var landingHTML []byte

func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appName := "Backend Framework"
		port := "8800"

		if config.Cfg != nil {
			if config.Cfg.APPName != "" {
				appName = config.Cfg.APPName
			}
			if config.Cfg.Port != "" {
				port = config.Cfg.Port
			}
		}

		content := string(landingHTML)
		content = strings.ReplaceAll(content, "{{.AppName}}", appName)
		content = strings.ReplaceAll(content, "{{.Port}}", port)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(content))
	}
}

