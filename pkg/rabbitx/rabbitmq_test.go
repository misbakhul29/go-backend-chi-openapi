package rabbitx

import (
	"strings"
	"testing"

	"github.com/misbakhul29/backend-framework/config"
)

func TestNewTopologyConfig_Default(t *testing.T) {
	topo := NewTopologyConfig("")
	if topo.Prefix != "app" {
		t.Errorf("expected default prefix 'app', got %q", topo.Prefix)
	}
	if topo.EventsExchange != "app.events" {
		t.Errorf("expected 'app.events', got %q", topo.EventsExchange)
	}
	if topo.JobsExchange != "app.jobs" {
		t.Errorf("expected 'app.jobs', got %q", topo.JobsExchange)
	}
	if topo.NotifyExchange != "app.notifications" {
		t.Errorf("expected 'app.notifications', got %q", topo.NotifyExchange)
	}
	if topo.DLXExchange != "app.dlx" {
		t.Errorf("expected 'app.dlx', got %q", topo.DLXExchange)
	}
	if topo.DeadQueue != "app.dead" {
		t.Errorf("expected 'app.dead', got %q", topo.DeadQueue)
	}
}

func TestNewTopologyConfig_CustomPrefix(t *testing.T) {
	topo := NewTopologyConfig("billing")
	if topo.Prefix != "billing" {
		t.Errorf("expected 'billing', got %q", topo.Prefix)
	}
	if topo.EventsExchange != "billing.events" {
		t.Errorf("expected 'billing.events', got %q", topo.EventsExchange)
	}
	if topo.JobsExchange != "billing.jobs" {
		t.Errorf("expected 'billing.jobs', got %q", topo.JobsExchange)
	}
	if topo.NotifyExchange != "billing.notifications" {
		t.Errorf("expected 'billing.notifications', got %q", topo.NotifyExchange)
	}
	if topo.DLXExchange != "billing.dlx" {
		t.Errorf("expected 'billing.dlx', got %q", topo.DLXExchange)
	}
	if topo.DeadQueue != "billing.dead" {
		t.Errorf("expected 'billing.dead', got %q", topo.DeadQueue)
	}
}

func TestNewTopologyConfig_Sanitization(t *testing.T) {
	topo := NewTopologyConfig("  My New App  ")
	if topo.Prefix != "my-new-app" {
		t.Errorf("expected sanitized 'my-new-app', got %q", topo.Prefix)
	}
	if topo.EventsExchange != "my-new-app.events" {
		t.Errorf("expected 'my-new-app.events', got %q", topo.EventsExchange)
	}
}

func TestNewTopologyConfig_DotSanitization(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedPrefix string
	}{
		{
			name:           "trailing dot",
			input:          "myapp.",
			expectedPrefix: "myapp",
		},
		{
			name:           "trailing multiple dots with whitespace",
			input:          "  myapp...  ",
			expectedPrefix: "myapp",
		},
		{
			name:           "leading dot",
			input:          ".myapp",
			expectedPrefix: "myapp",
		},
		{
			name:           "only dots",
			input:          "...",
			expectedPrefix: "app",
		},
		{
			name:           "internal double dots",
			input:          "myapp..service",
			expectedPrefix: "myapp.service",
		},
		{
			name:           "leading, trailing and internal multiple dots",
			input:          "...myapp...service...",
			expectedPrefix: "myapp.service",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			topo := NewTopologyConfig(tc.input)
			if topo.Prefix != tc.expectedPrefix {
				t.Errorf("input %q: expected prefix %q, got %q", tc.input, tc.expectedPrefix, topo.Prefix)
			}
			exchanges := []string{
				topo.EventsExchange,
				topo.JobsExchange,
				topo.NotifyExchange,
				topo.DLXExchange,
				topo.DeadQueue,
			}
			for _, name := range exchanges {
				if strings.Contains(name, "..") {
					t.Errorf("name %q contains illegal double dot", name)
				}
				if strings.HasPrefix(name, ".") {
					t.Errorf("name %q has illegal leading dot", name)
				}
			}
		})
	}
}

func TestDefaultExchangeNames_FromConfig(t *testing.T) {
	originalCfg := config.Cfg
	defer func() { config.Cfg = originalCfg }()

	config.Cfg = &config.Env{
		RabbitMQ: config.RabbitMQ{
			ExchangePrefix: "tenant_corp",
		},
	}

	topo := DefaultExchangeNames()
	if topo.Prefix != "tenant_corp" {
		t.Errorf("expected 'tenant_corp', got %q", topo.Prefix)
	}
	if topo.EventsExchange != "tenant_corp.events" {
		t.Errorf("expected 'tenant_corp.events', got %q", topo.EventsExchange)
	}
}

func TestDefaultExchangeNames_FallbackWhenConfigNil(t *testing.T) {
	originalCfg := config.Cfg
	defer func() { config.Cfg = originalCfg }()
	config.Cfg = nil

	topo := DefaultExchangeNames()
	if topo.Prefix != "app" {
		t.Errorf("expected 'app', got %q", topo.Prefix)
	}
}

func TestDefaultExchangeNames_ExplicitPrefixPriority(t *testing.T) {
	originalCfg := config.Cfg
	defer func() { config.Cfg = originalCfg }()

	config.Cfg = &config.Env{
		RabbitMQ: config.RabbitMQ{
			ExchangePrefix: "config_prefix",
		},
	}

	topo := DefaultExchangeNames("explicit_override")
	if topo.Prefix != "explicit_override" {
		t.Errorf("expected explicit prefix override, got %q", topo.Prefix)
	}
}

func TestPing_NilConnection(t *testing.T) {
	err := Ping(nil)
	if err == nil {
		t.Errorf("expected error for nil connection, got nil")
	}
}
