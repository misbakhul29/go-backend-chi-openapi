package rabbitx

import (
	"strings"
	"testing"
)

// TestPrefixSanitization_StandardInputs verifies that whitespace is trimmed,
// spaces are converted to hyphens, uppercase is lowercased, and empty inputs fall back to "app".
func TestPrefixSanitization_StandardInputs(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedPrefix string
	}{
		{
			name:           "standard prefix",
			input:          "tenant-alpha",
			expectedPrefix: "tenant-alpha",
		},
		{
			name:           "whitespace trimming",
			input:          "   tenant-beta   ",
			expectedPrefix: "tenant-beta",
		},
		{
			name:           "spaces converted to hyphens",
			input:          "my new service",
			expectedPrefix: "my-new-service",
		},
		{
			name:           "uppercase converted to lowercase",
			input:          "UPPER_TENANT",
			expectedPrefix: "upper_tenant",
		},
		{
			name:           "empty input falls back to app",
			input:          "",
			expectedPrefix: "app",
		},
		{
			name:           "whitespace only falls back to app",
			input:          "    \t\n  ",
			expectedPrefix: "app",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			topo := NewTopologyConfig(tc.input)

			if topo.Prefix != tc.expectedPrefix {
				t.Errorf("input %q: expected prefix %q, got %q", tc.input, tc.expectedPrefix, topo.Prefix)
			}

			expectedEvents := tc.expectedPrefix + ".events"
			if topo.EventsExchange != expectedEvents {
				t.Errorf("expected EventsExchange %q, got %q", expectedEvents, topo.EventsExchange)
			}
		})
	}
}

// TestPrefixSanitization_TrailingDotDefect empirically probes the behavior of NewTopologyConfig
// when presented with trailing dots in the prefix (e.g. "myapp." or "my-service...").
// It verifies whether trailing dots are stripped or if double-dots (..) are produced.
func TestPrefixSanitization_TrailingDotDefect(t *testing.T) {
	adversarialInputs := []string{
		"myapp.",
		"  myapp...  ",
		".myapp",
		"...",
	}

	for _, input := range adversarialInputs {
		topo := NewTopologyConfig(input)

		// Probe whether trailing dots produce double-dots in exchange names
		hasDoubleDots := strings.Contains(topo.EventsExchange, "..") ||
			strings.Contains(topo.JobsExchange, "..") ||
			strings.Contains(topo.NotifyExchange, "..") ||
			strings.Contains(topo.DLXExchange, "..") ||
			strings.Contains(topo.DeadQueue, "..")

		if hasDoubleDots {
			t.Logf("[FINDING] Prefix input %q resulted in double-dot exchange/queue names: Events=%q, DeadQueue=%q (missing strings.Trim(p, \".\"))",
				input, topo.EventsExchange, topo.DeadQueue)
		}

		if input == "..." && topo.Prefix == "..." {
			t.Logf("[FINDING] Dot-only prefix %q was not sanitized to fallback 'app', producing EventsExchange=%q",
				input, topo.EventsExchange)
		}
	}
}
