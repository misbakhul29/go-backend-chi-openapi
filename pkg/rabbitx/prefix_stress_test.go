package rabbitx

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestAdversarial_RabbitMQPrefix_ChaoticStress(t *testing.T) {
	maliciousAndChaoticInputs := []struct {
		name  string
		input string
	}{
		// Multi-dot and dot edge cases
		{"single dot", "."},
		{"double dot", ".."},
		{"triple dot", "..."},
		{"many dots", "...................."},
		{"trailing single dot", "myapp."},
		{"trailing multiple dots", "myapp...."},
		{"leading single dot", ".myapp"},
		{"leading multiple dots", "....myapp"},
		{"leading and trailing dots", "...myapp..."},
		{"dots with inner spaces", ". . ."},
		{"dots with outer spaces", "   ...   "},
		{"dots and spaces mixed", " . . . . . "},
		{"multiple dots between words", "my..app...service....exchange"},
		{"alternating dots and hyphens", ".-.-.-."},
		{"dots and underscores", "..__..__.."},
		{"dot slash traversal style", "../../../app"},
		{"dot backslash traversal style", "..\\..\\..\\app"},

		// Whitespace and chaotic whitespace
		{"empty string", ""},
		{"spaces only", "     "},
		{"tabs only", "\t\t\t"},
		{"newlines only", "\n\r\n\r"},
		{"mixed whitespace", " \t \r \n "},
		{"leading/trailing whitespace with dots", "  \t ...myapp... \n "},
		{"whitespace between dots and words", "  .  myapp  .  "},

		// Malicious injection and metacharacters
		{"command injection semicolon", "myapp; rm -rf /;"},
		{"command injection pipe", "myapp | cat /etc/passwd"},
		{"command injection subshell", "myapp$(whoami)"},
		{"command injection backticks", "myapp`id`"},
		{"sql injection quote", "myapp' OR '1'='1"},
		{"xss script tag", "<script>alert('xss')</script>"},
		{"xml tag", "<exchange name=\"test\"/>"},
		{"null bytes", "my\x00app\x00prefix"},
		{"control characters", "my\x01\x02\x03app\x1f"},
		{"url encoded dots", "myapp%2e%2e%2f"},
		{"amqp forbidden wildcards", "myapp.*.#"},

		// Unicode and chaotic internationalization
		{"emoji prefix", "🔥🚀rabbit-app🎉"},
		{"unicode fullwidth dots", "myapp．service"},
		{"unicode one-dot leader", "myapp․service"},
		{"unicode two-dot leader", "myapp‥service"},
		{"unicode horizontal ellipsis", "myapp…service"},
		{"cjk characters", "我的微服务.队列"},
		{"cyrillic characters", "сервис.очередь"},
		{"arabic characters", "خدمة.طابور"},
		{"zero-width space", "my\u200Bapp"},
		{"zero-width joiner", "my\u200Capp"},
		{"byte order mark", "\uFEFFmyapp"},
		{"non-breaking space", "my\u00A0app"},

		// Extreme sizes
		{"1000 dots", strings.Repeat(".", 1000)},
		{"1000 spaces", strings.Repeat(" ", 1000)},
		{"1000 dots with word", strings.Repeat(".", 500) + "myapp" + strings.Repeat(".", 500)},
		{"interleaved 500 dot-space pairs", strings.Repeat(". ", 500)},
		{"long prefix 4096 chars", strings.Repeat("a", 4096)},
	}

	for _, tc := range maliciousAndChaoticInputs {
		t.Run(tc.name, func(t *testing.T) {
			topo := NewTopologyConfig(tc.input)

			// Invariant 1: Prefix must never be empty
			if topo.Prefix == "" {
				t.Fatalf("[VULNERABILITY] Prefix is empty for input %q", tc.input)
			}

			// Invariant 2: Prefix must never contain double dots
			if strings.Contains(topo.Prefix, "..") {
				t.Fatalf("[VULNERABILITY] Prefix %q contains double dots '..' for input %q", topo.Prefix, tc.input)
			}

			// Invariant 3: Prefix must never have leading or trailing dots
			if strings.HasPrefix(topo.Prefix, ".") {
				t.Fatalf("[VULNERABILITY] Prefix %q has leading dot for input %q", topo.Prefix, tc.input)
			}
			if strings.HasSuffix(topo.Prefix, ".") {
				t.Fatalf("[VULNERABILITY] Prefix %q has trailing dot for input %q", topo.Prefix, tc.input)
			}

			// Invariant 4: Check all topology exchange and queue names
			exchanges := map[string]string{
				"EventsExchange": topo.EventsExchange,
				"JobsExchange":   topo.JobsExchange,
				"NotifyExchange": topo.NotifyExchange,
				"DLXExchange":    topo.DLXExchange,
				"DeadQueue":      topo.DeadQueue,
			}

			for fieldName, name := range exchanges {
				if strings.Contains(name, "..") {
					t.Fatalf("[VULNERABILITY] %s %q contains illegal double dot for input %q", fieldName, name, tc.input)
				}
				if strings.HasPrefix(name, ".") {
					t.Fatalf("[VULNERABILITY] %s %q starts with illegal dot for input %q", fieldName, name, tc.input)
				}
				if strings.HasSuffix(name, ".") {
					t.Fatalf("[VULNERABILITY] %s %q ends with illegal dot for input %q", fieldName, name, tc.input)
				}
			}
		})
	}
}

// TestAdversarial_RabbitMQPrefix_RandomFuzzing performs 50,000 randomized fuzzing iterations
// to detect any combination of runes/bytes that could generate double-dots or malformed names.
func TestAdversarial_RabbitMQPrefix_RandomFuzzing(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	runesPool := []rune{
		'.', ' ', '-', '_', '/', '\\', '\t', '\n', '\r', '\x00',
		'a', 'Z', '0', '9', '!', '@', '#', '$', '%', '^', '&', '*',
		'．', '‥', '…', '․', '🔥', '🚀', '\u200B', '\u00A0', '中', '文',
	}

	const iterations = 50000
	for i := 0; i < iterations; i++ {
		length := rng.Intn(64)
		var sb strings.Builder
		for j := 0; j < length; j++ {
			sb.WriteRune(runesPool[rng.Intn(len(runesPool))])
		}
		input := sb.String()

		topo := NewTopologyConfig(input)

		if topo.Prefix == "" {
			t.Fatalf("[FUZZ FAILURE] iteration %d: empty prefix for input %q", i, input)
		}
		if strings.Contains(topo.Prefix, "..") {
			t.Fatalf("[FUZZ FAILURE] iteration %d: prefix %q has double dots for input %q", i, topo.Prefix, input)
		}
		if strings.HasPrefix(topo.Prefix, ".") {
			t.Fatalf("[FUZZ FAILURE] iteration %d: prefix %q has leading dot for input %q", i, topo.Prefix, input)
		}
		if strings.HasSuffix(topo.Prefix, ".") {
			t.Fatalf("[FUZZ FAILURE] iteration %d: prefix %q has trailing dot for input %q", i, topo.Prefix, input)
		}

		exchanges := []string{
			topo.EventsExchange,
			topo.JobsExchange,
			topo.NotifyExchange,
			topo.DLXExchange,
			topo.DeadQueue,
		}
		for _, ex := range exchanges {
			if strings.Contains(ex, "..") {
				t.Fatalf("[FUZZ FAILURE] iteration %d: exchange %q has double dots for input %q", i, ex, input)
			}
			if strings.HasPrefix(ex, ".") {
				t.Fatalf("[FUZZ FAILURE] iteration %d: exchange %q has leading dot for input %q", i, ex, input)
			}
		}
	}
}
