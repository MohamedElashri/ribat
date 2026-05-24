package policy

import (
	"testing"
	"time"
)

func TestParseDurationSupportsPolicyUnits(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{input: "30s", want: 30 * time.Second},
		{input: "15m", want: 15 * time.Minute},
		{input: "24h", want: 24 * time.Hour},
		{input: "7d", want: 7 * 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if err != nil {
				t.Fatalf("ParseDuration(%q) error = %v", tt.input, err)
			}
			if got.Duration != tt.want {
				t.Fatalf("ParseDuration(%q) = %s, want %s", tt.input, got.Duration, tt.want)
			}
		})
	}
}

func TestParseDurationRejectsInvalidValues(t *testing.T) {
	for _, input := range []string{"", "soon", "-1h", "1w", "1.5d"} {
		t.Run(input, func(t *testing.T) {
			if got, err := ParseDuration(input); err == nil {
				t.Fatalf("ParseDuration(%q) = %s, want error", input, got.Duration)
			}
		})
	}
}
