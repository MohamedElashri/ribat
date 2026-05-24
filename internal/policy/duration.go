package policy

import (
	"fmt"
	"strconv"
	"time"
)

// Duration wraps time.Duration so policy files can use day-based values such
// as "7d" in addition to Go's standard "30s", "15m", and "24h" units.
type Duration struct {
	time.Duration
}

func ParseDuration(value string) (Duration, error) {
	if value == "" {
		return Duration{}, fmt.Errorf("duration is empty")
	}

	unit := value[len(value)-1:]
	if unit == "d" {
		days, err := strconv.Atoi(value[:len(value)-1])
		if err != nil || days < 0 {
			return Duration{}, fmt.Errorf("duration %q must use a non-negative whole number of days", value)
		}
		return Duration{Duration: time.Duration(days) * 24 * time.Hour}, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return Duration{}, fmt.Errorf("duration %q must use units like 30s, 15m, 24h, 7d, or 14d", value)
	}
	if parsed < 0 {
		return Duration{}, fmt.Errorf("duration %q must not be negative", value)
	}

	return Duration{Duration: parsed}, nil
}

func (d Duration) String() string {
	if d.Duration%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", int(d.Duration/(24*time.Hour)))
	}
	return d.Duration.String()
}
