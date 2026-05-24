package version

import "testing"

func TestStringDefault(t *testing.T) {
	t.Cleanup(func() {
		Version = "dev"
		Commit = ""
		Date = ""
	})

	Version = "dev"
	Commit = ""
	Date = ""

	if got := String(); got != "dev" {
		t.Fatalf("String() = %q, want %q", got, "dev")
	}
}

func TestStringWithBuildMetadata(t *testing.T) {
	t.Cleanup(func() {
		Version = "dev"
		Commit = ""
		Date = ""
	})

	Version = "1.2.3"
	Commit = "abc123"
	Date = "2026-05-24"

	if got := String(); got != "1.2.3 (abc123, 2026-05-24)" {
		t.Fatalf("String() = %q", got)
	}
}
