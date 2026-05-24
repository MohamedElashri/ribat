package version

// These values can be overridden at build time with -ldflags.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

func String() string {
	if Commit == "" && Date == "" {
		return Version
	}
	if Commit == "" {
		return Version + " (" + Date + ")"
	}
	if Date == "" {
		return Version + " (" + Commit + ")"
	}
	return Version + " (" + Commit + ", " + Date + ")"
}
