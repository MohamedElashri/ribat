package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Event struct {
	Timestamp      time.Time `json:"timestamp"`
	ImageRef       string    `json:"image_ref"`
	Registry       string    `json:"registry,omitempty"`
	Repository     string    `json:"repository,omitempty"`
	Tag            string    `json:"tag,omitempty"`
	Digest         string    `json:"digest,omitempty"`
	Decision       string    `json:"decision"`
	Reason         string    `json:"reason"`
	MatchedRule    string    `json:"matched_rule,omitempty"`
	ClientUser     string    `json:"client_user,omitempty"`
	RequestMethod  string    `json:"request_method,omitempty"`
	RequestURI     string    `json:"request_uri,omitempty"`
	CosignVerified bool      `json:"cosign_verified,omitempty"`
	CosignCached   bool      `json:"cosign_cached,omitempty"`
}

type Logger struct {
	path string
}

func NewLogger(path string) *Logger {
	return &Logger{path: path}
}

func (l *Logger) Record(event Event) error {
	if l == nil || l.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	file, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}
