package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	ObservationStatusQuarantined = "quarantined"

	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

type SQLiteStore struct {
	db *sql.DB
}

type Observation struct {
	ID            int64
	Registry      string
	Repository    string
	Tag           string
	Digest        string
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	LastAllowedAt *time.Time
	Status        string
}

type DecisionRecord struct {
	ID            int64
	Timestamp     time.Time
	ImageRef      string
	Registry      string
	Repository    string
	Tag           string
	Digest        string
	Decision      string
	Reason        string
	ClientUser    string
	RequestMethod string
	RequestURI    string
}

type Approval struct {
	ID         int64
	Registry   string
	Repository string
	Tag        string
	Digest     string
	ApprovedAt time.Time
	ApprovedBy string
	Reason     string
	ExpiresAt  *time.Time
}

type Freeze struct {
	ID         int64
	Registry   string
	Repository string
	Tag        string
	Digest     string
	CreatedAt  time.Time
	CreatedBy  string
	Reason     string
	ExpiresAt  *time.Time
}

type Bypass struct {
	ID         int64
	Registry   string
	Repository string
	Tag        string
	CreatedAt  time.Time
	CreatedBy  string
	Reason     string
	ExpiresAt  *time.Time
}

type LocalOverride struct {
	Approval *Approval
	Freeze   *Freeze
	Bypass   *Bypass
	Decision string
}

type ExportedState struct {
	Version      int              `json:"version"`
	Observations []Observation    `json:"observations"`
	Decisions    []DecisionRecord `json:"decisions"`
	Approvals    []Approval       `json:"approvals"`
	Freezes      []Freeze         `json:"freezes"`
	Bypasses     []Bypass         `json:"bypasses"`
}

func OpenSQLite(path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite state path is required")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create sqlite state directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite state: %w", err)
	}
	store := &SQLiteStore{db: db}
	if err := store.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) Migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS tag_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registry TEXT NOT NULL,
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    digest TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    last_allowed_at INTEGER,
    status TEXT NOT NULL,
    UNIQUE(registry, repository, tag, digest)
);

CREATE TABLE IF NOT EXISTS pull_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    image_ref TEXT NOT NULL,
    registry TEXT,
    repository TEXT,
    tag TEXT,
    digest TEXT,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    client_user TEXT,
    request_method TEXT,
    request_uri TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registry TEXT NOT NULL,
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    digest TEXT NOT NULL,
    approved_at INTEGER NOT NULL,
    approved_by TEXT,
    reason TEXT,
    expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS freezes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registry TEXT NOT NULL,
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    digest TEXT,
    created_at INTEGER NOT NULL,
    created_by TEXT,
    reason TEXT,
    expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS bypasses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registry TEXT NOT NULL,
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    created_by TEXT,
    reason TEXT,
    expires_at INTEGER
);`

	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate sqlite state: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetObservation(ctx context.Context, registry, repository, tag, digest string) (*Observation, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, registry, repository, tag, digest, first_seen_at, last_seen_at, last_allowed_at, status
FROM tag_observations
WHERE registry = ? AND repository = ? AND tag = ? AND digest = ?`, registry, repository, tag, digest)
	return scanObservation(row)
}

func (s *SQLiteStore) ListObservations(ctx context.Context, registry, repository, tag string) ([]Observation, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, registry, repository, tag, digest, first_seen_at, last_seen_at, last_allowed_at, status
FROM tag_observations
WHERE registry = ? AND repository = ? AND tag = ?
ORDER BY first_seen_at DESC, id DESC`, registry, repository, tag)
	if err != nil {
		return nil, fmt.Errorf("list observations: %w", err)
	}
	defer rows.Close()

	var observations []Observation
	for rows.Next() {
		obs, err := scanObservationRows(rows)
		if err != nil {
			return nil, err
		}
		observations = append(observations, obs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list observations: %w", err)
	}
	return observations, nil
}

func (s *SQLiteStore) CreateObservation(ctx context.Context, registry, repository, tag, digest string, now time.Time) (*Observation, error) {
	ts := unix(now)
	_, err := s.db.ExecContext(ctx, `
INSERT OR IGNORE INTO tag_observations
    (registry, repository, tag, digest, first_seen_at, last_seen_at, status)
VALUES (?, ?, ?, ?, ?, ?, ?)`, registry, repository, tag, digest, ts, ts, ObservationStatusQuarantined)
	if err != nil {
		return nil, fmt.Errorf("create observation: %w", err)
	}
	return s.GetObservation(ctx, registry, repository, tag, digest)
}

func (s *SQLiteStore) TouchObservation(ctx context.Context, id int64, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE tag_observations
SET last_seen_at = ?
WHERE id = ?`, unix(now), id)
	if err != nil {
		return fmt.Errorf("touch observation: %w", err)
	}
	return requireAffected(result, "touch observation")
}

func (s *SQLiteStore) MarkObservationAllowed(ctx context.Context, id int64, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE tag_observations
SET last_seen_at = ?, last_allowed_at = ?
WHERE id = ?`, unix(now), unix(now), id)
	if err != nil {
		return fmt.Errorf("mark observation allowed: %w", err)
	}
	return requireAffected(result, "mark observation allowed")
}

func (s *SQLiteStore) RecordDecision(ctx context.Context, record DecisionRecord) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO pull_decisions
    (timestamp, image_ref, registry, repository, tag, digest, decision, reason, client_user, request_method, request_uri)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		unix(record.Timestamp), record.ImageRef, record.Registry, record.Repository, record.Tag, record.Digest,
		record.Decision, record.Reason, record.ClientUser, record.RequestMethod, record.RequestURI)
	if err != nil {
		return fmt.Errorf("record decision: %w", err)
	}
	return nil
}

func (s *SQLiteStore) CountDecisions(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pull_decisions").Scan(&count); err != nil {
		return 0, fmt.Errorf("count decisions: %w", err)
	}
	return count, nil
}

func (s *SQLiteStore) ListDecisions(ctx context.Context) ([]DecisionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, timestamp, image_ref, registry, repository, tag, digest, decision, reason, client_user, request_method, request_uri
FROM pull_decisions
ORDER BY timestamp ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list decisions: %w", err)
	}
	defer rows.Close()

	var decisions []DecisionRecord
	for rows.Next() {
		decision, err := scanDecisionRows(rows)
		if err != nil {
			return nil, err
		}
		decisions = append(decisions, decision)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list decisions: %w", err)
	}
	return decisions, nil
}

func (s *SQLiteStore) ApproveDigest(ctx context.Context, registry, repository, tag, digest string, approvedAt time.Time, approvedBy, reason string, expiresAt *time.Time) (*Approval, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO approvals
    (registry, repository, tag, digest, approved_at, approved_by, reason, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		registry, repository, tag, digest, unix(approvedAt), approvedBy, reason, nullableUnix(expiresAt))
	if err != nil {
		return nil, fmt.Errorf("approve digest: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("approve digest: read inserted id: %w", err)
	}
	return s.GetApproval(ctx, id)
}

func (s *SQLiteStore) FreezeTag(ctx context.Context, registry, repository, tag, digest string, createdAt time.Time, createdBy, reason string, expiresAt *time.Time) (*Freeze, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO freezes
    (registry, repository, tag, digest, created_at, created_by, reason, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		registry, repository, tag, nullableString(digest), unix(createdAt), createdBy, reason, nullableUnix(expiresAt))
	if err != nil {
		return nil, fmt.Errorf("freeze tag: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("freeze tag: read inserted id: %w", err)
	}
	return s.GetFreeze(ctx, id)
}

func (s *SQLiteStore) BypassTag(ctx context.Context, registry, repository, tag string, createdAt time.Time, createdBy, reason string, expiresAt *time.Time) (*Bypass, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO bypasses
    (registry, repository, tag, created_at, created_by, reason, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		registry, repository, tag, unix(createdAt), createdBy, reason, nullableUnix(expiresAt))
	if err != nil {
		return nil, fmt.Errorf("bypass tag: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("bypass tag: read inserted id: %w", err)
	}
	return s.GetBypass(ctx, id)
}

func (s *SQLiteStore) GetApproval(ctx context.Context, id int64) (*Approval, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, registry, repository, tag, digest, approved_at, approved_by, reason, expires_at
FROM approvals
WHERE id = ?`, id)
	return scanApproval(row)
}

func (s *SQLiteStore) GetFreeze(ctx context.Context, id int64) (*Freeze, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, registry, repository, tag, digest, created_at, created_by, reason, expires_at
FROM freezes
WHERE id = ?`, id)
	return scanFreeze(row)
}

func (s *SQLiteStore) GetBypass(ctx context.Context, id int64) (*Bypass, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, registry, repository, tag, created_at, created_by, reason, expires_at
FROM bypasses
WHERE id = ?`, id)
	return scanBypass(row)
}

func (s *SQLiteStore) ActiveApproval(ctx context.Context, registry, repository, tag, digest string, now time.Time) (*Approval, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, registry, repository, tag, digest, approved_at, approved_by, reason, expires_at
FROM approvals
WHERE registry = ? AND repository = ? AND tag = ? AND digest = ?
  AND (expires_at IS NULL OR expires_at > ?)
ORDER BY approved_at DESC, id DESC
LIMIT 1`, registry, repository, tag, digest, unix(now))
	return scanApproval(row)
}

func (s *SQLiteStore) ActiveFreeze(ctx context.Context, registry, repository, tag, digest string, now time.Time) (*Freeze, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, registry, repository, tag, digest, created_at, created_by, reason, expires_at
FROM freezes
WHERE registry = ? AND repository = ? AND tag = ?
  AND (digest IS NULL OR digest = ?)
  AND (expires_at IS NULL OR expires_at > ?)
ORDER BY created_at DESC, id DESC
LIMIT 1`, registry, repository, tag, digest, unix(now))
	return scanFreeze(row)
}

func (s *SQLiteStore) ActiveBypass(ctx context.Context, registry, repository, tag string, now time.Time) (*Bypass, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, registry, repository, tag, created_at, created_by, reason, expires_at
FROM bypasses
WHERE registry = ? AND repository = ? AND tag = ?
  AND (expires_at IS NULL OR expires_at > ?)
ORDER BY created_at DESC, id DESC
LIMIT 1`, registry, repository, tag, unix(now))
	return scanBypass(row)
}

func (s *SQLiteStore) LocalOverride(ctx context.Context, registry, repository, tag, digest string, now time.Time) (LocalOverride, error) {
	freeze, err := s.ActiveFreeze(ctx, registry, repository, tag, digest, now)
	if err != nil {
		return LocalOverride{}, err
	}
	approval, err := s.ActiveApproval(ctx, registry, repository, tag, digest, now)
	if err != nil {
		return LocalOverride{}, err
	}
	bypass, err := s.ActiveBypass(ctx, registry, repository, tag, now)
	if err != nil {
		return LocalOverride{}, err
	}
	override := LocalOverride{Approval: approval, Freeze: freeze, Bypass: bypass}
	switch {
	case freeze != nil:
		override.Decision = DecisionDeny
	case approval != nil:
		override.Decision = DecisionAllow
	case bypass != nil:
		override.Decision = DecisionAllow
	}
	return override, nil
}

func (s *SQLiteStore) ExportState(ctx context.Context) (ExportedState, error) {
	observations, err := s.listAllObservations(ctx)
	if err != nil {
		return ExportedState{}, err
	}
	decisions, err := s.ListDecisions(ctx)
	if err != nil {
		return ExportedState{}, err
	}
	approvals, err := s.listApprovals(ctx)
	if err != nil {
		return ExportedState{}, err
	}
	freezes, err := s.listFreezes(ctx)
	if err != nil {
		return ExportedState{}, err
	}
	bypasses, err := s.listBypasses(ctx)
	if err != nil {
		return ExportedState{}, err
	}
	return ExportedState{
		Version:      1,
		Observations: observations,
		Decisions:    decisions,
		Approvals:    approvals,
		Freezes:      freezes,
		Bypasses:     bypasses,
	}, nil
}

func (s *SQLiteStore) ImportState(ctx context.Context, state ExportedState) error {
	if state.Version != 1 {
		return fmt.Errorf("unsupported state export version %d", state.Version)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin import state: %w", err)
	}
	defer tx.Rollback()

	for _, obs := range state.Observations {
		_, err := tx.ExecContext(ctx, `
INSERT OR REPLACE INTO tag_observations
    (id, registry, repository, tag, digest, first_seen_at, last_seen_at, last_allowed_at, status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			obs.ID, obs.Registry, obs.Repository, obs.Tag, obs.Digest, unix(obs.FirstSeenAt), unix(obs.LastSeenAt), nullableUnix(obs.LastAllowedAt), obs.Status)
		if err != nil {
			return fmt.Errorf("import observation %s/%s:%s@%s: %w", obs.Registry, obs.Repository, obs.Tag, obs.Digest, err)
		}
	}
	for _, decision := range state.Decisions {
		_, err := tx.ExecContext(ctx, `
INSERT OR REPLACE INTO pull_decisions
    (id, timestamp, image_ref, registry, repository, tag, digest, decision, reason, client_user, request_method, request_uri)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			decision.ID, unix(decision.Timestamp), decision.ImageRef, decision.Registry, decision.Repository, decision.Tag, decision.Digest,
			decision.Decision, decision.Reason, decision.ClientUser, decision.RequestMethod, decision.RequestURI)
		if err != nil {
			return fmt.Errorf("import decision for %s: %w", decision.ImageRef, err)
		}
	}
	for _, approval := range state.Approvals {
		_, err := tx.ExecContext(ctx, `
INSERT OR REPLACE INTO approvals
    (id, registry, repository, tag, digest, approved_at, approved_by, reason, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			approval.ID, approval.Registry, approval.Repository, approval.Tag, approval.Digest, unix(approval.ApprovedAt), approval.ApprovedBy, approval.Reason, nullableUnix(approval.ExpiresAt))
		if err != nil {
			return fmt.Errorf("import approval %s/%s:%s@%s: %w", approval.Registry, approval.Repository, approval.Tag, approval.Digest, err)
		}
	}
	for _, freeze := range state.Freezes {
		_, err := tx.ExecContext(ctx, `
INSERT OR REPLACE INTO freezes
    (id, registry, repository, tag, digest, created_at, created_by, reason, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			freeze.ID, freeze.Registry, freeze.Repository, freeze.Tag, nullableString(freeze.Digest), unix(freeze.CreatedAt), freeze.CreatedBy, freeze.Reason, nullableUnix(freeze.ExpiresAt))
		if err != nil {
			return fmt.Errorf("import freeze %s/%s:%s: %w", freeze.Registry, freeze.Repository, freeze.Tag, err)
		}
	}
	for _, bypass := range state.Bypasses {
		_, err := tx.ExecContext(ctx, `
INSERT OR REPLACE INTO bypasses
    (id, registry, repository, tag, created_at, created_by, reason, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			bypass.ID, bypass.Registry, bypass.Repository, bypass.Tag, unix(bypass.CreatedAt), bypass.CreatedBy, bypass.Reason, nullableUnix(bypass.ExpiresAt))
		if err != nil {
			return fmt.Errorf("import bypass %s/%s:%s: %w", bypass.Registry, bypass.Repository, bypass.Tag, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit import state: %w", err)
	}
	return nil
}

func (s *SQLiteStore) listAllObservations(ctx context.Context) ([]Observation, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, registry, repository, tag, digest, first_seen_at, last_seen_at, last_allowed_at, status
FROM tag_observations
ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list all observations: %w", err)
	}
	defer rows.Close()

	var observations []Observation
	for rows.Next() {
		obs, err := scanObservationRows(rows)
		if err != nil {
			return nil, err
		}
		observations = append(observations, obs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list all observations: %w", err)
	}
	return observations, nil
}

func (s *SQLiteStore) listApprovals(ctx context.Context) ([]Approval, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, registry, repository, tag, digest, approved_at, approved_by, reason, expires_at
FROM approvals
ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list approvals: %w", err)
	}
	defer rows.Close()

	var approvals []Approval
	for rows.Next() {
		approval, err := scanApprovalRows(rows)
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, approval)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list approvals: %w", err)
	}
	return approvals, nil
}

func (s *SQLiteStore) listFreezes(ctx context.Context) ([]Freeze, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, registry, repository, tag, digest, created_at, created_by, reason, expires_at
FROM freezes
ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list freezes: %w", err)
	}
	defer rows.Close()

	var freezes []Freeze
	for rows.Next() {
		freeze, err := scanFreezeRows(rows)
		if err != nil {
			return nil, err
		}
		freezes = append(freezes, freeze)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list freezes: %w", err)
	}
	return freezes, nil
}

func (s *SQLiteStore) listBypasses(ctx context.Context) ([]Bypass, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, registry, repository, tag, created_at, created_by, reason, expires_at
FROM bypasses
ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list bypasses: %w", err)
	}
	defer rows.Close()

	var bypasses []Bypass
	for rows.Next() {
		bypass, err := scanBypassRows(rows)
		if err != nil {
			return nil, err
		}
		bypasses = append(bypasses, bypass)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list bypasses: %w", err)
	}
	return bypasses, nil
}

func scanObservation(scanner interface {
	Scan(dest ...any) error
}) (*Observation, error) {
	obs, err := scanObservationValue(scanner)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get observation: %w", err)
	}
	return &obs, nil
}

func scanObservationRows(scanner interface {
	Scan(dest ...any) error
}) (Observation, error) {
	obs, err := scanObservationValue(scanner)
	if err != nil {
		return Observation{}, fmt.Errorf("list observations: %w", err)
	}
	return obs, nil
}

func scanDecisionRows(scanner interface {
	Scan(dest ...any) error
}) (DecisionRecord, error) {
	var decision DecisionRecord
	var timestamp int64
	if err := scanner.Scan(&decision.ID, &timestamp, &decision.ImageRef, &decision.Registry, &decision.Repository, &decision.Tag, &decision.Digest, &decision.Decision, &decision.Reason, &decision.ClientUser, &decision.RequestMethod, &decision.RequestURI); err != nil {
		return DecisionRecord{}, fmt.Errorf("list decisions: %w", err)
	}
	decision.Timestamp = time.Unix(timestamp, 0).UTC()
	return decision, nil
}

func scanObservationValue(scanner interface {
	Scan(dest ...any) error
}) (Observation, error) {
	var obs Observation
	var firstSeen, lastSeen int64
	var lastAllowed sql.NullInt64
	if err := scanner.Scan(&obs.ID, &obs.Registry, &obs.Repository, &obs.Tag, &obs.Digest, &firstSeen, &lastSeen, &lastAllowed, &obs.Status); err != nil {
		return Observation{}, err
	}
	obs.FirstSeenAt = time.Unix(firstSeen, 0).UTC()
	obs.LastSeenAt = time.Unix(lastSeen, 0).UTC()
	if lastAllowed.Valid {
		t := time.Unix(lastAllowed.Int64, 0).UTC()
		obs.LastAllowedAt = &t
	}
	return obs, nil
}

func scanApproval(scanner interface {
	Scan(dest ...any) error
}) (*Approval, error) {
	approval, err := scanApprovalValue(scanner)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get approval: %w", err)
	}
	return &approval, nil
}

func scanApprovalRows(scanner interface {
	Scan(dest ...any) error
}) (Approval, error) {
	approval, err := scanApprovalValue(scanner)
	if err != nil {
		return Approval{}, fmt.Errorf("list approvals: %w", err)
	}
	return approval, nil
}

func scanApprovalValue(scanner interface {
	Scan(dest ...any) error
}) (Approval, error) {
	var approval Approval
	var approvedAt int64
	var expiresAt sql.NullInt64
	if err := scanner.Scan(&approval.ID, &approval.Registry, &approval.Repository, &approval.Tag, &approval.Digest, &approvedAt, &approval.ApprovedBy, &approval.Reason, &expiresAt); err != nil {
		return Approval{}, err
	}
	approval.ApprovedAt = time.Unix(approvedAt, 0).UTC()
	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0).UTC()
		approval.ExpiresAt = &t
	}
	return approval, nil
}

func scanFreeze(scanner interface {
	Scan(dest ...any) error
}) (*Freeze, error) {
	freeze, err := scanFreezeValue(scanner)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get freeze: %w", err)
	}
	return &freeze, nil
}

func scanFreezeRows(scanner interface {
	Scan(dest ...any) error
}) (Freeze, error) {
	freeze, err := scanFreezeValue(scanner)
	if err != nil {
		return Freeze{}, fmt.Errorf("list freezes: %w", err)
	}
	return freeze, nil
}

func scanFreezeValue(scanner interface {
	Scan(dest ...any) error
}) (Freeze, error) {
	var freeze Freeze
	var createdAt int64
	var digest sql.NullString
	var expiresAt sql.NullInt64
	if err := scanner.Scan(&freeze.ID, &freeze.Registry, &freeze.Repository, &freeze.Tag, &digest, &createdAt, &freeze.CreatedBy, &freeze.Reason, &expiresAt); err != nil {
		return Freeze{}, err
	}
	freeze.Digest = digest.String
	freeze.CreatedAt = time.Unix(createdAt, 0).UTC()
	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0).UTC()
		freeze.ExpiresAt = &t
	}
	return freeze, nil
}

func scanBypass(scanner interface {
	Scan(dest ...any) error
}) (*Bypass, error) {
	bypass, err := scanBypassValue(scanner)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get bypass: %w", err)
	}
	return &bypass, nil
}

func scanBypassRows(scanner interface {
	Scan(dest ...any) error
}) (Bypass, error) {
	bypass, err := scanBypassValue(scanner)
	if err != nil {
		return Bypass{}, fmt.Errorf("list bypasses: %w", err)
	}
	return bypass, nil
}

func scanBypassValue(scanner interface {
	Scan(dest ...any) error
}) (Bypass, error) {
	var bypass Bypass
	var createdAt int64
	var expiresAt sql.NullInt64
	if err := scanner.Scan(&bypass.ID, &bypass.Registry, &bypass.Repository, &bypass.Tag, &createdAt, &bypass.CreatedBy, &bypass.Reason, &expiresAt); err != nil {
		return Bypass{}, err
	}
	bypass.CreatedAt = time.Unix(createdAt, 0).UTC()
	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0).UTC()
		bypass.ExpiresAt = &t
	}
	return bypass, nil
}

func requireAffected(result sql.Result, operation string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: read affected rows: %w", operation, err)
	}
	if rows == 0 {
		return fmt.Errorf("%s: no matching row", operation)
	}
	return nil
}

func unix(t time.Time) int64 {
	return t.UTC().Unix()
}

func nullableUnix(t *time.Time) any {
	if t == nil {
		return nil
	}
	return unix(*t)
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
