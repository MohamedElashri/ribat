# Ribat

Ribat is a Docker image update gate for mutable tags such as `latest`, `stable`, and rolling release tags. It is designed to observe the digest a tag resolves to, keep new digests in quarantine for a configured age, and only allow pulls after the policy is satisfied.

The initial implementation is a Go command-line application. Future phases will add Docker authorization plugin mode, registry digest resolution, persistent quarantine state, verification checks, and audit logging.

## Usage
```bash
go run ./cmd/ribat version
go test ./...
```

## Configuration

An example policy is available at `configs/ribat.example.yaml`.
