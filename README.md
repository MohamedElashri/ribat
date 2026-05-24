# Ribat

Ribat is a Docker image update gate for mutable tags such as `latest`, `stable`, and rolling release tags. It is designed to observe the digest a tag resolves to, keep new digests in quarantine for a configured age, and only allow pulls after the policy is satisfied.

The current implementation includes a Go command-line application, local quarantine state, registry digest resolution, and Docker authorization plugin mode. Later phases will add installation packaging, verification backends, and proxy mode.

## Usage
```bash
go run ./cmd/ribat version
go run ./cmd/ribat inspect docker.io/library/alpine:latest
go run ./cmd/ribat decide --config /path/to/ribat.yaml docker.io/library/alpine:latest
go run ./cmd/ribat authz --config /path/to/ribat.yaml --socket /run/docker/plugins/ribat.sock
go test ./...
```

## Configuration

An example policy is available at `configs/ribat.example.yaml`.
