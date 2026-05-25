# Ribat Troubleshooting

## Docker Does Not Start

Rollback safely:

```bash
sudo systemctl stop docker
sudo rm -f /etc/systemd/system/docker.service.d/10-ribat.conf
```

Remove `ribat` from `/etc/docker/daemon.json` under `authorization-plugins`, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl start docker
```

The rollback leaves `/var/lib/ribat/state.db` and `/var/log/ribat/audit.jsonl` available for inspection.

## Plugin Socket Is Missing

Check the service:

```bash
sudo systemctl status ribat.service
sudo journalctl -u ribat.service
```

Confirm the activation endpoint:

```bash
sudo curl --unix-socket /run/docker/plugins/ribat.sock -X POST http://localhost/Plugin.Activate
```

The response should mention `authz`.

## Pulls Are Denied

Inspect the decision:

```bash
ribat decide --config /etc/ribat/config.yaml docker.io/library/alpine:latest
```

Then check local state and audit logs:

```bash
ribat status --config /etc/ribat/config.yaml docker.io/library/alpine:latest
ribat audit --config /etc/ribat/config.yaml --image docker.io/library/alpine:latest --since 24h
```

Common reasons are first-seen quarantine, digest age below policy, active freeze, registry resolution failure, or Cosign verification failure.

## Cosign Verification Fails

Confirm `cosign` is installed on the Ribat host:

```bash
cosign version
```

Check that the policy identity, identity regex, issuer, and key path match the image publisher. Ribat verifies the resolved digest, so the signature must cover the digest returned by the registry.

## Build Pulls Are Denied

`docker build --pull` is denied by design in the current AuthZ mode. Pre-pull approved base images, use digest-pinned bases, and run builds without `--pull`.

## Registry Proxy Pull Fails

Use the explicit upstream-registry path convention:

```bash
docker pull 127.0.0.1:5000/docker.io/library/alpine:latest
docker pull 127.0.0.1:5000/ghcr.io/example/app:main
```

Proxy mode currently gates manifests and blobs for pull enforcement. It does not implement uploads, catalog, tag listing, or persistent blob caching.
