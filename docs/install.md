# Installing Ribat on a Docker Host

This guide installs Ribat as a systemd service that exposes a Docker authorization plugin socket at `/run/docker/plugins/ribat.sock`.

## Paths

Ribat uses these host paths by convention:

```text
/etc/ribat/config.yaml
/var/lib/ribat/state.db
/var/log/ribat/audit.jsonl
/run/docker/plugins/ribat.sock
```

The SQLite state file lives under `/var/lib/ribat`, so restarting Docker or Ribat does not clear quarantine observations, approvals, or freezes.

## Install

Build and install the binary, example config, state directory, log directory, and systemd service:

```bash
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now ribat.service
```

Check that the plugin endpoint is reachable:

```bash
sudo curl --unix-socket /run/docker/plugins/ribat.sock -X POST http://localhost/Plugin.Activate
```

The response should include `authz`.

## Docker Daemon Configuration

Merge this setting into `/etc/docker/daemon.json`:

```json
{
  "authorization-plugins": ["ribat"]
}
```

An example file is available at `packaging/docker/daemon-ribat.json`. If your Docker daemon already has a `daemon.json`, merge the `authorization-plugins` key instead of replacing the whole file.

Install the optional Docker systemd drop-in so Docker starts after Ribat:

```bash
sudo make install-docker-dropin
sudo systemctl daemon-reload
sudo systemctl restart docker
```

After Docker restarts, first-seen mutable-tag pulls should be denied and recorded according to `/etc/ribat/config.yaml`.

## Disable

To disable Ribat without deleting state:

```bash
sudo systemctl stop docker
```

Remove `ribat` from the `authorization-plugins` list in `/etc/docker/daemon.json`.

If you installed the Docker drop-in, remove it:

```bash
sudo rm -f /etc/systemd/system/docker.service.d/10-ribat.conf
sudo systemctl daemon-reload
```

Then restart Docker and stop Ribat:

```bash
sudo systemctl start docker
sudo systemctl disable --now ribat.service
```

## Rollback

Use this rollback when Docker cannot start or pulls are blocked unexpectedly:

```bash
sudo systemctl stop docker
sudo rm -f /etc/systemd/system/docker.service.d/10-ribat.conf
```

Edit `/etc/docker/daemon.json` and remove `ribat` from `authorization-plugins`.

Then reload systemd and start Docker:

```bash
sudo systemctl daemon-reload
sudo systemctl start docker
```

The rollback leaves `/var/lib/ribat/state.db` and `/var/log/ribat/audit.jsonl` in place for inspection. Remove the service and binary only after Docker is healthy:

```bash
sudo make uninstall
```
