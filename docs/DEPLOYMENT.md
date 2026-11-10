# Deployment

HostProof runs from one place and assesses Linux hosts over SSH. Nothing needs to stay on the target unless you choose the fixed probe option. The LLM runs in its own container on a private network.

## Requirements

- Docker with Compose, on a machine that can reach your hosts over SSH
- `/usr/bin/python3` on each target host
- One scanner report per host, such as Trivy JSON

Local models are memory-hungry. Allow enough memory for your chosen model, and give Docker Desktop that much if you use it. On Linux, you can add an NVIDIA GPU to the `ollama` service.

## Set up

```bash
cp -r workspace.example workspace
docker compose up -d ollama
docker compose exec ollama ollama pull qwen2.5:7b
```

Create a dedicated SSH key, and record each host's key after checking it through a trusted route:

```bash
ssh-keygen -t ed25519 -N "" -f workspace/ssh/id_ed25519
ssh-keyscan -H HOST_ADDRESS >> workspace/ssh/known_hosts
```

HostProof refuses hosts it doesn't recognise, and it never turns off host key checking.

Create a report on each host, then copy it to `workspace/reports/`:

```bash
sudo trivy rootfs --scanners vuln --pkg-types os --format json --output web01.json /
```

List your hosts in `workspace/hosts.yaml`. Paths are relative to that file.

## Scan

```bash
docker compose run --rm hostproof scan --inventory hosts.yaml --out runs
```

Results go to `workspace/runs/`: one report and OpenVEX draft for the fleet, plus an audit log per host. On Linux, the container runs as user `10001`, so that user must be able to write to `workspace/`.

The exit code is `3` if any host couldn't be assessed, and those hosts are listed at the end of the output.

| Option | Default | Purpose |
| --- | --- | --- |
| `--workers` | 8 | Hosts checked at the same time |
| `--max-model-findings` | 25 | Findings sent to the model across all hosts, most exposed first |
| `--llm none` | Off | Rules and ranking only, with no model |
| `--show` | 20 | Rows shown on screen. The report has them all |

To use Ollama running elsewhere, set `HOSTPROOF_OLLAMA_URL` in `docker-compose.yml`.

## Access on target hosts

The probe needs root to inspect every process. Without it, results are marked incomplete, and nothing that depends on them gets dismissed.

### For a lab: send the probe over SSH

```text
hostproof ALL=(root) NOPASSWD: /usr/bin/python3 -I - *
```

This is the simplest setup, with nothing installed on the host. **It gives that account full root**, as it can send any Python code. Use it only in a lab.

### For production: install one fixed probe

Copy `src/hostproof/probe.py` to each host, owned by root and not writable by anyone else:

```bash
sudo install -o root -g root -m 0644 -D probe.py /opt/hostproof/probe.py
```

Allow only that file:

```text
hostproof ALL=(root) NOPASSWD: /usr/bin/python3 -I /opt/hostproof/probe.py *
```

Then set this in the inventory:

```yaml
defaults:
  probe_path: /opt/hostproof/probe.py
```

The account can now only run the probe's read-only checks. The probe enforces its own limits, so it refuses other check names and secret-looking paths even if it's called directly.

Roll out a new probe file whenever you upgrade HostProof.

### When SSH isn't possible

For air-gapped hosts, or hosts with no SSH service, install HostProof on the host and use `--target local`.

## Protecting the controller

One machine with SSH access to a fleet is a valuable target:

- Use a dedicated key for HostProof, and no other purpose
- Restrict where that key can connect from, using `from=` in `authorized_keys`
- Keep `workspace/` out of Git, and limit who can read it, as it holds keys and host details
- Send audit logs to a separate system, as Phase 3 will support natively

## How it scales

- **Hosts run in parallel:** the plain-rule pass uses up to `--workers` hosts at a time.
- **Checks are cached:** each check runs once per package on each host, however many CVEs affect that package.
- **The model is the bottleneck:** it runs one finding at a time, on the most exposed findings across the fleet.

Each check currently opens its own SSH connection, and a very large fleet will need connection reuse and resumable scans. See the [roadmap](ROADMAP.md).
