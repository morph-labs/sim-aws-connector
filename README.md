# sim-aws-connector

Sim-AWS connector container (WireGuard + ws/udp tunnel client).

The connector:
- reads a Sim-AWS connect bundle (`connect_bundle_v1`),
- tunnels WireGuard UDP over a Morph instance HTTP WebSocket tunnel,
- brings up `wg0`, configures DNS, sets `AWS_CA_BUNDLE`,
- then runs your command (default `bash`).

## Build

```bash
docker build -t sim-aws-connector:local connector
```

## Run

```bash
docker run --rm -it \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -e MORPH_API_KEY \
  -v "$PWD/aws-sim-connect-bundle.json:/bundle.json:ro" \
  sim-aws-connector:local \
  --bundle /bundle.json
```

Inside the container, AWS CLI/SDKs should work with default endpoints (no `--endpoint-url`) as long as your AWS credentials are available via env vars/profiles.
