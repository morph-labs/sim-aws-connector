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

Inside the container:
- `AWS_REGION` / `AWS_DEFAULT_REGION` default to the first region in the connect bundle (if not already set).
- `AWS_PAGER` defaults to empty (paging disabled).
- Dummy credentials are set if `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are both unset.
- The tunnel client sends periodic WebSocket pings and reconnects automatically if the gateway closes idle connections.

AWS CLI/SDKs should work with default endpoints (no `--endpoint-url`) as long as your AWS credentials are available via env vars/profiles.
