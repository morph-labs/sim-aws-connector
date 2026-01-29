#!/usr/bin/env bash
set -euo pipefail
umask 077

log() { printf '[sim-aws-connector] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

cleanup() {
  set +e
  if [[ -n "${WG_IFACE:-}" ]]; then
    ip link del "$WG_IFACE" >/dev/null 2>&1 || true
  fi
  if [[ -n "${WGGO_PID:-}" ]]; then
    kill "$WGGO_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${TUNNEL_PID:-}" ]]; then
    kill "$TUNNEL_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${headers_file:-}" ]]; then
    rm -f "$headers_file" >/dev/null 2>&1 || true
  fi
  if [[ -n "${privkey_file:-}" ]]; then
    rm -f "$privkey_file" >/dev/null 2>&1 || true
  fi
  if [[ -n "${ca_file:-}" ]]; then
    rm -f "$ca_file" >/dev/null 2>&1 || true
  fi
  if [[ -n "${bundle_file:-}" && "${CONNECT_BUNDLE_JSON:-}" != "" ]]; then
    rm -f "$bundle_file" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

require_cmd jq
require_cmd ip
require_cmd wg
require_cmd wireguard-go
require_cmd python3

[[ -c /dev/net/tun ]] || die "/dev/net/tun is not available (run with --device=/dev/net/tun and --cap-add=NET_ADMIN)"

CONNECT_BUNDLE_PATH="${CONNECT_BUNDLE_PATH:-/run/connect-bundle.json}"
CONNECT_BUNDLE_JSON="${CONNECT_BUNDLE_JSON:-}"

bundle_file="$CONNECT_BUNDLE_PATH"
if [[ -n "$CONNECT_BUNDLE_JSON" ]]; then
  bundle_file="$(mktemp)"
  chmod 600 "$bundle_file"
  printf '%s' "$CONNECT_BUNDLE_JSON" >"$bundle_file"
fi

[[ -r "$bundle_file" ]] || die "connect bundle not found/readable at: $bundle_file"

WG_IFACE="${WG_IFACE:-wg0}"
LOCAL_WG_UDP_PORT="${LOCAL_WG_UDP_PORT:-51820}"

tunnel_ws_url="$(jq -er '.tunnel_ws_url' "$bundle_file")"

auth_header_name="$(jq -er '.auth.header_name' "$bundle_file")"
auth_header_value_template="$(jq -er '.auth.header_value_template' "$bundle_file")"

MORPH_API_KEY="${MORPH_API_KEY:-}"
[[ -n "$MORPH_API_KEY" ]] || die "MORPH_API_KEY is required (do not pass it on the command line; use -e MORPH_API_KEY)"

if [[ "$auth_header_value_template" != *'${MORPH_API_KEY}'* ]]; then
  die "auth.header_value_template must contain \${MORPH_API_KEY}"
fi
auth_header_value="${auth_header_value_template//'${MORPH_API_KEY}'/$MORPH_API_KEY}"

wg_client_private_key="$(jq -er '.wg.client_private_key' "$bundle_file")"
wg_client_address="$(jq -er '.wg.client_address' "$bundle_file")"
wg_server_public_key="$(jq -er '.wg.server_public_key' "$bundle_file")"
wg_endpoint_host="$(jq -er '.wg.endpoint_host' "$bundle_file")"
wg_endpoint_port="$(jq -er '.wg.endpoint_port | tostring' "$bundle_file")"
wg_mtu="$(jq -r '.wg.mtu // empty' "$bundle_file")"
wg_persistent_keepalive="$(jq -r '.wg.persistent_keepalive // empty' "$bundle_file")"

dns_nameserver="$(jq -er '.dns.nameserver' "$bundle_file")"

tls_ca_cert_pem="$(jq -r '.tls.ca_cert_pem // empty' "$bundle_file")"
tls_ca_fingerprint_sha256="$(jq -r '.tls.ca_fingerprint_sha256 // empty' "$bundle_file")"

allowed_ips_csv="$(jq -er '.wg.allowed_ips | if type=="array" then join(",") else . end' "$bundle_file")"

log "starting tunnel + wireguard (iface=$WG_IFACE, local_udp=127.0.0.1:${LOCAL_WG_UDP_PORT})"

headers_file="$(mktemp)"
chmod 600 "$headers_file"
printf '%s: %s\n' "$auth_header_name" "$auth_header_value" >"$headers_file"

ca_file=""
if [[ -n "$tls_ca_cert_pem" ]]; then
  ca_file="$(mktemp)"
  chmod 600 "$ca_file"
  # shellcheck disable=SC2059
  printf '%s\n' "$tls_ca_cert_pem" >"$ca_file"
  export AWS_CA_BUNDLE="$ca_file"
  export REQUESTS_CA_BUNDLE="$ca_file"
  export CURL_CA_BUNDLE="$ca_file"
  export SSL_CERT_FILE="$ca_file"
elif [[ -n "$tls_ca_fingerprint_sha256" ]]; then
  log "WARN: tls.ca_cert_pem not provided (only fingerprint present); cannot set AWS_CA_BUNDLE"
fi

extract_url_hostport() {
  local url="$1"
  local rest hostport
  rest="${url#*://}"
  hostport="${rest%%/*}"
  hostport="${hostport##*@}"
  printf '%s' "$hostport"
}

pin_route_to_hostport() {
  local hostport="$1"
  local host="${hostport}"
  if [[ "$hostport" == \[*\]* ]]; then
    host="${hostport#\[}"
    host="${host%%\]*}"
  else
    host="${hostport%%:*}"
  fi

  if [[ -z "$host" ]]; then
    return 0
  fi

  if [[ "$host" =~ ^[0-9.]+$ ]]; then
    # already an IPv4
    local ip="$host"
    local route
    route="$(ip route get "$ip" 2>/dev/null || true)"
    if [[ "$route" == *" via "* && "$route" == *" dev "* ]]; then
      local via dev
      via="$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$route")"
      dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$route")"
      if [[ -n "$via" && -n "$dev" ]]; then
        ip route replace "${ip}/32" via "$via" dev "$dev" >/dev/null 2>&1 || true
      fi
    fi
    return 0
  fi

  local ip
  ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}' || true)"
  if [[ -z "$ip" ]]; then
    ip="$(getent hosts "$host" 2>/dev/null | awk 'NR==1{print $1}' || true)"
  fi
  if [[ -n "$ip" ]]; then
    local route
    route="$(ip route get "$ip" 2>/dev/null || true)"
    if [[ "$route" == *" via "* && "$route" == *" dev "* ]]; then
      local via dev
      via="$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$route")"
      dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$route")"
      if [[ -n "$via" && -n "$dev" ]]; then
        ip route replace "${ip}/32" via "$via" dev "$dev" >/dev/null 2>&1 || true
      fi
    fi
  fi
}

hostport="$(extract_url_hostport "$tunnel_ws_url")"
pin_route_to_hostport "$hostport"

TUNNEL_HEADER="$(cat "$headers_file")"
python3 /usr/local/bin/ws_udp_tunnel_client.py \
  --ws-url "$tunnel_ws_url" \
  --udp-listen "127.0.0.1:${LOCAL_WG_UDP_PORT}" \
  --header "$TUNNEL_HEADER" &
TUNNEL_PID="$!"

# Wait for UDP listener to appear.
for _ in $(seq 1 50); do
  if ss -lun 2>/dev/null | awk '{print $5}' | grep -qE "(:|\\])${LOCAL_WG_UDP_PORT}$"; then
    break
  fi
  sleep 0.1
done

privkey_file="$(mktemp)"
chmod 600 "$privkey_file"
printf '%s\n' "$wg_client_private_key" >"$privkey_file"

wireguard-go "$WG_IFACE" &
WGGO_PID="$!"

for _ in $(seq 1 50); do
  if wg show "$WG_IFACE" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

wg_args=(
  set "$WG_IFACE"
  private-key "$privkey_file"
  peer "$wg_server_public_key"
  allowed-ips "$allowed_ips_csv"
  endpoint "127.0.0.1:${LOCAL_WG_UDP_PORT}"
)
if [[ -n "$wg_persistent_keepalive" ]]; then
  wg_args+=(persistent-keepalive "$wg_persistent_keepalive")
fi
wg "${wg_args[@]}"

if [[ -n "$wg_mtu" ]]; then
  ip link set dev "$WG_IFACE" mtu "$wg_mtu"
fi

ip address add "$wg_client_address" dev "$WG_IFACE" 2>/dev/null || true
ip link set up dev "$WG_IFACE"

# Preserve the current default route (if any) when adding a wg default route.
add_default_route_v4() {
  local line via dev
  line="$(ip route show default 2>/dev/null | head -n1 || true)"
  if [[ -n "$line" && "$line" == *" via "* && "$line" == *" dev "* ]]; then
    via="$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$line")"
    dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$line")"
    if [[ -n "$via" && -n "$dev" ]]; then
      ip route replace default via "$via" dev "$dev" metric 500 >/dev/null 2>&1 || true
      ip route add default dev "$WG_IFACE" metric 100 >/dev/null 2>&1 || ip route replace default dev "$WG_IFACE" >/dev/null 2>&1 || true
    fi
  else
    ip route add default dev "$WG_IFACE" metric 100 >/dev/null 2>&1 || true
  fi
}

emit_allowed_ips() {
  if jq -e '.wg.allowed_ips | type=="array"' "$bundle_file" >/dev/null 2>&1; then
    jq -er '.wg.allowed_ips[]' "$bundle_file"
    return 0
  fi

  local s
  s="$(jq -er '.wg.allowed_ips' "$bundle_file")"
  if [[ "$s" == *","* ]]; then
    tr ',' '\n' <<<"$s"
  else
    printf '%s\n' "$s"
  fi
}

# Add routes for AllowedIPs (wg-quick normally does this).
emit_allowed_ips | while IFS= read -r cidr; do
  cidr="${cidr#"${cidr%%[![:space:]]*}"}"
  cidr="${cidr%"${cidr##*[![:space:]]}"}"
  [[ -z "$cidr" ]] && continue
  if [[ "$cidr" == "0.0.0.0/0" ]]; then
    add_default_route_v4
    continue
  fi
  ip route replace "$cidr" dev "$WG_IFACE" >/dev/null 2>&1 || true
done

# Ensure the nameserver is reachable over wg.
if [[ "$dns_nameserver" =~ ^[0-9.]+$ ]]; then
  ip route replace "${dns_nameserver}/32" dev "$WG_IFACE" >/dev/null 2>&1 || true
fi

# Configure resolver for in-tunnel DNS.
if [[ -w /etc/resolv.conf ]]; then
  cp -f /etc/resolv.conf /tmp/resolv.conf.bak 2>/dev/null || true
  {
    printf 'nameserver %s\n' "$dns_nameserver"
    printf 'options edns0 trust-ad\n'
  } >/etc/resolv.conf
else
  log "WARN: /etc/resolv.conf is not writable; pass --dns ${dns_nameserver} to docker run"
fi

log "ready; exec: ${1:-bash}"
exec "$@"
