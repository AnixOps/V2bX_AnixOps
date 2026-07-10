#!/usr/bin/env bash
# Privileged acceptance test for the real V2bX WireGuard -> GOST relay -> NAT
# path. It is intentionally executed only by GitHub Actions release/manual jobs.

set -Eeuo pipefail

BIN="${V2BX_WIREGUARD_INTEGRATION_BIN:-}"
GOST_BIN="${GOST_BIN:-gost}"
LOG_DIR="${WIREGUARD_INTEGRATION_LOG_DIR:-$(pwd)/wireguard-integration-artifacts}"
TUNNEL_TYPE="${WIREGUARD_RELAY_TUNNEL_TYPE:-quic}"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "wireguard relay integration must run as root" >&2
  exit 1
fi
if [[ -z "${BIN}" || ! -x "${BIN}" ]]; then
  echo "V2BX_WIREGUARD_INTEGRATION_BIN must reference an executable integration runner" >&2
  exit 1
fi
if [[ "${TUNNEL_TYPE}" != "quic" && "${TUNNEL_TYPE}" != "wss" ]]; then
  echo "WIREGUARD_RELAY_TUNNEL_TYPE must be quic or wss" >&2
  exit 1
fi

for command in ip wg iptables curl openssl python3 "${GOST_BIN}"; do
  require_command "${command}"
done

if [[ ! -c /dev/net/tun ]]; then
  echo "/dev/net/tun is unavailable; this runner cannot perform the privileged WireGuard test" >&2
  exit 1
fi

mkdir -p "${LOG_DIR}"
chmod 0700 "${LOG_DIR}"
WORK_DIR="$(mktemp -d /tmp/v2bx-wireguard-relay.XXXXXX)"
chmod 0700 "${WORK_DIR}"
PIDS=()
NAMESPACES=(wg-client wg-entry wg-exit wg-internet)

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "${pid}" 2>/dev/null || true
  done
  for namespace in "${NAMESPACES[@]}"; do
    ip netns del "${namespace}" 2>/dev/null || true
  done
  rm -rf "${WORK_DIR}"
  chmod -R a+rX "${LOG_DIR}" 2>/dev/null || true
  exit "${status}"
}
trap cleanup EXIT

wait_for_file() {
  local path="$1"
  local deadline=$((SECONDS + 30))
  until [[ -s "${path}" ]]; do
    if (( SECONDS >= deadline )); then
      echo "timed out waiting for ${path}" >&2
      return 1
    fi
    sleep 0.25
  done
}

wait_for_link() {
  local namespace="$1"
  local link="$2"
  local deadline=$((SECONDS + 30))
  until ip -n "${namespace}" link show "${link}" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "timed out waiting for ${namespace}/${link}" >&2
      return 1
    fi
    sleep 0.25
  done
}

for namespace in "${NAMESPACES[@]}"; do
  ip netns add "${namespace}"
  ip -n "${namespace}" link set lo up
done

# Client <-> entry control path, entry <-> exit relay transport, and exit
# <-> internet egress are isolated so packets cannot bypass the relay path.
ip link add entry-client type veth peer name client-link
ip link set entry-client netns wg-entry
ip link set client-link netns wg-client
ip -n wg-entry addr add 192.0.2.1/24 dev entry-client
ip -n wg-entry link set entry-client up
ip -n wg-client addr add 192.0.2.2/24 dev client-link
ip -n wg-client link set client-link up

ip link add entry-relay type veth peer name exit-relay
ip link set entry-relay netns wg-entry
ip link set exit-relay netns wg-exit
ip -n wg-entry addr add 172.16.1.1/24 dev entry-relay
ip -n wg-entry link set entry-relay up
ip -n wg-exit addr add 172.16.1.2/24 dev exit-relay
ip -n wg-exit link set exit-relay up

ip link add exit-uplink type veth peer name internet-link
ip link set exit-uplink netns wg-exit
ip link set internet-link netns wg-internet
ip -n wg-exit addr add 198.51.100.1/24 dev exit-uplink
ip -n wg-exit link set exit-uplink up
ip -n wg-internet addr add 198.51.100.2/24 dev internet-link
ip -n wg-internet link set internet-link up

# The entry and exit must install their route-specific FORWARD rules.
# A default-drop policy prevents the acceptance test from passing because of the
# namespace's permissive firewall default.
ip netns exec wg-entry iptables -P FORWARD DROP
ip netns exec wg-exit iptables -P FORWARD DROP

umask 077
ENTRY_PRIVATE_KEY="$(wg genkey)"
ENTRY_PUBLIC_KEY="$(printf '%s' "${ENTRY_PRIVATE_KEY}" | wg pubkey)"
CLIENT_PRIVATE_KEY="$(wg genkey)"
CLIENT_PUBLIC_KEY="$(printf '%s' "${CLIENT_PRIVATE_KEY}" | wg pubkey)"
PRESHARED_KEY="$(wg genpsk)"
CLIENT_PRIVATE_FILE="${WORK_DIR}/client-private.key"
PRESHARED_FILE="${WORK_DIR}/preshared.key"
printf '%s\n' "${CLIENT_PRIVATE_KEY}" >"${CLIENT_PRIVATE_FILE}"
printf '%s\n' "${PRESHARED_KEY}" >"${PRESHARED_FILE}"

WSS_ENTRY_ARGS=()
WSS_EXIT_ARGS=()
if [[ "${TUNNEL_TYPE}" == "wss" ]]; then
  WSS_CERT_FILE="${WORK_DIR}/relay-cert.pem"
  WSS_KEY_FILE="${WORK_DIR}/relay-key.pem"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=relay.integration.test' \
    -addext 'subjectAltName=DNS:relay.integration.test' \
    -keyout "${WSS_KEY_FILE}" -out "${WSS_CERT_FILE}" \
    >"${LOG_DIR}/wss-certificate.log" 2>&1
  WSS_ENTRY_ARGS=(
    --wss-path /wireguard
    --wss-server-name relay.integration.test
    --wss-ca-file "${WSS_CERT_FILE}"
  )
  WSS_EXIT_ARGS=(
    --wss-path /wireguard
    --wss-cert-file "${WSS_CERT_FILE}"
    --wss-key-file "${WSS_KEY_FILE}"
  )
fi

mkdir -p "${WORK_DIR}/www"
printf 'wireguard-gost-integration-ok\n' >"${WORK_DIR}/www/health"
ip netns exec wg-internet python3 -m http.server 8080 \
  --bind 198.51.100.2 --directory "${WORK_DIR}/www" \
  >"${LOG_DIR}/internet-http.log" 2>&1 &
PIDS+=("$!")

ip netns exec wg-exit "${BIN}" \
  --role exit \
  --tunnel-type "${TUNNEL_TYPE}" \
  "${WSS_EXIT_ARGS[@]}" \
  --tag integration-exit \
  --runtime-dir "${WORK_DIR}/exit-runtime" \
  --ready-file "${WORK_DIR}/exit.ready" \
  --gost-path "${GOST_BIN}" \
  --relay-server 172.16.1.2 \
  --relay-server-port 18443 \
  --tun-port 18421 \
  --tun-name gtwgitexit \
  --entry-tun-address 172.31.66.2/24 \
  --exit-tun-address 172.31.66.1/24 \
  --outbound-interface exit-uplink \
  >"${LOG_DIR}/exit.log" 2>&1 &
PIDS+=("$!")
wait_for_file "${WORK_DIR}/exit.ready"
wait_for_link wg-exit gtwgitexit

ip netns exec wg-entry "${BIN}" \
  --role entry \
  --tunnel-type "${TUNNEL_TYPE}" \
  "${WSS_ENTRY_ARGS[@]}" \
  --tag integration-entry \
  --runtime-dir "${WORK_DIR}/entry-runtime" \
  --ready-file "${WORK_DIR}/entry.ready" \
  --gost-path "${GOST_BIN}" \
  --server-private-key "${ENTRY_PRIVATE_KEY}" \
  --peer-public-key "${CLIENT_PUBLIC_KEY}" \
  --peer-preshared-key "${PRESHARED_KEY}" \
  --peer-ip 10.66.0.2 \
  --relay-server 172.16.1.2 \
  --relay-server-port 18443 \
  --tun-port 18421 \
  --tun-name gtwgitentry \
  --entry-tun-address 172.31.66.2/24 \
  --exit-tun-address 172.31.66.1/24 \
  >"${LOG_DIR}/entry.log" 2>&1 &
PIDS+=("$!")
wait_for_file "${WORK_DIR}/entry.ready"
wait_for_link wg-entry gtwgitentry

ip -n wg-client link add wgclient type wireguard
ip -n wg-client addr add 10.66.0.2/32 dev wgclient
ip netns exec wg-client wg set wgclient \
  private-key "${CLIENT_PRIVATE_FILE}" \
  peer "${ENTRY_PUBLIC_KEY}" \
  preshared-key "${PRESHARED_FILE}" \
  endpoint 192.0.2.1:51820 \
  allowed-ips 198.51.100.0/24 \
  persistent-keepalive 5
ip -n wg-client link set mtu 1280 dev wgclient
ip -n wg-client link set wgclient up
ip -n wg-client route replace 198.51.100.0/24 dev wgclient

handshake_deadline=$((SECONDS + 30))
until [[ "$(ip netns exec wg-client wg show wgclient latest-handshakes | awk '{print $2}')" != "0" ]]; do
  if (( SECONDS >= handshake_deadline )); then
    echo "WireGuard client did not complete a handshake" >&2
    exit 1
  fi
  sleep 0.25
done

response=""
curl_deadline=$((SECONDS + 40))
until response="$(ip netns exec wg-client curl --fail --silent --show-error --max-time 4 http://198.51.100.2:8080/health 2>/dev/null)"; do
  if (( SECONDS >= curl_deadline )); then
    echo "WireGuard -> GOST relay+${TUNNEL_TYPE} -> exit NAT HTTP request timed out" >&2
    exit 1
  fi
  sleep 0.5
done
if [[ "${response}" != "wireguard-gost-integration-ok" ]]; then
  echo "unexpected integration response: ${response}" >&2
  exit 1
fi

{
  echo "result=pass"
  echo "path=WireGuard client -> V2bX entry -> GOST relay+${TUNNEL_TYPE} -> V2bX exit NAT -> HTTP target"
  echo
  echo "[client wg]"
  ip netns exec wg-client wg show wgclient
  echo
  echo "[entry policy]"
  ip -n wg-entry rule show
  ip -n wg-entry route show table all
  echo
  echo "[exit nat]"
  ip netns exec wg-exit iptables -t nat -S
  ip netns exec wg-exit iptables -S FORWARD
} >"${LOG_DIR}/summary.txt"

echo "WireGuard relay integration passed; artifacts: ${LOG_DIR}"
