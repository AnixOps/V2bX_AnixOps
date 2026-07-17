#!/usr/bin/env bash

set -Eeuo pipefail

PLUGIN_BIN="${GOST_MESH_PLUGIN_BIN:-}"
GOST_BIN="${GOST_BIN:-}"
TRANSPORT="${GOST_MESH_TRANSPORT:-quic}"
LOG_DIR="${GOST_MESH_LOG_DIR:-$(pwd)/gost-mesh-acceptance-artifacts}"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "gost-mesh namespace acceptance must run as root" >&2
  exit 1
fi
if [[ ! -x "${PLUGIN_BIN}" ]]; then
  echo "GOST_MESH_PLUGIN_BIN must reference an executable gost-mesh plugin" >&2
  exit 1
fi
if [[ ! -x "${GOST_BIN}" ]]; then
  echo "GOST_BIN must reference the pinned GOST v3.2.6 executable" >&2
  exit 1
fi
if [[ "${TRANSPORT}" != "quic" && "${TRANSPORT}" != "wss" ]]; then
  echo "GOST_MESH_TRANSPORT must be quic or wss" >&2
  exit 1
fi
if [[ ! -c /dev/net/tun ]]; then
  echo "/dev/net/tun is unavailable" >&2
  exit 1
fi
for command in ip nft curl openssl python3 go install awk grep sed sh sleep ss sysctl wc; do
  require_command "${command}"
done
if [[ "$("${GOST_BIN}" -V 2>&1)" != gost\ v3.2.6\ * ]]; then
  echo "GOST_BIN is not pinned GOST v3.2.6" >&2
  exit 1
fi

mkdir -p "${LOG_DIR}"
chmod 0700 "${LOG_DIR}"
WORK_DIR="$(mktemp -d /tmp/anixops-gost-mesh.XXXXXX)"
chmod 0700 "${WORK_DIR}"
NAMESPACES=(gm-client gm-entry gm-exit gm-internet)
PIDS=()
ENTRY_PID=""
EXIT_PID=""

collect_diagnostics() {
  local namespace
  for namespace in "${NAMESPACES[@]}"; do
    if ip netns list | awk '{print $1}' | grep -Fxq "${namespace}"; then
      {
        echo "[links]"
        ip -n "${namespace}" -details link show
        echo "[addresses]"
        ip -n "${namespace}" -4 address show
        echo "[rules]"
        ip -n "${namespace}" -4 rule show
        echo "[routes]"
        ip -n "${namespace}" -4 route show table all
        echo "[nft]"
        ip netns exec "${namespace}" nft list ruleset
        echo "[sockets]"
        ip netns exec "${namespace}" ss -lntup
      } >"${LOG_DIR}/${namespace}-network.txt" 2>&1 || true
    fi
  done
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  collect_diagnostics
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

wait_for_link() {
  local namespace="$1"
  local link="$2"
  local deadline=$((SECONDS + 20))
  until ip -n "${namespace}" link show dev "${link}" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "timed out waiting for ${namespace}/${link}" >&2
      return 1
    fi
    sleep 0.1
  done
}

wait_for_health() {
  local socket="$1"
  local expected="$2"
  local deadline=$((SECONDS + 30))
  until "${WORK_DIR}/health-probe" "${socket}" gost-mesh "${expected}"; do
    if (( SECONDS >= deadline )); then
      echo "timed out waiting for ${socket} health ${expected}" >&2
      return 1
    fi
    sleep 0.2
  done
}

stop_plugin() {
  local pid="$1"
  local allow_failure="${2:-false}"
  kill -TERM "${pid}" 2>/dev/null || true
  if wait "${pid}"; then
    return 0
  fi
  if [[ "${allow_failure}" == "true" ]]; then
    return 0
  fi
  echo "plugin process ${pid} exited unsuccessfully" >&2
  return 1
}

assert_entry_clean() {
  local state="$1"
  local rules
  local plugin_routes
  local preserved_routes
  if ip -n gm-entry link show dev gme0 >/dev/null 2>&1; then
    echo "entry TUN interface leaked" >&2
    return 1
  fi
  rules="$(ip -n gm-entry -4 rule show)"
  if grep -Eq '^12010:' <<<"${rules}"; then
    echo "entry source policy rule leaked" >&2
    return 1
  fi
  plugin_routes="$(ip -n gm-entry -4 route show table 201 2>/dev/null || true)"
  if [[ -n "${plugin_routes}" ]]; then
    echo "entry policy route leaked" >&2
    return 1
  fi
  if [[ -e "${state}" ]]; then
    echo "entry ownership journal leaked" >&2
    return 1
  fi
  if [[ -S "${WORK_DIR}/entry.sock" ]]; then
    echo "entry health socket leaked" >&2
    return 1
  fi
  if ! grep -Eq '^11000:.*from 192\.0\.2\.0/24.*lookup 200' <<<"${rules}"; then
    echo "pre-existing policy rule was not preserved" >&2
    return 1
  fi
  preserved_routes="$(ip -n gm-entry -4 route show table 200)"
  if ! grep -q 'blackhole 203.0.113.0/24' <<<"${preserved_routes}"; then
    echo "pre-existing policy route was not preserved" >&2
    return 1
  fi
}

assert_counter() {
  local comment="$1"
  local packets
  packets="$(ip netns exec gm-entry nft list chain inet gm_guard output | awk -v marker="${comment}" '
    index($0, "comment \"" marker "\"") {
      for (field = 1; field <= NF; field++) if ($field == "packets") { print $(field + 1); exit }
    }
  ')"
  if [[ -z "${packets}" || "${packets}" -le 0 ]]; then
    echo "transport counter ${comment} did not observe packets" >&2
    return 1
  fi
}

assert_tcp_blocked() {
  local label="$1"
  if ip netns exec gm-client curl --noproxy '*' --fail --silent --show-error --max-time 3 \
    http://198.51.100.2:18080/health >"${LOG_DIR}/${label}-unexpected-response.txt" 2>"${LOG_DIR}/${label}-curl.txt"; then
    echo "${label} unexpectedly forwarded traffic" >&2
    return 1
  fi
}

cat >"${WORK_DIR}/health-probe.go" <<'EOF'
package main

import (
	"context"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	if len(os.Args) != 4 {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := grpc.DialContext(ctx, "unix://"+os.Args[1], grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		os.Exit(1)
	}
	defer connection.Close()
	response, err := healthpb.NewHealthClient(connection).Check(ctx, &healthpb.HealthCheckRequest{Service: os.Args[2]})
	if err != nil || response.Status.String() != os.Args[3] {
		os.Exit(1)
	}
}
EOF
GOWORK=off go build -o "${WORK_DIR}/health-probe" "${WORK_DIR}/health-probe.go"

install -m 0750 "${PLUGIN_BIN}" "${WORK_DIR}/plugin"
mkdir -p "${WORK_DIR}/runtime" "${WORK_DIR}/state"
chmod 0700 "${WORK_DIR}/runtime" "${WORK_DIR}/state"
install -m 0750 "${GOST_BIN}" "${WORK_DIR}/runtime/gost"

for namespace in "${NAMESPACES[@]}"; do
  ip netns add "${namespace}"
  ip -n "${namespace}" link set lo up
done

ip link add entry-client type veth peer name client-entry
ip link set entry-client netns gm-entry
ip link set client-entry netns gm-client
ip -n gm-entry addr add 10.61.0.1/24 dev entry-client
ip -n gm-entry link set entry-client up
ip -n gm-client addr add 10.61.0.2/24 dev client-entry
ip -n gm-client link set client-entry up

ip link add entry-relay type veth peer name exit-relay
ip link set entry-relay netns gm-entry
ip link set exit-relay netns gm-exit
ip -n gm-entry addr add 172.18.1.1/24 dev entry-relay
ip -n gm-entry link set entry-relay up
ip -n gm-exit addr add 172.18.1.2/24 dev exit-relay
ip -n gm-exit link set exit-relay up

ip link add exit-internet type veth peer name internet-exit
ip link set exit-internet netns gm-exit
ip link set internet-exit netns gm-internet
ip -n gm-exit addr add 198.51.100.1/24 dev exit-internet
ip -n gm-exit link set exit-internet up
ip -n gm-internet addr add 198.51.100.2/24 dev internet-exit
ip -n gm-internet link set internet-exit up

ip -n gm-client route add 198.51.100.0/24 via 10.61.0.1
ip -n gm-internet route add 10.61.0.0/24 via 198.51.100.1
ip -n gm-internet route add 172.31.70.0/30 via 198.51.100.1
ip netns exec gm-entry sysctl -qw net.ipv4.ip_forward=1
ip netns exec gm-exit sysctl -qw net.ipv4.ip_forward=1
# shellcheck disable=SC2016
ip netns exec gm-entry sh -c 'for path in /proc/sys/net/ipv4/conf/*/rp_filter; do printf 0 >"${path}"; done'
# shellcheck disable=SC2016
ip netns exec gm-exit sh -c 'for path in /proc/sys/net/ipv4/conf/*/rp_filter; do printf 0 >"${path}"; done'

ip -n gm-entry -4 route add table 200 blackhole 203.0.113.0/24
ip -n gm-entry -4 rule add priority 11000 from 192.0.2.0/24 table 200

ip netns exec gm-entry nft -f - <<'EOF'
table inet gm_guard {
  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
    iifname "entry-client" counter comment "client-arrival"
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    iifname "entry-client" oifname "gme0" counter accept comment "client-to-tun"
    iifname "gme0" oifname "entry-client" counter accept comment "tun-to-client"
  }
  chain output {
    type filter hook output priority filter; policy accept;
    ip daddr 172.18.1.2 tcp dport 18443 counter comment "gost-mesh-wss"
    ip daddr 172.18.1.2 udp dport 18443 counter comment "gost-mesh-quic"
  }
}
EOF
ip netns exec gm-exit nft -f - <<'EOF'
table inet gm_guard {
  chain forward {
    type filter hook forward priority filter; policy drop;
    iifname "gmx0" oifname "exit-internet" counter accept comment "tun-to-internet"
    iifname "exit-internet" oifname "gmx0" counter accept comment "internet-to-tun"
  }
}
EOF

umask 077
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj '/CN=AnixOps GOST Mesh Test CA' \
  -keyout "${WORK_DIR}/ca-key.pem" -out "${WORK_DIR}/ca.pem" \
  >"${LOG_DIR}/ca.log" 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=relay.integration.test' \
  -keyout "${WORK_DIR}/relay-key.pem" -out "${WORK_DIR}/relay.csr" \
  >"${LOG_DIR}/relay-csr.log" 2>&1
cat >"${WORK_DIR}/relay.ext" <<'EOF'
subjectAltName=DNS:relay.integration.test
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -sha256 -days 1 \
  -in "${WORK_DIR}/relay.csr" -CA "${WORK_DIR}/ca.pem" -CAkey "${WORK_DIR}/ca-key.pem" -CAcreateserial \
  -extfile "${WORK_DIR}/relay.ext" -out "${WORK_DIR}/relay.pem" \
  >"${LOG_DIR}/relay-cert.log" 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=gost-mesh-entry' \
  -keyout "${WORK_DIR}/client-key.pem" -out "${WORK_DIR}/client.csr" \
  >"${LOG_DIR}/client-csr.log" 2>&1
cat >"${WORK_DIR}/client.ext" <<'EOF'
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -sha256 -days 1 \
  -in "${WORK_DIR}/client.csr" -CA "${WORK_DIR}/ca.pem" -CAkey "${WORK_DIR}/ca-key.pem" -CAcreateserial \
  -extfile "${WORK_DIR}/client.ext" -out "${WORK_DIR}/client.pem" \
  >"${LOG_DIR}/client-cert.log" 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj '/CN=unauthorized-gost-mesh-client' \
  -addext 'extendedKeyUsage=clientAuth' \
  -keyout "${WORK_DIR}/rogue-client-key.pem" -out "${WORK_DIR}/rogue-client.pem" \
  >"${LOG_DIR}/rogue-client.log" 2>&1
chmod 0600 "${WORK_DIR}/ca-key.pem" "${WORK_DIR}/relay-key.pem" "${WORK_DIR}/client-key.pem" "${WORK_DIR}/rogue-client-key.pem"

WSS_PATH=""
if [[ "${TRANSPORT}" == "wss" ]]; then
  WSS_PATH="/anixops/gost-mesh/acceptance"
fi

cat >"${WORK_DIR}/exit.json" <<EOF
{
  "api_version":"anixops.gost-mesh/v1",
  "apply":true,
  "rollback_on_exit":true,
  "tunnels":[{
    "id":"acceptance-exit",
    "role":"exit",
    "transport":"${TRANSPORT}",
    "listen":{"address":"172.18.1.2","port":18443},
    "tun":{"name":"gmx0","address":"172.31.70.1/30","peer_address":"172.31.70.2","port":18421,"mtu":1280},
    "routing":{"source_cidrs":[],"route_cidrs":["10.61.0.0/24"],"table":0,"priority":0},
    "tls":{"server_name":"","ca_file":"${WORK_DIR}/ca.pem","cert_file":"${WORK_DIR}/relay.pem","key_file":"${WORK_DIR}/relay-key.pem"},
    "wss_path":"${WSS_PATH}",
    "health":{"enabled":false,"target":"","source_address":"","interval_seconds":5,"timeout_seconds":1,"failure_threshold":2,"restart_delay_seconds":1,"restart_limit":2}
  }]
}
EOF

cat >"${WORK_DIR}/entry-bad.json" <<EOF
{
  "api_version":"anixops.gost-mesh/v1",
  "apply":true,
  "rollback_on_exit":true,
  "tunnels":[{
    "id":"acceptance-entry",
    "role":"entry",
    "transport":"${TRANSPORT}",
    "remote":{"host":"172.18.1.2","port":18443},
    "tun":{"name":"gme0","address":"172.31.70.2/30","peer_address":"172.31.70.1","port":18421,"mtu":1280},
    "routing":{"source_cidrs":["10.61.0.0/24"],"route_cidrs":[],"table":201,"priority":12010},
    "tls":{"server_name":"wrong.integration.test","ca_file":"${WORK_DIR}/ca.pem","cert_file":"${WORK_DIR}/client.pem","key_file":"${WORK_DIR}/client-key.pem"},
    "wss_path":"${WSS_PATH}",
    "health":{"enabled":true,"target":"198.51.100.2:18080","source_address":"10.61.0.1","interval_seconds":5,"timeout_seconds":1,"failure_threshold":1,"restart_delay_seconds":1,"restart_limit":2}
  }]
}
EOF
sed 's/wrong\.integration\.test/relay.integration.test/' "${WORK_DIR}/entry-bad.json" >"${WORK_DIR}/entry.json"
sed \
  -e "s|${WORK_DIR}/client.pem|${WORK_DIR}/rogue-client.pem|" \
  -e "s|${WORK_DIR}/client-key.pem|${WORK_DIR}/rogue-client-key.pem|" \
  "${WORK_DIR}/entry.json" >"${WORK_DIR}/entry-unauthorized.json"

mkdir -p "${WORK_DIR}/www"
printf 'gost-mesh-tcp-ok\n' >"${WORK_DIR}/www/health"
ip netns exec gm-internet python3 -m http.server 18080 --bind 198.51.100.2 --directory "${WORK_DIR}/www" \
  >"${LOG_DIR}/http.log" 2>&1 &
PIDS+=("$!")
ip netns exec gm-internet python3 -u -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("198.51.100.2",18081))
while True:
    data,addr=s.recvfrom(65535)
    s.sendto(b"gost-mesh-udp:"+data,addr)
' >"${LOG_DIR}/udp.log" 2>&1 &
PIDS+=("$!")

ip netns exec gm-exit "${WORK_DIR}/plugin" \
  --anixops-socket "${WORK_DIR}/exit.sock" \
  --anixops-config "${WORK_DIR}/exit.json" \
  --anixops-state "${WORK_DIR}/state/exit.json" \
  >"${LOG_DIR}/exit.log" 2>&1 &
EXIT_PID="$!"
PIDS+=("${EXIT_PID}")
wait_for_link gm-exit gmx0
wait_for_health "${WORK_DIR}/exit.sock" SERVING

ip netns exec gm-entry "${WORK_DIR}/plugin" \
  --anixops-socket "${WORK_DIR}/entry.sock" \
  --anixops-config "${WORK_DIR}/entry-bad.json" \
  --anixops-state "${WORK_DIR}/state/entry.json" \
  >"${LOG_DIR}/entry-bad.log" 2>&1 &
ENTRY_PID="$!"
PIDS+=("${ENTRY_PID}")
wait_for_link gm-entry gme0
assert_tcp_blocked "wrong-sni"
wait_for_health "${WORK_DIR}/entry.sock" NOT_SERVING
stop_plugin "${ENTRY_PID}" true
assert_entry_clean "${WORK_DIR}/state/entry.json"

ip netns exec gm-entry "${WORK_DIR}/plugin" \
  --anixops-socket "${WORK_DIR}/entry.sock" \
  --anixops-config "${WORK_DIR}/entry-unauthorized.json" \
  --anixops-state "${WORK_DIR}/state/entry.json" \
  >"${LOG_DIR}/entry-unauthorized.log" 2>&1 &
ENTRY_PID="$!"
PIDS+=("${ENTRY_PID}")
wait_for_link gm-entry gme0
assert_tcp_blocked "unauthorized-client"
wait_for_health "${WORK_DIR}/entry.sock" NOT_SERVING
stop_plugin "${ENTRY_PID}" true
assert_entry_clean "${WORK_DIR}/state/entry.json"

ip netns exec gm-entry "${WORK_DIR}/plugin" \
  --anixops-socket "${WORK_DIR}/entry.sock" \
  --anixops-config "${WORK_DIR}/entry.json" \
  --anixops-state "${WORK_DIR}/state/entry.json" \
  >"${LOG_DIR}/entry.log" 2>&1 &
ENTRY_PID="$!"
PIDS+=("${ENTRY_PID}")
wait_for_link gm-entry gme0
wait_for_health "${WORK_DIR}/entry.sock" SERVING

{
  echo "[client route]"
  ip -n gm-client -4 route get 198.51.100.2
  echo "[entry forwarded route]"
  ip -n gm-entry -4 route get 198.51.100.2 from 10.61.0.2 iif entry-client
  echo "[entry local health route]"
  ip -n gm-entry -4 route get 198.51.100.2 from 10.61.0.1
  echo "[neighbors]"
  ip -n gm-client neigh show
  ip -n gm-entry neigh show
} >"${LOG_DIR}/pre-traffic-routes.txt" 2>&1

response="$(ip netns exec gm-client curl --noproxy '*' --fail --silent --show-error --max-time 5 http://198.51.100.2:18080/health)"
if [[ "${response}" != "gost-mesh-tcp-ok" ]]; then
  echo "unexpected TCP response: ${response}" >&2
  exit 1
fi
ip netns exec gm-client python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b"nonce-20260717",("198.51.100.2",18081))
data,_=s.recvfrom(65535)
assert data==b"gost-mesh-udp:nonce-20260717",data
'
assert_counter "gost-mesh-${TRANSPORT}"

stop_plugin "${ENTRY_PID}"
assert_entry_clean "${WORK_DIR}/state/entry.json"
stop_plugin "${EXIT_PID}"
if ip -n gm-exit link show dev gmx0 >/dev/null 2>&1; then
  echo "exit TUN interface leaked" >&2
  exit 1
fi
if [[ -e "${WORK_DIR}/state/exit.json" || -S "${WORK_DIR}/exit.sock" ]]; then
  echo "exit runtime state leaked" >&2
  exit 1
fi

entry_processes="$(ip netns pids gm-entry | wc -l)"
exit_processes="$(ip netns pids gm-exit | wc -l)"
if [[ "${entry_processes}" -ne 0 || "${exit_processes}" -ne 0 ]]; then
  echo "plugin or GOST process leaked: entry=${entry_processes}, exit=${exit_processes}" >&2
  exit 1
fi

{
  echo "result=pass"
  echo "transport=${TRANSPORT}"
  echo "tls_negative=wrong-sni-not-serving"
  echo "mtls_negative=unauthorized-client-not-serving"
  echo "tcp=pass"
  echo "udp=pass"
  echo "cleanup=pass"
  echo "preexisting_policy=preserved"
} >"${LOG_DIR}/summary.txt"

echo "gost-mesh ${TRANSPORT} namespace acceptance passed; artifacts: ${LOG_DIR}"
