#!/usr/bin/env bash
# Run a privileged network-namespace acceptance test for the nat-egress Agent
# plugin. This is intentionally outside the normal unit-test path because it
# requires root, iproute2, nftables, policy routing, and Linux NAT support.

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AGENT_BINARY=""
GO_BIN="${GO_BIN:-go}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

WORK_DIR=""
CLIENT_NS="anix-ne-c-$$"
ROUTER_NS="anix-ne-r-$$"
UPSTREAM_NS="anix-ne-u-$$"
SINK_NS="anix-ne-s-$$"
CLIENT_LINK="nec$$"
ROUTER_CLIENT_LINK="ner0$$"
ROUTER_EGRESS_LINK="ner1$$"
UPSTREAM_LINK="neu$$"
ROUTER_SINK_LINK="ner2$$"
SINK_LINK="nes$$"
PLUGIN_PID=""
MASQ_SERVER_PID=""
FORWARDED_SERVER_PID=""
WRONG_MARK_SERVER_PID=""

TABLE_NAME="anixops_nat_accept"
CHAIN_NAME="postrouting"
MARK=31337
MARK_HEX="$(printf '%x' "${MARK}")"
WRONG_MARK=$((MARK + 1))
POLICY_TABLE=201
RULE_PRIORITY=12137
MARK_FIXTURE_TABLE="anixops_mark_fixture"
MARK_FIXTURE_CHAIN="prerouting"
CORRECT_MARK_COMMENT="anixops:fixture:forwarded-correct"
WRONG_MARK_COMMENT="anixops:fixture:forwarded-wrong"
ROUTER_CLIENT_IP="10.45.0.1"
CLIENT_IP="10.45.0.2"
ROUTER_EGRESS_IP="10.45.1.1"
UPSTREAM_IP="10.45.1.2"
ROUTER_SINK_IP="10.45.2.1"
SINK_IP="10.45.2.2"
POLICY_SERVICE_IP="203.0.113.10"
MASQ_SERVICE_IP="203.0.113.11"
FORWARDED_SERVICE_PORT=18082
WRONG_MARK_SERVICE_PORT=18083

usage() {
  cat <<'EOF'
Usage: plugin/nategress/namespace_acceptance.sh [--agent-binary PATH]

Builds or uses a nat-egress Agent plugin binary, then proves in temporary
Linux network namespaces that:

1. Forwarded IPv4 traffic is masqueraded through the configured egress.
2. A separate topology fixture marks forwarded client traffic in prerouting;
   the exact expected mark follows the plugin policy route and is masqueraded.
3. A wrong-mark forwarded flow remains on the deliberately broken main route,
   while both producer-fixture counters prove the packets were classified.
4. rollback_on_exit deletes the plugin-created nft table, policy rule, and
   policy route.
5. rollback_on_exit restores a pre-existing nft table snapshot and preserves
   an exact pre-existing policy rule and policy route.

All namespaces and veth names include the current process ID and are removed
on exit.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

namespace_exists() {
  ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

diagnostics() {
  set +e
  printf '\n[NAT-EGRESS DIAGNOSTICS]\n' >&2
  if [[ -n "${WORK_DIR}" && -f "${WORK_DIR}/plugin.log" ]]; then
    printf '%s\n' '--- plugin.log ---' >&2
    sed -n '1,240p' "${WORK_DIR}/plugin.log" >&2
  fi
  if [[ -n "${WORK_DIR}" && -f "${WORK_DIR}/ownership.json" ]]; then
    printf '%s\n' '--- ownership.json ---' >&2
    sed -n '1,240p' "${WORK_DIR}/ownership.json" >&2
  fi
  for ns in "${CLIENT_NS}" "${ROUTER_NS}" "${UPSTREAM_NS}" "${SINK_NS}"; do
    namespace_exists "${ns}" || continue
    printf '%s\n' "--- namespace=${ns} addresses ---" >&2
    ip -n "${ns}" -details address show >&2
    printf '%s\n' "--- namespace=${ns} IPv4 routes (all tables) ---" >&2
    ip -n "${ns}" -4 route show table all >&2
    printf '%s\n' "--- namespace=${ns} IPv4 rules ---" >&2
    ip netns exec "${ns}" ip -4 rule show >&2
  done
  if namespace_exists "${ROUTER_NS}"; then
    printf '%s\n' "--- namespace=${ROUTER_NS} nft ruleset ---" >&2
    ip netns exec "${ROUTER_NS}" nft list ruleset >&2
    printf '%s\n' "--- namespace=${ROUTER_NS} marked route decision ---" >&2
    ip netns exec "${ROUTER_NS}" ip -4 route get "${POLICY_SERVICE_IP}" mark "${MARK}" >&2
  fi
}

fail() {
  trap - ERR
  printf '[ERROR] %s\n' "$*" >&2
  diagnostics
  exit 1
}

on_error() {
  local status="$1"
  local line="$2"
  trap - ERR
  printf '[ERROR] unexpected command failure at line %s (status=%s)\n' "${line}" "${status}" >&2
  diagnostics
  exit "${status}"
}

cleanup() {
  trap - ERR
  set +e
  for pid in "${PLUGIN_PID}" "${MASQ_SERVER_PID}" "${FORWARDED_SERVER_PID}" "${WRONG_MARK_SERVER_PID}"; do
    if [[ -n "${pid}" ]]; then
      kill "${pid}" >/dev/null 2>&1
      wait "${pid}" >/dev/null 2>&1
    fi
  done
  if command -v ip >/dev/null 2>&1; then
    for ns in "${CLIENT_NS}" "${ROUTER_NS}" "${UPSTREAM_NS}" "${SINK_NS}"; do
      if namespace_exists "${ns}"; then
        while read -r pid; do
          [[ -n "${pid}" ]] && kill "${pid}" >/dev/null 2>&1
        done < <(ip netns pids "${ns}")
      fi
    done
    for ns in "${CLIENT_NS}" "${ROUTER_NS}" "${UPSTREAM_NS}" "${SINK_NS}"; do
      namespace_exists "${ns}" && ip netns del "${ns}" >/dev/null 2>&1
    done
  fi
  if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
    find "${WORK_DIR}" -type f -delete >/dev/null 2>&1
    rmdir "${WORK_DIR}" >/dev/null 2>&1
  fi
}

wait_for_file() {
  local path="$1"
  local description="$2"
  for _ in {1..100}; do
    [[ -e "${path}" ]] && return 0
    sleep 0.05
  done
  fail "${description} did not become ready: ${path}"
}

start_plugin() {
  rm -f "${WORK_DIR}/plugin.log"
  ip netns exec "${ROUTER_NS}" "${AGENT_BINARY}" \
    --anixops-config "${WORK_DIR}/plugin.json" \
    --anixops-socket "${WORK_DIR}/plugin.sock" \
    --anixops-state "${WORK_DIR}/ownership.json" \
    >"${WORK_DIR}/plugin.log" 2>&1 &
  PLUGIN_PID="$!"
  wait_for_file "${WORK_DIR}/plugin.sock" "plugin socket"
  kill -0 "${PLUGIN_PID}" 2>/dev/null || fail "nat-egress exited before becoming ready"
}

fixture_counter() {
  local comment="$1"
  ip netns exec "${ROUTER_NS}" nft -j list chain inet "${MARK_FIXTURE_TABLE}" "${MARK_FIXTURE_CHAIN}" | \
    "${PYTHON_BIN}" -c '
import json
import sys

document = json.load(sys.stdin)
expected = sys.argv[1]
for item in document.get("nftables", []):
    rule = item.get("rule")
    if not rule or rule.get("comment") != expected:
        continue
    for expression in rule.get("expr", []):
        counter = expression.get("counter") if isinstance(expression, dict) else None
        if counter is not None:
            print(int(counter.get("packets", 0)))
            raise SystemExit(0)
raise SystemExit(f"counter rule not found: {expected}")
' "${comment}"
}

stop_plugin() {
  kill "${PLUGIN_PID}"
  wait "${PLUGIN_PID}"
  PLUGIN_PID=""
}

policy_rule_output() {
  ip netns exec "${ROUTER_NS}" ip -4 rule show priority "${RULE_PRIORITY}"
}

policy_route_output() {
  ip -n "${ROUTER_NS}" -4 route show table "${POLICY_TABLE}" default
}

assert_policy_rule_present() {
  local output
  output="$(policy_rule_output)"
  [[ "${output}" == *"fwmark 0x${MARK_HEX}"* && "${output}" == *"lookup ${POLICY_TABLE}"* ]] || \
    fail "expected policy rule is missing or changed: ${output:-<empty>}"
  [[ "$(printf '%s\n' "${output}" | sed '/^$/d' | wc -l)" -eq 1 ]] || \
    fail "expected exactly one matching policy rule: ${output}"
}

assert_policy_route_present() {
  local output
  output="$(policy_route_output)"
  [[ "${output}" == *"default via ${UPSTREAM_IP}"* && "${output}" == *"dev ${ROUTER_EGRESS_LINK}"* && "${output}" == *"src ${ROUTER_EGRESS_IP}"* && "${output}" == *"metric 42"* ]] || \
    fail "expected policy route is missing or changed: ${output:-<empty>}"
  [[ "$(printf '%s\n' "${output}" | sed '/^$/d' | wc -l)" -eq 1 ]] || \
    fail "expected exactly one policy route: ${output}"
}

trap 'on_error "$?" "$LINENO"' ERR
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent-binary)
      [[ $# -ge 2 ]] || fail "--agent-binary requires a path"
      AGENT_BINARY="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$(id -u)" == "0" ]] || fail "root is required to create network namespaces and policy-routing state"
for command in ip nft sysctl timeout awk grep sed find wc readlink "${PYTHON_BIN}"; do
  require_command "${command}"
done

WORK_DIR="$(mktemp -d)"
chmod 0700 "${WORK_DIR}"

if [[ -z "${AGENT_BINARY}" ]]; then
  AGENT_BINARY="${WORK_DIR}/nat-egress-agent"
  GOEXPERIMENT="${GOEXPERIMENT:-jsonv2}" GOWORK=off "${GO_BIN}" -C "${ROOT_DIR}" build -o "${AGENT_BINARY}" ./cmd/nat-egress
fi
AGENT_BINARY="$(readlink -f "${AGENT_BINARY}")"
[[ -x "${AGENT_BINARY}" ]] || fail "agent binary is not executable: ${AGENT_BINARY}"

cat >"${WORK_DIR}/masq_server.py" <<'PY'
import pathlib
import socket
import sys

ready = pathlib.Path(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("203.0.113.11", 18081))
server.listen(1)
ready.touch()
conn, addr = server.accept()
with conn:
    conn.sendall((addr[0] + "\n").encode("ascii"))
PY

cat >"${WORK_DIR}/upstream_fixture_server.py" <<'PY'
import pathlib
import socket
import sys

ready = pathlib.Path(sys.argv[1])
reached = pathlib.Path(sys.argv[2])
port = int(sys.argv[3])
label = sys.argv[4]
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("203.0.113.10", port))
server.listen(1)
ready.touch()
conn, addr = server.accept()
reached.touch()
with conn:
    conn.sendall((label + ":" + addr[0] + "\n").encode("ascii"))
PY

cat >"${WORK_DIR}/masq_client.py" <<'PY'
import socket

with socket.create_connection(("203.0.113.11", 18081), timeout=3) as connection:
    observed = connection.recv(64).decode("ascii").strip()
if observed != "10.45.1.1":
    raise SystemExit(f"server observed source {observed!r}, expected masqueraded source '10.45.1.1'")
PY

cat >"${WORK_DIR}/forwarded_client.py" <<'PY'
import socket
import sys

port = int(sys.argv[1])
expected = sys.argv[2].encode("ascii") + b"\n"
with socket.create_connection(("203.0.113.10", port), timeout=3) as connection:
    payload = connection.recv(128)
if payload != expected:
    raise SystemExit(f"unexpected forwarded response: {payload!r}, expected {expected!r}")
PY

ip netns add "${CLIENT_NS}"
ip netns add "${ROUTER_NS}"
ip netns add "${UPSTREAM_NS}"
ip netns add "${SINK_NS}"

ip link add "${CLIENT_LINK}" type veth peer name "${ROUTER_CLIENT_LINK}"
ip link add "${ROUTER_EGRESS_LINK}" type veth peer name "${UPSTREAM_LINK}"
ip link add "${ROUTER_SINK_LINK}" type veth peer name "${SINK_LINK}"
ip link set "${CLIENT_LINK}" netns "${CLIENT_NS}"
ip link set "${ROUTER_CLIENT_LINK}" netns "${ROUTER_NS}"
ip link set "${ROUTER_EGRESS_LINK}" netns "${ROUTER_NS}"
ip link set "${UPSTREAM_LINK}" netns "${UPSTREAM_NS}"
ip link set "${ROUTER_SINK_LINK}" netns "${ROUTER_NS}"
ip link set "${SINK_LINK}" netns "${SINK_NS}"

ip -n "${CLIENT_NS}" address add "${CLIENT_IP}/24" dev "${CLIENT_LINK}"
ip -n "${ROUTER_NS}" address add "${ROUTER_CLIENT_IP}/24" dev "${ROUTER_CLIENT_LINK}"
ip -n "${ROUTER_NS}" address add "${ROUTER_EGRESS_IP}/24" dev "${ROUTER_EGRESS_LINK}"
ip -n "${UPSTREAM_NS}" address add "${UPSTREAM_IP}/24" dev "${UPSTREAM_LINK}"
ip -n "${ROUTER_NS}" address add "${ROUTER_SINK_IP}/24" dev "${ROUTER_SINK_LINK}"
ip -n "${SINK_NS}" address add "${SINK_IP}/24" dev "${SINK_LINK}"
ip -n "${UPSTREAM_NS}" address add "${POLICY_SERVICE_IP}/32" dev lo
ip -n "${UPSTREAM_NS}" address add "${MASQ_SERVICE_IP}/32" dev lo

for ns in "${CLIENT_NS}" "${ROUTER_NS}" "${UPSTREAM_NS}" "${SINK_NS}"; do
  ip -n "${ns}" link set lo up
done
ip -n "${CLIENT_NS}" link set "${CLIENT_LINK}" up
ip -n "${ROUTER_NS}" link set "${ROUTER_CLIENT_LINK}" up
ip -n "${ROUTER_NS}" link set "${ROUTER_EGRESS_LINK}" up
ip -n "${UPSTREAM_NS}" link set "${UPSTREAM_LINK}" up
ip -n "${ROUTER_NS}" link set "${ROUTER_SINK_LINK}" up
ip -n "${SINK_NS}" link set "${SINK_LINK}" up

ip -n "${CLIENT_NS}" route add default via "${ROUTER_CLIENT_IP}"
ip -n "${ROUTER_NS}" route add default via "${UPSTREAM_IP}" dev "${ROUTER_EGRESS_LINK}" src "${ROUTER_EGRESS_IP}" metric 42
ip -n "${ROUTER_NS}" route add "${POLICY_SERVICE_IP}/32" via "${SINK_IP}" dev "${ROUTER_SINK_LINK}"
ip netns exec "${ROUTER_NS}" sysctl -q -w net.ipv4.ip_forward=1
for ns in "${ROUTER_NS}" "${UPSTREAM_NS}"; do
  ip netns exec "${ns}" sysctl -q -w net.ipv4.conf.all.rp_filter=0
  ip netns exec "${ns}" sysctl -q -w net.ipv4.conf.default.rp_filter=0
done
for interface in "${ROUTER_CLIENT_LINK}" "${ROUTER_EGRESS_LINK}" "${ROUTER_SINK_LINK}"; do
  ip netns exec "${ROUTER_NS}" sysctl -q -w "net.ipv4.conf.${interface}.rp_filter=0"
done
ip netns exec "${UPSTREAM_NS}" sysctl -q -w "net.ipv4.conf.${UPSTREAM_LINK}.rp_filter=0"

# This table is an independent topology/ingress producer fixture. Its contract
# is to classify forwarded client traffic and set a packet mark before route
# lookup. nat-egress is only the consumer of the exact configured mark: it
# must not create, mutate, snapshot, or remove this fixture table.
cat >"${WORK_DIR}/mark_fixture.nft" <<EOF
add table inet ${MARK_FIXTURE_TABLE}
add chain inet ${MARK_FIXTURE_TABLE} ${MARK_FIXTURE_CHAIN} { type filter hook prerouting priority mangle; policy accept; }
add rule inet ${MARK_FIXTURE_TABLE} ${MARK_FIXTURE_CHAIN} iifname "${ROUTER_CLIENT_LINK}" ip daddr ${POLICY_SERVICE_IP} tcp dport ${FORWARDED_SERVICE_PORT} counter meta mark set ${MARK} comment "${CORRECT_MARK_COMMENT}"
add rule inet ${MARK_FIXTURE_TABLE} ${MARK_FIXTURE_CHAIN} iifname "${ROUTER_CLIENT_LINK}" ip daddr ${POLICY_SERVICE_IP} tcp dport ${WRONG_MARK_SERVICE_PORT} counter meta mark set ${WRONG_MARK} comment "${WRONG_MARK_COMMENT}"
EOF
ip netns exec "${ROUTER_NS}" nft -f "${WORK_DIR}/mark_fixture.nft"
[[ "$(fixture_counter "${CORRECT_MARK_COMMENT}")" -eq 0 ]] || fail "correct-mark producer fixture counter was not initialized to zero"
[[ "$(fixture_counter "${WRONG_MARK_COMMENT}")" -eq 0 ]] || fail "wrong-mark producer fixture counter was not initialized to zero"

cat >"${WORK_DIR}/plugin.json" <<EOF
{
  "apply": true,
  "rollback_on_exit": true,
  "table_name": "${TABLE_NAME}",
  "chain_name": "${CHAIN_NAME}",
  "egress_interface": "${ROUTER_EGRESS_LINK}",
  "default_mark": ${MARK},
  "policy_table": ${POLICY_TABLE},
  "rule_priority": ${RULE_PRIORITY},
  "ipv4_masquerade": true,
  "ipv6_masquerade": false,
  "health_check_enabled": false,
  "health_check_interval_seconds": 5,
  "health_check_timeout_seconds": 1,
  "health_check_target": "${POLICY_SERVICE_IP}:${FORWARDED_SERVICE_PORT}"
}
EOF
chmod 0600 "${WORK_DIR}/plugin.json"

ip netns exec "${UPSTREAM_NS}" "${PYTHON_BIN}" "${WORK_DIR}/masq_server.py" "${WORK_DIR}/masq.ready" &
MASQ_SERVER_PID="$!"
ip netns exec "${UPSTREAM_NS}" "${PYTHON_BIN}" "${WORK_DIR}/upstream_fixture_server.py" \
  "${WORK_DIR}/forwarded.ready" "${WORK_DIR}/forwarded.reached" "${FORWARDED_SERVICE_PORT}" "forwarded-ok" &
FORWARDED_SERVER_PID="$!"
ip netns exec "${UPSTREAM_NS}" "${PYTHON_BIN}" "${WORK_DIR}/upstream_fixture_server.py" \
  "${WORK_DIR}/wrong-mark.ready" "${WORK_DIR}/wrong-mark.reached" "${WRONG_MARK_SERVICE_PORT}" "wrong-mark-reached" &
WRONG_MARK_SERVER_PID="$!"
wait_for_file "${WORK_DIR}/masq.ready" "masquerade test server"
wait_for_file "${WORK_DIR}/forwarded.ready" "forwarded mark-consumer test server"
wait_for_file "${WORK_DIR}/wrong-mark.ready" "wrong-mark negative test server"

start_plugin
[[ -f "${WORK_DIR}/ownership.json" ]] || fail "nat-egress ownership journal was not created at the explicit --anixops-state path"
RULESET="$(ip netns exec "${ROUTER_NS}" nft list table inet "${TABLE_NAME}")"
[[ "${RULESET}" == *"anixops:nat-egress:ipv4"* ]] || fail "IPv4 masquerade rule was not installed: ${RULESET}"
assert_policy_rule_present
assert_policy_route_present

MARKED_ROUTE="$(ip netns exec "${ROUTER_NS}" ip -4 route get "${POLICY_SERVICE_IP}" mark "${MARK}")"
[[ "${MARKED_ROUTE}" == *"via ${UPSTREAM_IP}"* && "${MARKED_ROUTE}" == *"dev ${ROUTER_EGRESS_LINK}"* && "${MARKED_ROUTE}" == *"table ${POLICY_TABLE}"* ]] || \
  fail "fwmark did not select the plugin policy table: ${MARKED_ROUTE}"
UNMARKED_ROUTE="$(ip netns exec "${ROUTER_NS}" ip -4 route get "${POLICY_SERVICE_IP}")"
[[ "${UNMARKED_ROUTE}" == *"via ${SINK_IP}"* && "${UNMARKED_ROUTE}" == *"dev ${ROUTER_SINK_LINK}"* ]] || \
  fail "unmarked control route does not point at the sink: ${UNMARKED_ROUTE}"
WRONG_MARKED_ROUTE="$(ip netns exec "${ROUTER_NS}" ip -4 route get "${POLICY_SERVICE_IP}" mark "${WRONG_MARK}")"
[[ "${WRONG_MARKED_ROUTE}" == *"via ${SINK_IP}"* && "${WRONG_MARKED_ROUTE}" == *"dev ${ROUTER_SINK_LINK}"* ]] || \
  fail "wrong mark unexpectedly escaped the deliberately broken main route: ${WRONG_MARKED_ROUTE}"

timeout 10 ip netns exec "${CLIENT_NS}" "${PYTHON_BIN}" "${WORK_DIR}/masq_client.py"
timeout 10 ip netns exec "${CLIENT_NS}" "${PYTHON_BIN}" "${WORK_DIR}/forwarded_client.py" \
  "${FORWARDED_SERVICE_PORT}" "forwarded-ok:${ROUTER_EGRESS_IP}"
wait_for_file "${WORK_DIR}/forwarded.reached" "correct-mark upstream fixture"
CORRECT_MARK_PACKETS="$(fixture_counter "${CORRECT_MARK_COMMENT}")"
WRONG_MARK_PACKETS_BEFORE="$(fixture_counter "${WRONG_MARK_COMMENT}")"
[[ "${CORRECT_MARK_PACKETS}" -gt 0 ]] || fail "correct-mark producer fixture did not count forwarded client packets"
[[ "${WRONG_MARK_PACKETS_BEFORE}" -eq 0 ]] || fail "wrong-mark producer fixture counted packets before its negative flow"

if timeout 4 ip netns exec "${CLIENT_NS}" "${PYTHON_BIN}" "${WORK_DIR}/forwarded_client.py" \
  "${WRONG_MARK_SERVICE_PORT}" "wrong-mark-reached:${ROUTER_EGRESS_IP}" >/dev/null 2>&1; then
  fail "wrong-mark forwarded client flow unexpectedly reached the upstream fixture"
fi
[[ ! -e "${WORK_DIR}/wrong-mark.reached" ]] || fail "wrong-mark upstream fixture was reached despite the unmatched policy mark"
WRONG_MARK_PACKETS="$(fixture_counter "${WRONG_MARK_COMMENT}")"
[[ "${WRONG_MARK_PACKETS}" -gt 0 ]] || fail "wrong-mark producer fixture did not count the negative forwarded flow"

wait "${MASQ_SERVER_PID}"
MASQ_SERVER_PID=""
wait "${FORWARDED_SERVER_PID}"
FORWARDED_SERVER_PID=""
kill "${WRONG_MARK_SERVER_PID}" >/dev/null 2>&1 || true
wait "${WRONG_MARK_SERVER_PID}" >/dev/null 2>&1 || true
WRONG_MARK_SERVER_PID=""

stop_plugin
[[ ! -e "${WORK_DIR}/ownership.json" ]] || fail "normal plugin exit did not remove the explicit ownership journal"
if ip netns exec "${ROUTER_NS}" nft list table inet "${TABLE_NAME}" >/dev/null 2>&1; then
  fail "plugin-created nftables table survived rollback_on_exit"
fi
if [[ -n "$(policy_rule_output)" ]]; then
  fail "plugin-created policy rule survived rollback_on_exit: $(policy_rule_output)"
fi
if [[ -n "$(policy_route_output)" ]]; then
  fail "plugin-created policy route survived rollback_on_exit: $(policy_route_output)"
fi
FIXTURE_RULESET="$(ip netns exec "${ROUTER_NS}" nft list table inet "${MARK_FIXTURE_TABLE}")"
[[ "${FIXTURE_RULESET}" == *"${CORRECT_MARK_COMMENT}"* && "${FIXTURE_RULESET}" == *"${WRONG_MARK_COMMENT}"* ]] || \
  fail "nat-egress rollback mutated or removed the independent mark-producer fixture"

cat >"${WORK_DIR}/snapshot.nft" <<EOF
table inet ${TABLE_NAME} {
  chain ${CHAIN_NAME} {
    type nat hook postrouting priority srcnat; policy accept;
    counter comment "pre-existing-nft-marker"
  }
}
EOF
ip netns exec "${ROUTER_NS}" nft -f "${WORK_DIR}/snapshot.nft"
ip -n "${ROUTER_NS}" -4 route add table "${POLICY_TABLE}" default via "${UPSTREAM_IP}" dev "${ROUTER_EGRESS_LINK}" src "${ROUTER_EGRESS_IP}" metric 42
ip netns exec "${ROUTER_NS}" ip -4 rule add priority "${RULE_PRIORITY}" fwmark "${MARK}" lookup "${POLICY_TABLE}"
assert_policy_rule_present
assert_policy_route_present

start_plugin
[[ -f "${WORK_DIR}/ownership.json" ]] || fail "second plugin start did not create the explicit ownership journal"
RULESET="$(ip netns exec "${ROUTER_NS}" nft list table inet "${TABLE_NAME}")"
[[ "${RULESET}" == *"anixops:nat-egress:ipv4"* ]] || fail "plugin did not replace the pre-existing nftables table"
[[ "${RULESET}" != *"pre-existing-nft-marker"* ]] || fail "pre-existing nftables rule remained active while the plugin was running"
stop_plugin
[[ ! -e "${WORK_DIR}/ownership.json" ]] || fail "second normal plugin exit did not remove the explicit ownership journal"

RULESET="$(ip netns exec "${ROUTER_NS}" nft list table inet "${TABLE_NAME}")"
[[ "${RULESET}" == *"pre-existing-nft-marker"* ]] || fail "pre-existing nftables snapshot was not restored"
[[ "${RULESET}" != *"anixops:nat-egress:ipv4"* ]] || fail "plugin nftables rule survived snapshot rollback"
assert_policy_rule_present
assert_policy_route_present
FIXTURE_RULESET="$(ip netns exec "${ROUTER_NS}" nft list table inet "${MARK_FIXTURE_TABLE}")"
[[ "${FIXTURE_RULESET}" == *"${CORRECT_MARK_COMMENT}"* && "${FIXTURE_RULESET}" == *"${WRONG_MARK_COMMENT}"* ]] || \
  fail "second nat-egress rollback mutated or removed the independent mark-producer fixture"
FINAL_CORRECT_MARK_PACKETS="$(fixture_counter "${CORRECT_MARK_COMMENT}")"
FINAL_WRONG_MARK_PACKETS="$(fixture_counter "${WRONG_MARK_COMMENT}")"
[[ "${FINAL_CORRECT_MARK_PACKETS}" -ge "${CORRECT_MARK_PACKETS}" ]] || fail "correct-mark fixture counter was reset during rollback"
[[ "${FINAL_WRONG_MARK_PACKETS}" -ge "${WRONG_MARK_PACKETS}" ]] || fail "wrong-mark fixture counter was reset during rollback"
CORRECT_MARK_PACKETS="${FINAL_CORRECT_MARK_PACKETS}"
WRONG_MARK_PACKETS="${FINAL_WRONG_MARK_PACKETS}"

printf 'status=PASS\n'
printf 'plugin_id=nat-egress\n'
printf 'ipv4_masquerade=true\n'
printf 'forwarded_mark_consumer=true\n'
printf 'forwarded_mark_consumer_masquerade=true\n'
printf 'wrong_mark_forwarded_flow=blocked\n'
printf 'mark_producer_fixture_correct_packets=%s\n' "${CORRECT_MARK_PACKETS}"
printf 'mark_producer_fixture_wrong_packets=%s\n' "${WRONG_MARK_PACKETS}"
printf 'mark_producer_fixture_after_rollback=preserved\n'
printf 'normal_exit_ownership_journal=removed\n'
printf 'rollback_created_nft_table=deleted\n'
printf 'rollback_created_policy_rule=deleted\n'
printf 'rollback_created_policy_route=deleted\n'
printf 'rollback_existing_nft_table=snapshot_restored\n'
printf 'rollback_existing_policy_rule=preserved\n'
printf 'rollback_existing_policy_route=preserved\n'
