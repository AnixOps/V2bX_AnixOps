#!/usr/bin/env bash
# Enforce that local build helper scripts cannot be used as release build paths
# by default. GitHub Actions is the only approved release build source.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/check_release_build_policy.sh [--self-test|--help]

Scans local build helper scripts for Go build commands. Any local build helper
must document the GitHub Actions-only release policy and require
ALLOW_LOCAL_BUILD opt-in.
EOF
}

find_build_helpers() {
  local root="$1"
  find "${root}" \
    -maxdepth 2 \
    -type f \
    \( -name 'build.sh' -o -name 'build.ps1' \) \
    -print \
    | sort
}

script_has_build_command() {
  local file="$1"
  grep -Eq '(^|[^[:alnum:]_])go[[:space:]]+build([^[:alnum:]_]|$)|(^|[^[:alnum:]_])&[[:space:]]+go[[:space:]]+@buildArgs([^[:alnum:]_]|$)' "${file}"
}

script_has_release_policy_guard() {
  local file="$1"
  grep -Fq 'Release builds must be produced by GitHub Actions' "${file}" &&
    grep -Fq 'ALLOW_LOCAL_BUILD' "${file}"
}

check_policy() {
  local root="$1"
  local failed=0
  local file rel

  while IFS= read -r file; do
    if ! script_has_build_command "${file}"; then
      continue
    fi

    rel="${file#${root}/}"
    if script_has_release_policy_guard "${file}"; then
      echo "ok: ${rel} local build is guarded"
      continue
    fi

    echo "error: ${rel} contains a local build command without the release build guard" >&2
    failed=1
  done < <(find_build_helpers "${root}")

  return "${failed}"
}

run_self_test() {
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' RETURN

  cat >"${tmpdir}/build.sh" <<'EOF'
#!/usr/bin/env bash
# Release builds must be produced by GitHub Actions release workflows.
if [[ "${ALLOW_LOCAL_BUILD:-}" != "1" ]]; then
  exit 1
fi
go build .
EOF

  cat >"${tmpdir}/build.ps1" <<'EOF'
# Release builds must be produced by GitHub Actions release workflows.
if ($env:ALLOW_LOCAL_BUILD -ne "1") { exit 1 }
& go @buildArgs
EOF

  if ! check_policy "${tmpdir}" >/dev/null; then
    echo "self-test failed: guarded build helpers should pass" >&2
    return 1
  fi

  cat >"${tmpdir}/build.sh" <<'EOF'
#!/usr/bin/env bash
go build .
EOF

  if check_policy "${tmpdir}" >/dev/null 2>&1; then
    echo "self-test failed: unguarded build helper should fail" >&2
    return 1
  fi

  echo "release build policy self-test passed"
}

case "${1:-}" in
  --self-test)
    run_self_test
    exit 0
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  "")
    check_policy "${REPO_ROOT}"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
