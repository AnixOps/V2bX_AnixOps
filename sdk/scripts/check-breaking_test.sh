#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
temporary_root="$(mktemp -d)"
trap 'rm -rf "${temporary_root}"' EXIT

empty_repository="${temporary_root}/empty.git"
git init --bare --quiet "${empty_repository}"

output="$(SDK_REPOSITORY_URL="${empty_repository}" "${SCRIPT_DIR}/check-breaking.sh")"
expected="No stable sdk/v1 tag exists; bootstrap compatibility check skipped."

if [[ "${output}" != "${expected}" ]]; then
	printf 'unexpected bootstrap output: %s\n' "${output}" >&2
	exit 1
fi
