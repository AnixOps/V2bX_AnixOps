#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sdk_root="$(cd "${script_dir}/.." && pwd)"
repository_url="${SDK_REPOSITORY_URL:-https://github.com/AnixOps/anix-agent.git}"
base_tag="${SDK_BASE_TAG:-}"

cd "${sdk_root}"
GOWORK=off go test ./plugincontrol >&2

if [[ -z "${base_tag}" ]]; then
	base_tag="$(git ls-remote --tags --refs "${repository_url}" 'sdk/v1.*' \
		| awk '{print $2}' \
		| sed 's#refs/tags/##' \
		| grep -E '^sdk/v1\.[0-9]+\.[0-9]+$' \
		| sort -V \
		| tail -n 1 || true)"
fi

if [[ -z "${base_tag}" ]]; then
	echo "No stable sdk/v1 tag exists; bootstrap compatibility check skipped."
	exit 0
fi

buf breaking . --against "${repository_url}#tag=${base_tag},subdir=sdk"
