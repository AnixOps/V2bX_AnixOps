#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROTO_FILE="api/grpc/v2board.proto"

cd "${REPO_ROOT}"

if ! command -v protoc >/dev/null 2>&1; then
  echo "error: protoc not found. install Protocol Buffers compiler first." >&2
  exit 1
fi
if ! command -v protoc-gen-go >/dev/null 2>&1; then
  echo "error: protoc-gen-go not found. install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" >&2
  exit 1
fi
if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
  echo "error: protoc-gen-go-grpc not found. install with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest" >&2
  exit 1
fi

protoc \
  --go_out=. \
  --go_opt=paths=source_relative \
  --go-grpc_out=. \
  --go-grpc_opt=paths=source_relative \
  "${PROTO_FILE}"

echo "Generated: api/grpc/v2boardpb/*.go"
