# Anix Agent SDK Synchronization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `anix.agent.v1` into a published nested SDK module so Agent and Control can develop together locally while independently consuming immutable SDK versions in CI and releases.

**Architecture:** `github.com/AnixOps/anix-agent/sdk` owns the Agent v1 protobuf, generated bindings, protocol documentation, and pure capability helpers. `anix-agent/v4` and `anix-control/v4` both import the SDK but never each other; a local, untracked `go.work` resolves three source modules during cross-repository development.

**Tech Stack:** Go 1.25/1.26.5, protobuf 29.2, `protoc-gen-go` 1.36.11, `protoc-gen-go-grpc` 1.6.1, Buf 1.71.0, gRPC, GitHub Actions.

## Global Constraints

- SDK module path: `github.com/AnixOps/anix-agent/sdk`.
- Candidate and stable tags: `sdk/v1.0.0-rc.1` and `sdk/v1.0.0`; root `go.mod` files use `v1.0.0-rc.1` and `v1.0.0` respectively.
- SDK v1 accepts only backwards-compatible protobuf changes. No existing field number, field wire type, service, or message meaning may change.
- SDK must not import `github.com/AnixOps/anix-agent/v4`; Control must not import any package under that root module.
- Generated protobuf files are only produced by SDK generation scripts.
- Root modules never commit `replace`; ordinary CI uses `GOWORK=off` and an exact SDK tag.
- A local workspace contains `anix-control`, `anix-agent`, and `anix-agent/sdk`, but its `go.work` is not committed.
- Preserve current REST, v2board gRPC, WebSocket, and Agent-first runtime behavior during this migration.

## File Map

- Agent creates `sdk/go.mod`, `sdk/api/grpc/agent/v1/*`, `sdk/api/grpc/gen.sh`, `sdk/api/grpc/gen.ps1`, `sdk/agentcontrol/protocol.go`, `sdk/agentcontrol/protocol_test.go`, `sdk/buf.yaml`, `sdk/scripts/check-breaking.sh`, and `.github/workflows/sdk.yml`.
- Agent modifies its root module, Agent v1 import sites, root code generators, root CI/release checks, README, and protocol documentation; it deletes the old `api/grpc/agent/v1` directory once imports move.
- Control modifies its root module, every `internal/grpc` and `internal/handler` Agent v1 import, root code generators, CI, README, and cross-repository fixtures; it creates a dependency gate and an SDK sync workflow.

### Task 1: Create the SDK module and canonical protobuf

**Files:**
- Create: `anix-agent/sdk/go.mod`
- Create: `anix-agent/sdk/api/grpc/agent/v1/agent.proto`
- Create: `anix-agent/sdk/api/grpc/agent/v1/agent.pb.go`
- Create: `anix-agent/sdk/api/grpc/agent/v1/agent_grpc.pb.go`
- Create: `anix-agent/sdk/api/grpc/agent/v1/agent_descriptor_test.go`
- Create: `anix-agent/sdk/api/grpc/agent/v1/PROTOCOL.md`
- Create: `anix-agent/sdk/api/grpc/gen.sh`
- Create: `anix-agent/sdk/api/grpc/gen.ps1`
- Create: `anix-agent/sdk/README.md`

**Interfaces:**
- Produces package `agentv1pb` at `github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1`.
- Produces the unchanged `anix.agent.v1.AgentControlService.ControlStream` wire contract.

- [ ] **Step 1: Write the descriptor test before generated code exists**

~~~go
package agentv1pb

import "testing"

func TestAgentControlServiceDescriptor(t *testing.T) {
	if got := string(File_api_grpc_agent_v1_agent_proto.Package()); got != "anix.agent.v1" {
		t.Fatalf("package = %q, want anix.agent.v1", got)
	}
	service := File_api_grpc_agent_v1_agent_proto.Services().ByName("AgentControlService")
	if service == nil || service.Methods().ByName("ControlStream") == nil {
		t.Fatal("AgentControlService.ControlStream descriptor is missing")
	}
}
~~~

- [ ] **Step 2: Run the test to prove the contract is absent**

Run from `anix-agent`:

~~~bash
cd sdk
go test ./api/grpc/agent/v1 -run TestAgentControlServiceDescriptor -count=1
~~~

Expected: FAIL because the nested module and generated descriptor do not yet exist.

- [ ] **Step 3: Create the module and canonical source**

Create `sdk/go.mod`:

~~~go
module github.com/AnixOps/anix-agent/sdk

go 1.25

toolchain go1.25.0

require (
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.10
)
~~~

Copy the existing Agent contract and update only the Go import path:

~~~bash
mkdir -p sdk/api/grpc/agent/v1
cp api/grpc/agent/v1/agent.proto sdk/api/grpc/agent/v1/agent.proto
perl -0pi -e 's#github\.com/AnixOps/anix-agent/v4/api/grpc/agent/v1;agentv1pb#github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1;agentv1pb#' sdk/api/grpc/agent/v1/agent.proto
~~~

The resulting protobuf option must be:

~~~proto
option go_package = "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1;agentv1pb";
~~~

- [ ] **Step 4: Add platform generation entry points and canonical documentation**

Create executable `sdk/api/grpc/gen.sh`:

~~~bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MODULE_PATH="github.com/AnixOps/anix-agent/sdk"

cd "${SDK_ROOT}"
for command_name in protoc protoc-gen-go protoc-gen-go-grpc; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "error: ${command_name} not found" >&2
    exit 1
  }
done

protoc \
  --go_out=. \
  --go_opt="module=${MODULE_PATH}" \
  --go-grpc_out=. \
  --go-grpc_opt="module=${MODULE_PATH}" \
  api/grpc/agent/v1/agent.proto
~~~

Create `sdk/api/grpc/gen.ps1` with the same module path and one proto input:

~~~powershell
param()
$ErrorActionPreference = "Stop"
$ModulePath = "github.com/AnixOps/anix-agent/sdk"
$SdkRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Push-Location $SdkRoot
try {
    protoc --go_out=. "--go_opt=module=$ModulePath" --go-grpc_out=. "--go-grpc_opt=module=$ModulePath" api/grpc/agent/v1/agent.proto
}
finally {
    Pop-Location
}
~~~

Copy the existing protocol document to `sdk/api/grpc/agent/v1/PROTOCOL.md`, changing its generation instruction to `cd sdk && bash api/grpc/gen.sh`. Create `sdk/README.md` containing the canonical import and the rule that this module must not import Agent root code.

- [ ] **Step 5: Generate, test, and commit the canonical module**

~~~bash
cd anix-agent/sdk
go mod tidy
chmod +x api/grpc/gen.sh
PATH="$(go env GOPATH)/bin:${PATH}" bash api/grpc/gen.sh
go test ./api/grpc/agent/v1 -run TestAgentControlServiceDescriptor -count=1
git diff --exit-code -- api/grpc/agent/v1
cd ..
git add sdk
git commit -m "feat(sdk): add canonical agent v1 protobuf module"
~~~

Expected: the descriptor test passes, generated packages point at the SDK module, and no SDK package imports `anix-agent/v4`.

### Task 2: Add pure protocol and capability helpers

**Files:**
- Create: `anix-agent/sdk/agentcontrol/protocol.go`
- Create: `anix-agent/sdk/agentcontrol/protocol_test.go`

**Interfaces:**
- `ProtocolV1 = "anix.agent.v1"`
- `CapabilityVersionV1 = "v1"`
- `ValidateCapabilities([]*agentv1pb.Capability) error`
- `HasCapability([]*agentv1pb.Capability, string) bool`
- `HasCapabilityVersion([]*agentv1pb.Capability, string, string) bool`

- [ ] **Step 1: Write helper tests first**

Create `sdk/agentcontrol/protocol_test.go`:

~~~go
package agentcontrol

import (
	"errors"
	"testing"

	agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
)

func TestValidateCapabilities(t *testing.T) {
	tests := []struct {
		name string
		value []*agentv1pb.Capability
		want error
	}{
		{"missing", nil, ErrCapabilitiesRequired},
		{"empty", []*agentv1pb.Capability{}, ErrCapabilitiesRequired},
		{"nil", []*agentv1pb.Capability{nil}, ErrCapabilityNameRequired},
		{"blank", []*agentv1pb.Capability{{Name: "  "}}, ErrCapabilityNameRequired},
		{"valid", []*agentv1pb.Capability{{Name: "agent.ping", Version: CapabilityVersionV1}}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateCapabilities(test.value); !errors.Is(err, test.want) {
				t.Fatalf("ValidateCapabilities() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCapabilityQueries(t *testing.T) {
	capabilities := []*agentv1pb.Capability{nil, {Name: "agent.ping", Version: CapabilityVersionV1}, {Name: "plugin.health", Version: "v2"}}
	if !HasCapability(capabilities, "agent.ping") || HasCapability(capabilities, "missing") {
		t.Fatal("unexpected name lookup result")
	}
	if !HasCapabilityVersion(capabilities, "plugin.health", "v2") || HasCapabilityVersion(capabilities, "plugin.health", CapabilityVersionV1) {
		t.Fatal("unexpected version lookup result")
	}
}
~~~

- [ ] **Step 2: Run the test and verify the API is missing**

~~~bash
cd anix-agent/sdk
go test ./agentcontrol -run 'TestValidateCapabilities|TestCapabilityQueries' -count=1
~~~

Expected: FAIL with undefined helper symbols.

- [ ] **Step 3: Implement the exact side-effect-free helper API**

Create `sdk/agentcontrol/protocol.go`:

~~~go
package agentcontrol

import (
	"errors"
	"strings"

	agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
)

const (
	ProtocolV1 = "anix.agent.v1"
	CapabilityVersionV1 = "v1"
)

var (
	ErrCapabilitiesRequired = errors.New("hello capabilities are required")
	ErrCapabilityNameRequired = errors.New("capability name is required")
)

func ValidateCapabilities(capabilities []*agentv1pb.Capability) error {
	if len(capabilities) == 0 {
		return ErrCapabilitiesRequired
	}
	for _, capability := range capabilities {
		if capability == nil || strings.TrimSpace(capability.Name) == "" {
			return ErrCapabilityNameRequired
		}
	}
	return nil
}

func HasCapability(capabilities []*agentv1pb.Capability, name string) bool {
	for _, capability := range capabilities {
		if capability != nil && capability.Name == name {
			return true
		}
	}
	return false
}

func HasCapabilityVersion(capabilities []*agentv1pb.Capability, name, version string) bool {
	for _, capability := range capabilities {
		if capability != nil && capability.Name == name && capability.Version == version {
			return true
		}
	}
	return false
}
~~~

- [ ] **Step 4: Run focused and complete SDK tests, then commit**

~~~bash
cd anix-agent/sdk
gofmt -w agentcontrol/protocol.go agentcontrol/protocol_test.go
go test ./agentcontrol -run 'TestValidateCapabilities|TestCapabilityQueries' -count=1
go test ./... -count=1
cd ..
git add sdk/agentcontrol
git commit -m "feat(sdk): add agent control protocol helpers"
~~~

Expected: validation retains Control's existing error strings, and SDK code has no network, filesystem, configuration, or runtime dependency.

### Task 3: Add SDK CI, compatibility checks, and a candidate tag

**Files:**
- Create: `anix-agent/sdk/buf.yaml`
- Create: `anix-agent/sdk/scripts/check-breaking.sh`
- Create: `anix-agent/.github/workflows/sdk.yml`

**Interfaces:**
- Runs Buf FILE breaking checks against the newest stable `sdk/v1.*` tag.
- Skips the comparison only for the initial bootstrap when no stable v1 tag exists.

- [ ] **Step 1: Add Buf configuration and baseline lookup**

Create `sdk/buf.yaml`:

~~~yaml
version: v2
modules:
  - path: .
breaking:
  use:
    - FILE
~~~

Create executable `sdk/scripts/check-breaking.sh`:

~~~bash
#!/usr/bin/env bash
set -euo pipefail

repository_url="${SDK_REPOSITORY_URL:-https://github.com/AnixOps/anix-agent.git}"
base_tag="${SDK_BASE_TAG:-}"
if [[ -z "${base_tag}" ]]; then
  base_tag="$(git ls-remote --tags --refs "${repository_url}" 'sdk/v1.*' | awk '{print $2}' | sed 's#refs/tags/##' | grep -E '^sdk/v1\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1 || true)"
fi
if [[ -z "${base_tag}" ]]; then
  echo "No stable sdk/v1 tag exists; bootstrap compatibility check skipped."
  exit 0
fi
buf breaking . --against "${repository_url}#tag=${base_tag},subdir=sdk"
~~~

- [ ] **Step 2: Add the dedicated SDK quality workflow**

Create `.github/workflows/sdk.yml`:

~~~yaml
name: SDK Quality
on:
  push:
    branches: [master, dev_new]
    tags: ["sdk/v*"]
  pull_request:
    branches: [master, dev_new]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  sdk-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25.0"
      - uses: arduino/setup-protoc@v3
        with:
          version: "29.2"
          repo-token: ${{ secrets.GITHUB_TOKEN }}
      - name: Install generators and Buf
        run: |
          go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
          go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1
          go install github.com/bufbuild/buf/cmd/buf@v1.71.0
          echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"
      - name: Verify SDK
        run: |
          set -euo pipefail
          cd sdk
          go mod tidy
          git diff --exit-code -- go.mod go.sum
          bash api/grpc/gen.sh
          git diff --exit-code -- api/grpc/agent/v1
          test -z "$(git ls-files --others --exclude-standard -- api/grpc/agent/v1)"
          go test ./... -count=1
          bash scripts/check-breaking.sh
~~~

- [ ] **Step 3: Verify locally, commit, and publish the candidate after CI succeeds**

~~~bash
cd anix-agent/sdk
chmod +x scripts/check-breaking.sh
bash -n scripts/check-breaking.sh
go install github.com/bufbuild/buf/cmd/buf@v1.71.0
PATH="$(go env GOPATH)/bin:${PATH}" bash scripts/check-breaking.sh
cd ..
git add sdk .github/workflows/sdk.yml
git commit -m "ci(sdk): verify generated and compatible protocol changes"
git push origin HEAD
git tag -a sdk/v1.0.0-rc.1 -m "SDK v1.0.0 release candidate"
git push origin sdk/v1.0.0-rc.1
~~~

Expected: `go get github.com/AnixOps/anix-agent/sdk@v1.0.0-rc.1` resolves, while existing Agent binary-release workflows remain limited to `v*` tags.

### Task 4: Migrate Agent root to consume the SDK candidate

**Files:**
- Modify: `anix-agent/go.mod`, `anix-agent/go.sum`
- Modify: `anix-agent/api/agent/client.go`, `api/agent/client_test.go`, `api/agent/operation_envelope.go`, `api/agent/operation_envelope_test.go`
- Modify: `anix-agent/cmd/agent-control-fixture/main.go`, `node/agent_control.go`, `node/agent_control_test.go`, `node/agent_plugin_e2e_test.go`, `node/task_error_test.go`, `plugin/observed_state.go`
- Modify: `anix-agent/api/grpc/gen.sh`, `api/grpc/gen.ps1`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `README.md`, `docs/PROTOCOL_CONFIG_SYNC.md`
- Delete: `anix-agent/api/grpc/agent/v1/`

**Interfaces:**
- Consumes exact `github.com/AnixOps/anix-agent/sdk v1.0.0-rc.1`.
- Keeps exported `agent.ProtocolVersion` but aliases it to `agentcontrol.ProtocolV1`.

- [ ] **Step 1: Pin the candidate with no workspace resolution**

~~~bash
cd anix-agent
GOWORK=off go get github.com/AnixOps/anix-agent/sdk@v1.0.0-rc.1
GOWORK=off go mod tidy
GOWORK=off go list -m all | grep -Fx 'github.com/AnixOps/anix-agent/sdk v1.0.0-rc.1'
~~~

- [ ] **Step 2: Replace every Agent v1 import and centralize shared values**

In the listed Agent runtime and test files, replace:

~~~go
agentv1pb "github.com/AnixOps/anix-agent/v4/api/grpc/agent/v1"
~~~

with:

~~~go
agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
~~~

In `api/agent/client.go`, add this entry to the existing import block and replace the existing `ProtocolVersion` literal inside its existing `const (...)` block:

~~~go
agentcontrol "github.com/AnixOps/anix-agent/sdk/agentcontrol"

const (
	ProtocolVersion = agentcontrol.ProtocolV1
	// retain all existing timing and operation constants in this block
)
~~~

In `node/agent_control.go`, use `agentcontrol.CapabilityVersionV1` for every existing capability version literal without changing any capability names or supervisor gating. In `node/agent_plugin_e2e_test.go`, replace the local exact-version loop:

~~~go
func hasE2ECapability(capabilities []*agentv1pb.Capability, name, version string) bool {
	return agentcontrol.HasCapabilityVersion(capabilities, name, version)
}
~~~

- [ ] **Step 3: Remove duplicate Agent codegen and update root checks**

~~~bash
cd anix-agent
git rm -r api/grpc/agent/v1
~~~

Set `PROTO_FILES` in both root generation scripts to only `api/grpc/v2board.proto`. Update root CI and release checks to diff only `api/grpc/v2boardpb`; SDK generation is covered solely by `sdk.yml`.

- [ ] **Step 4: Update docs, run regression tests, and commit**

Document these checks in `README.md`:

~~~bash
cd sdk && bash api/grpc/gen.sh && git diff --exit-code -- api/grpc/agent/v1
cd .. && bash api/grpc/gen.sh && git diff --exit-code -- api/grpc/v2boardpb
~~~

Point `docs/PROTOCOL_CONFIG_SYNC.md` to `sdk/api/grpc/agent/v1/PROTOCOL.md`, then run:

~~~bash
if grep -R -n --include='*.go' 'github.com/AnixOps/anix-agent/v4/api/grpc/agent/v1' .; then
  exit 1
fi
GOEXPERIMENT=jsonv2 GOWORK=off go test ./api/agent ./node ./plugin ./cmd -count=1
GOEXPERIMENT=jsonv2 GOWORK=off go test ./... -count=1
git add go.mod go.sum api node plugin cmd .github/workflows README.md docs
git commit -m "refactor: consume shared agent sdk"
~~~

Expected: root Agent behavior tests remain unchanged and no local `api/grpc/agent/v1` package remains.

### Task 5: Migrate Control root and enforce the dependency boundary

**Files:**
- Modify: `anix-control/go.mod`, `anix-control/go.sum`
- Modify: `anix-control/internal/grpc/agent_control_server.go`, `agent_control_server_test.go`, `agent_plugin_package_cross_repo_e2e_test.go`, `agent_recovery_test.go`, `kernel_operation_bridge.go`, `kernel_operation_bridge_cross_repo_e2e_test.go`, `kernel_operation_bridge_test.go`, `operation_replay.go`, `server.go`
- Modify: `anix-control/internal/handler/agent_control.go`, `agent_control_handler_test.go`, `api/grpc/gen.sh`, `api/grpc/gen.ps1`, `.github/workflows/ci.yml`, `README.md`
- Create: `anix-control/config/scripts/check_agent_sdk_dependency.sh`
- Delete: `anix-control/api/grpc/agent/v1/`

**Interfaces:**
- Keeps `grpc.AgentProtocolVersion` as `agentcontrol.ProtocolV1`.
- Uses SDK `ValidateCapabilities` and `HasCapability` while retaining all current gRPC status codes and error text.

- [ ] **Step 1: Pin the candidate and write the failing boundary gate**

~~~bash
cd anix-control
GOWORK=off go get github.com/AnixOps/anix-agent/sdk@v1.0.0-rc.1
GOWORK=off go mod tidy
~~~

Create `config/scripts/check_agent_sdk_dependency.sh` before imports move:

~~~bash
#!/usr/bin/env bash
set -euo pipefail

forbidden='^github\.com/AnixOps/anix-agent/v4(/|$)'
if [[ -d "api/grpc/agent/v1" ]]; then
  echo "Control local Agent v1 protobuf must be removed in favor of the SDK." >&2
  exit 1
fi
modules="$(GOWORK=off go list -m -f '{{.Path}}' all)"
packages="$(GOWORK=off go list -deps -f '{{.ImportPath}}' ./...)"
unexpected="$(printf '%s\n%s\n' "${modules}" "${packages}" | grep -E "${forbidden}" || true)"
if [[ -n "${unexpected}" ]]; then
  echo "Control must depend on anix-agent/sdk, not anix-agent/v4:" >&2
  echo "${unexpected}" >&2
  exit 1
fi
~~~

Run `bash config/scripts/check_agent_sdk_dependency.sh`. Expected: FAIL before the local `api/grpc/agent/v1` copy is removed; after migration it rejects both a restored local copy and any Agent root module dependency.

- [ ] **Step 2: Move every Control protobuf import and server helper call**

Replace the local protobuf import in all listed `internal/grpc` and `internal/handler` files with:

~~~go
agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
~~~

In `internal/grpc/agent_control_server.go`, add `agentcontrol "github.com/AnixOps/anix-agent/sdk/agentcontrol"` to the existing import block and replace the existing constant group and helper bodies with:

~~~go
const (
	AgentProtocolVersion = agentcontrol.ProtocolV1
	defaultAgentHeartbeatIntervalSeconds = uint32(20)
)

if err := agentcontrol.ValidateCapabilities(hello.Capabilities); err != nil {
	return status.Error(codes.InvalidArgument, err.Error())
}

func connectionSupportsOperation(connection *AgentControlConnection, kind string) bool {
	return agentcontrol.HasCapability(connection.Capabilities, kind)
}
~~~

Do not change stream authentication, session/revision handling, dispatching, persistence, heartbeat, or any status code.

- [ ] **Step 3: Remove Control codegen duplication and wire the gate into CI**

~~~bash
cd anix-control
git rm -r api/grpc/agent/v1
~~~

Set both Control root generation scripts to generate only `api/grpc/v2board.proto`. Update the README and every generated-code CI check to name only `api/grpc/v2boardpb`.

Add this step in `go-quality`, after `go mod tidy` and before full tests:

~~~yaml
      - name: Verify Agent SDK dependency boundary
        run: bash config/scripts/check_agent_sdk_dependency.sh
~~~

Also add `bash -n config/scripts/check_agent_sdk_dependency.sh` to the existing Control script-syntax gate.

- [ ] **Step 4: Verify and commit the Control migration**

~~~bash
cd anix-control
if grep -R -n --include='*.go' 'github.com/AnixOps/anix-control/v4/api/grpc/agent/v1' .; then
  exit 1
fi
bash config/scripts/check_agent_sdk_dependency.sh
GOWORK=off go test ./internal/grpc ./internal/handler -count=1
GOWORK=off go test ./... -count=1 -p=1
git add go.mod go.sum api internal config/scripts .github/workflows README.md
git commit -m "refactor: consume shared agent sdk"
~~~

Expected: server, recovery, bridge, handler, and existing process-E2E semantics remain intact; Control contains no Agent v4 root package in its module or package dependency graph.

### Task 6: Add workspace-aware cross-repository E2E and CI

**Files:**
- Create: `anix-control/.github/workflows/sdk-sync.yml`
- Modify: `anix-control/internal/grpc/kernel_operation_bridge_cross_repo_e2e_test.go`
- Modify: `anix-control/internal/grpc/agent_plugin_package_cross_repo_e2e_test.go`

**Interfaces:**
- `ANIXOPS_AGENT_ROOT` selects the Agent checkout.
- Optional `ANIXOPS_AGENT_GO` selects the Agent Go 1.25 binary.
- A caller-supplied `GOWORK` is preserved; an absent `GOWORK` remains `off` for existing standalone E2E behavior.

- [ ] **Step 1: Preserve caller workspace and Agent toolchain in fixture builders**

Add these helpers in each test package; duplication is necessary because one file is package `grpc` and the other is package `grpc_test`:

~~~go
func crossRepositoryAgentGo() string {
	if configured := strings.TrimSpace(os.Getenv("ANIXOPS_AGENT_GO")); configured != "" {
		return configured
	}
	return "go"
}

func crossRepositoryAgentBuildEnv() []string {
	env := append([]string(nil), os.Environ()...)
	if strings.TrimSpace(os.Getenv("GOWORK")) == "" {
		env = append(env, "GOWORK=off")
	}
	return append(env, "GOEXPERIMENT=jsonv2")
}
~~~

In the bridge test, replace the fixture builder command with:

~~~go
command := exec.Command(crossRepositoryAgentGo(), "build", "-o", binaryPath, "./cmd/agent-control-fixture")
command.Dir = agentRoot
command.Env = crossRepositoryAgentBuildEnv()
~~~

Apply the same `exec.Command` and `Env` changes to `buildCrossRepositoryMachineTelemetry` and `buildCrossRepositoryAgentFixtureBinary` in the plugin package E2E test.

- [ ] **Step 2: Create the manual paired-ref workflow**

Create `anix-control/.github/workflows/sdk-sync.yml`:

~~~yaml
name: SDK Sync
on:
  workflow_dispatch:
    inputs:
      agent_ref:
        description: Agent commit, branch, or tag paired with this Control ref
        required: true
        default: dev_new
permissions:
  contents: read
jobs:
  sdk-sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          path: anix-control
      - uses: actions/checkout@v7
        with:
          repository: AnixOps/anix-agent
          ref: ${{ inputs.agent_ref }}
          path: anix-agent
      - uses: actions/setup-go@v6
        with:
          go-version: "1.25.0"
      - name: Capture Agent Go binary
        run: echo "ANIXOPS_AGENT_GO=$(readlink -f \"$(command -v go)\")" >> "$GITHUB_ENV"
      - name: Initialize workspace
        run: go work init ./anix-control ./anix-agent ./anix-agent/sdk
      - name: Test SDK and Agent
        run: |
          cd anix-agent/sdk
          GOWORK="$GITHUB_WORKSPACE/go.work" go test ./... -count=1
          cd ..
          GOEXPERIMENT=jsonv2 GOWORK="$GITHUB_WORKSPACE/go.work" go test ./api/agent ./node -count=1
      - uses: actions/setup-go@v6
        with:
          go-version: "1.26.5"
      - name: Run real cross-repository E2E
        working-directory: anix-control
        env:
          ANIXOPS_AGENT_ROOT: ${{ github.workspace }}/anix-agent
          ANIXOPS_AGENT_GO: ${{ env.ANIXOPS_AGENT_GO }}
          ANIXOPS_CROSS_REPO_E2E: "1"
          GOWORK: ${{ github.workspace }}/go.work
        run: |
          go test ./internal/grpc -run '^(TestKernelOperationBridgeCrossRepositoryAgentProcess|TestAgentPluginPackageCrossRepositoryE2E)$' -count=1 -timeout 10m
~~~

- [ ] **Step 3: Verify the local workspace path and commit**

~~~bash
cd /path/to/common-parent
go work init ./anix-control ./anix-agent ./anix-agent/sdk
GOWORK="$PWD/go.work" GOEXPERIMENT=jsonv2 go test ./anix-agent/sdk/... ./anix-agent/api/agent ./anix-agent/node -count=1
cd anix-control
ANIXOPS_AGENT_ROOT="../anix-agent" ANIXOPS_CROSS_REPO_E2E=1 GOWORK="../go.work" go test ./internal/grpc -run '^(TestKernelOperationBridgeCrossRepositoryAgentProcess|TestAgentPluginPackageCrossRepositoryE2E)$' -count=1 -timeout 10m
git add .github/workflows/sdk-sync.yml internal/grpc/kernel_operation_bridge_cross_repo_e2e_test.go internal/grpc/agent_plugin_package_cross_repo_e2e_test.go
git commit -m "ci: add shared sdk cross-repository gate"
~~~

Expected: standard E2E still defaults to `GOWORK=off`; the paired workflow uses the three-module workspace and an explicitly captured Agent Go binary.

### Task 7: Promote the stable SDK tag and verify reproducibility

**Files:**
- Modify: `anix-agent/go.mod`, `anix-agent/go.sum`
- Modify: `anix-control/go.mod`, `anix-control/go.sum`
- Verify: `anix-agent/docs/superpowers/specs/2026-07-18-anix-agent-sdk-sync-design.md`
- Verify: this implementation plan

**Interfaces:**
- Produces stable `sdk/v1.0.0` and two roots pinned to `v1.0.0`, never a branch, pseudo-version, or committed `replace`.

- [ ] **Step 1: Require all candidate gates to pass**

Before creating the stable tag, require green results for SDK Quality on `sdk/v1.0.0-rc.1`, Agent root CI using that candidate, Control go-quality using that candidate, and SDK Sync for the paired Agent and Control refs.

- [ ] **Step 2: Tag the exact candidate commit as stable**

~~~bash
cd anix-agent
git fetch --tags origin
git tag -a sdk/v1.0.0 "$(git rev-list -n 1 sdk/v1.0.0-rc.1)" -m "SDK v1.0.0"
git push origin sdk/v1.0.0
GOWORK=off go list -m -versions github.com/AnixOps/anix-agent/sdk
~~~

Expected: module versions include `v1.0.0-rc.1` and `v1.0.0`; Agent binary artifact workflows do not run for `sdk/v*`.

- [ ] **Step 3: Pin both roots to the stable tag in separate commits**

~~~bash
cd anix-agent
GOWORK=off go get github.com/AnixOps/anix-agent/sdk@v1.0.0
GOWORK=off go mod tidy
GOEXPERIMENT=jsonv2 GOWORK=off go test ./... -count=1
git add go.mod go.sum
git commit -m "chore: pin sdk v1.0.0"

cd ../anix-control
GOWORK=off go get github.com/AnixOps/anix-agent/sdk@v1.0.0
GOWORK=off go mod tidy
bash config/scripts/check_agent_sdk_dependency.sh
GOWORK=off go test ./... -count=1 -p=1
git add go.mod go.sum
git commit -m "chore: pin sdk v1.0.0"
~~~

- [ ] **Step 4: Run final no-workspace and cross-workspace acceptance checks**

~~~bash
cd anix-agent
GOEXPERIMENT=jsonv2 GOWORK=off go test ./... -count=1

cd ../anix-control
GOWORK=off go test ./... -count=1 -p=1
bash config/scripts/check_agent_sdk_dependency.sh
~~~

Dispatch `SDK Sync` from the merged Control commit using the merged Agent ref. Expected: ordinary builds resolve stable `v1.0.0`; the local workspace is optional; Agent and Control production releases remain independently versioned.
