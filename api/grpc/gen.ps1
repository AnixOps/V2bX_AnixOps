param(
    [string]$ProtoFile = "api/grpc/v2board.proto"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command protoc -ErrorAction SilentlyContinue)) {
    throw "protoc not found. Install Protocol Buffers compiler first."
}
if (-not (Get-Command protoc-gen-go -ErrorAction SilentlyContinue)) {
    throw "protoc-gen-go not found. Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
}
if (-not (Get-Command protoc-gen-go-grpc -ErrorAction SilentlyContinue)) {
    throw "protoc-gen-go-grpc not found. Install with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Push-Location $repoRoot
try {
    protoc `
        --go_out=. `
        --go_opt=paths=source_relative `
        --go-grpc_out=. `
        --go-grpc_opt=paths=source_relative `
        $ProtoFile

    Write-Host "Generated: api/grpc/v2boardpb/*.go"
}
finally {
    Pop-Location
}
