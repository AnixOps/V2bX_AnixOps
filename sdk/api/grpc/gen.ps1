param()

$ErrorActionPreference = "Stop"
$ModulePath = "github.com/AnixOps/anix-agent/sdk"
$ProtoFile = "api/grpc/agent/v1/agent.proto"

foreach ($CommandName in @("protoc", "protoc-gen-go", "protoc-gen-go-grpc")) {
    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        throw "$CommandName not found"
    }
}

$SdkRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Push-Location $SdkRoot
try {
    protoc `
        --go_out=. `
        "--go_opt=module=$ModulePath" `
        --go-grpc_out=. `
        "--go-grpc_opt=module=$ModulePath" `
        $ProtoFile
    Write-Host "Generated AnixOps Agent SDK gRPC bindings."
}
finally {
    Pop-Location
}
