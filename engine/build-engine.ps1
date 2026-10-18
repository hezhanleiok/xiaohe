# 生成 app/libs/engine.aar（gomobile bind 产物）。
#
# 这台机器上的几个坑，都写进环境变量里了，别每次手敲：
#   - 依赖全部来自本机 Go 模块缓存（GOPROXY=off）：GitHub 在这条线路上只有
#     ~2 Mbps，走代理拉依赖会把构建时间从 1 分钟拖到半小时。
#   - JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8：gomobile 会把 Go 注释抄进生成的
#     Java 源码，中文注释在 GBK 默认编码的 javac 下直接报错。
#   - GOFLAGS=-mod=mod：不要用 vendor，靠 replace 指向 third_party。
#
# 用法：powershell -ExecutionPolicy Bypass -File .\build-engine.ps1 [-Abi arm64]
param(
    [string]$Abi = "arm64"
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$env:GOFLAGS = "-mod=mod"
$env:GOPROXY = "off"
$env:GOSUMDB = "off"
$env:GOTOOLCHAIN = "local"
$env:JAVA_TOOL_OPTIONS = "-Dfile.encoding=UTF-8"
$env:ANDROID_HOME = "D:\Android\Sdk"
$env:ANDROID_NDK_HOME = "D:\Android\Sdk\ndk\27.0.12077973"
$env:PATH = "$env:USERPROFILE\go\bin;$env:PATH"

Push-Location $here
try {
    $out = Join-Path $here "..\app\libs\engine.aar"
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $out) | Out-Null
    Write-Host "gomobile bind -> $out (android/$Abi)"
    gomobile bind -target "android/$Abi" -androidapi 26 -o $out .
    if ($LASTEXITCODE -ne 0) { throw "gomobile bind 失败（exit $LASTEXITCODE）" }
    $f = Get-Item $out
    Write-Host ("OK: {0:N2} MB  {1}" -f ($f.Length / 1MB), $f.FullName)
}
finally {
    Pop-Location
}
