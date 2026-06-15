# 本地开发启动：先打包再 java -jar。
# 说明：工程路径含中文时，Windows 上 `mvn spring-boot:run` 子进程 classpath 可能乱码导致主类找不到；
#       用 fat jar 启动可规避。
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
Push-Location $here
try {
    if (-not (Get-Command mvn -ErrorAction SilentlyContinue)) {
        throw "未找到 mvn，请先安装 Maven 并加入 PATH，或编辑本脚本写死 mvn.cmd 全路径。"
    }
    & mvn -DskipTests package
    $jar = Join-Path $here "target\defense-gateway-0.1.0-SNAPSHOT.jar"
    if (-not (Test-Path $jar)) {
        throw "未生成 $jar，请检查 mvn package 日志。"
    }
    Write-Host "启动: java -jar $jar" -ForegroundColor Cyan
    & java -jar $jar @args
} finally {
    Pop-Location
}
