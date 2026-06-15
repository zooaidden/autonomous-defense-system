# =============================================================================
# Autonomous Defense System - health probe (PowerShell, Windows / Kylin-on-WSL).
# =============================================================================
#
# Probes the five well-known ports of the deployment:
#     8080  defense-gateway     (Java)   -> /api/health
#     8001  agent-brain         (Python) -> /health
#     8002  formal-verifier     (Python) -> /health
#     8081  actuator-service    (Java)   -> /api/health
#     5173  dashboard-ui        (Vite)   -> /
#
# Exit codes:
#   0 - every service answered with a successful HTTP probe
#   1 - one or more services failed both checks
# =============================================================================

$ErrorActionPreference = 'Continue'

$host_ = if ($env:HEALTH_PROBE_HOST) { $env:HEALTH_PROBE_HOST } else { '127.0.0.1' }
$timeoutSec = if ($env:CURL_TIMEOUT_SECONDS) { [int]$env:CURL_TIMEOUT_SECONDS } else { 3 }

function Resolve-Port([string]$value, [int]$defaultValue) {
    if ($value -and $value.Trim() -ne '') {
        return [int]$value
    }
    return $defaultValue
}

$probes = @(
    @{ Name = 'defense-gateway';  Port = Resolve-Port $env:DEFENSE_GATEWAY_PORT 8080;  Urls = @('/api/health', '/') },
    @{ Name = 'agent-brain';      Port = Resolve-Port $env:AGENT_BRAIN_PORT 8001;      Urls = @('/health', '/') },
    @{ Name = 'formal-verifier';  Port = Resolve-Port $env:FORMAL_VERIFIER_PORT 8002;  Urls = @('/health', '/') },
    @{ Name = 'actuator-service'; Port = Resolve-Port $env:ACTUATOR_SERVICE_PORT 8081; Urls = @('/api/health', '/') },
    @{ Name = 'dashboard-ui';     Port = Resolve-Port $env:DASHBOARD_UI_PORT 5173;     Urls = @('/') }
)

$failures = 0
Write-Host ""
Write-Host "==================== health probe ===================="
Write-Host (" host={0}  timeout={1}s" -f $host_, $timeoutSec)
Write-Host "------------------------------------------------------"

foreach ($probe in $probes) {
    $name = $probe.Name
    $port = $probe.Port
    $hit = $false

    foreach ($urlPath in $probe.Urls) {
        $url = "http://$host_`:$port$urlPath"
        try {
            $resp = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec $timeoutSec -UseBasicParsing -ErrorAction Stop
            if ($resp.StatusCode -ge 100 -and $resp.StatusCode -lt 500) {
                Write-Host ("  [OK]       {0,-22}  port={1,-5}  {2} -> {3}" -f $name, $port, $url, $resp.StatusCode)
                $hit = $true
                break
            }
        } catch {
            # try next URL
        }
    }

    if (-not $hit) {
        Write-Host ("  [DOWN]     {0,-22}  port={1,-5}  no successful HTTP response on probes" -f $name, $port)
        $failures += 1
    }
}

Write-Host "------------------------------------------------------"
if ($failures -gt 0) {
    Write-Host (" RESULT: {0} service(s) DOWN" -f $failures) -ForegroundColor Red
    Write-Host "======================================================"
    Write-Host ""
    exit 1
} else {
    Write-Host " RESULT: all services healthy" -ForegroundColor Green
    Write-Host "======================================================"
    Write-Host ""
    exit 0
}
