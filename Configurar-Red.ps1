$ErrorActionPreference = 'Stop'

$puerto = 5000

$identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identidad)
$esAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $esAdmin) {
    $ejecutable = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell.exe' }
    $argumentos = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    Start-Process -FilePath $ejecutable -ArgumentList $argumentos -Verb RunAs | Out-Null
    Write-Host 'Se solicitaron permisos de administrador para configurar el acceso en red.' -ForegroundColor Yellow
    exit
}

$urlAcl = "http://+:$puerto/"
$usuario = $identidad.Name

& netsh http delete urlacl "url=$urlAcl" 2>$null | Out-Null
& netsh http add urlacl "url=$urlAcl" "user=$usuario" | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear la URL ACL.' }

& netsh advfirewall firewall delete rule name="DataHunt $puerto" 2>$null | Out-Null
& netsh advfirewall firewall add rule name="DataHunt $puerto" dir=in action=allow protocol=TCP localport=$puerto remoteip=localsubnet | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear la regla de firewall.' }

Write-Host '' 
Write-Host 'Configuracion completada.' -ForegroundColor Green
Write-Host 'Ahora ejecuta: pwsh -File .\app.ps1' -ForegroundColor Cyan
Write-Host 'URLs disponibles en esta red:' -ForegroundColor Cyan

Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -ne '127.0.0.1' -and
    $_.PrefixOrigin -ne 'WellKnown' -and
    $_.InterfaceAlias -notmatch 'Tailscale'
} | ForEach-Object { Write-Host "  http://$($_.IPAddress):$puerto/" }
