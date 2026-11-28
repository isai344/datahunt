$ErrorActionPreference = 'Stop'

# Data Hunt v2: HTTPS en 443 y redireccion HTTP en 80.
# No modificar el puerto 5990 (MSStrgSvc).
$puertoHttps = 443
$puertoHttp  = 80

$identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identidad)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $ejecutable = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell.exe' }
    Start-Process -FilePath $ejecutable -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath)) -Verb RunAs | Out-Null
    Write-Host 'Se solicitaron permisos de administrador para configurar el acceso en red.' -ForegroundColor Yellow
    exit
}

$sid = $identidad.User.Value
$sddl = "D:(A;;GX;;;S-1-5-18)(A;;GX;;;$sid)"

foreach ($url in @("https://+:$puertoHttps/","http://+:$puertoHttp/")) {
    & netsh http delete urlacl "url=$url" 2>$null | Out-Null
    & netsh http add urlacl "url=$url" "sddl=$sddl" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "No se pudo crear la URL ACL $url" }
}

foreach ($puerto in @($puertoHttps,$puertoHttp)) {
    $nombre = "DataHunt $puerto TLS"
    & netsh advfirewall firewall delete rule "name=$nombre" 2>$null | Out-Null
    & netsh advfirewall firewall add rule "name=$nombre" dir=in action=allow protocol=TCP "localport=$puerto" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "No se pudo crear la regla de firewall para el puerto $puerto" }
}

Write-Host ''
Write-Host 'Configuracion de red completada.' -ForegroundColor Green
Write-Host 'La aplicacion NO se levanta con este script. Usa:' -ForegroundColor Cyan
Write-Host '  pwsh -File C:\DataHunt\Iniciar-DataHunt.ps1' -ForegroundColor Cyan
Write-Host 'URL principal: https://kuxtal.com/' -ForegroundColor Cyan
Write-Host 'http://kuxtal.com/ redirige a HTTPS.' -ForegroundColor Cyan
