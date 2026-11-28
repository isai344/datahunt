# Lanzador de Data Hunt v2 - HTTPS 443 (hospitalkuxtal.com / kuxtal.com) + redireccion 80
# Uso: pwsh -File C:\DataHunt\Iniciar-DataHunt.ps1
# No toca el puerto 5990 (pertenece a MSStrgSvc).
$ErrorActionPreference = 'Stop'
$app     = 'C:\DataHunt\app.ps1'
$base    = 'C:\DataHunt'
$url     = 'https://hospitalkuxtal.com/'
$urlAlt  = 'https://kuxtal.com/'
$puerto  = 443
$puertoHttp = 80
$pwsh    = 'C:\Program Files\PowerShell\7\pwsh.exe'
$sid     = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# 1. PowerShell 7
if ($PSVersionTable.PSVersion.Major -lt 7) {
    if (Test-Path $pwsh) {
        & $pwsh -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
    throw 'Se requiere PowerShell 7 (pwsh) y no se encontro en la ruta esperada.'
}
Write-Host "[OK] PowerShell $($PSVersionTable.PSVersion.ToString())"

# 2. Archivos necesarios
$requeridos = @('app.ps1','users.csv','access_log.csv','arco_solicitudes.csv','Configurar-Red.ps1','Actualizar-DnsKuxtal.ps1')
$faltan = @($requeridos | Where-Object { -not (Test-Path (Join-Path $base $_)) })
if ($faltan.Count -gt 0) { throw "Faltan archivos en $base : $($faltan -join ', ')" }
Write-Host '[OK] Archivos de la aplicacion presentes'

# 3. URL ACL (SYSTEM + usuario actual) por SID
foreach ($entry in @(@("https://+:$puerto/",'HTTPS'), @("http://+:$puertoHttp/",'HTTP 80'))) {
    $aclUrl = $entry[0]
    $acl = (& netsh http show urlacl "url=$aclUrl" | Out-String)
    if ($acl -notmatch [regex]::Escape($sid)) {
        throw "La URL ACL de $aclUrl no incluye al usuario actual ($sid). Ejecuta Configurar-KuxtalCom.ps1 como administrador."
    }
}
Write-Host '[OK] URL ACL HTTPS 443 y HTTP 80 para el usuario actual'

# 4. Firewall
foreach ($p in @($puerto,$puertoHttp)) {
    $regla = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match "DataHunt $p TLS" -and $_.Enabled -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'
    })
    if ($regla.Count -eq 0) { throw "No hay regla de firewall para TCP $p. Ejecuta Configurar-KuxtalCom.ps1." }
}
Write-Host '[OK] Reglas de firewall TCP 443 y 80 habilitadas'

# 5. Certificado enlazado
$ssl = (& netsh http show sslcert "ipport=0.0.0.0:$puerto" | Out-String)
if ($ssl -notmatch 'Certificate Hash') { throw "No hay certificado enlazado en 0.0.0.0:$puerto. Ejecuta Configurar-KuxtalCom.ps1." }
Write-Host '[OK] Certificado TLS enlazado en 443'

# 6. Puerto libre
$listen = @(Get-NetTCPConnection -LocalPort $puerto -State Listen -ErrorAction SilentlyContinue)
if ($listen.Count -gt 0) {
    Write-Host "[INFO] El puerto $puerto ya tiene un listener; la app podria estar ya levantada."
    Write-Host "       Verifica con: Invoke-WebRequest $url -UseBasicParsing"
    exit 0
}

# 7. Arrancar app.ps1
$proc = Start-Process -FilePath $pwsh `
    -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$app `
    -WorkingDirectory $base -WindowStyle Hidden -PassThru

$listo = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 500
    if (@(Get-NetTCPConnection -LocalPort $puerto -State Listen -ErrorAction SilentlyContinue).Count -gt 0) { $listo = $true; break }
}
if (-not $listo) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    throw 'La app no llego a escuchar en 443. Revisa eventos y permisos.'
}

$verificado = $null
foreach ($u in @($url,$urlAlt)) {
    try {
        $resp = Invoke-WebRequest -Uri $u -TimeoutSec 10 -UseBasicParsing
        if ([int]$resp.StatusCode -eq 200) { $verificado = $u; break }
    } catch { }
}
if (-not $verificado) {
    try {
        $resp = Invoke-WebRequest -Uri "https://127.0.0.1:$puerto/" -TimeoutSec 10 -UseBasicParsing -SkipCertificateCheck
        Write-Warning "La app responde por 127.0.0.1 pero NO por $url ni $urlAlt . Revisa DNS/hosts."
    } catch {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        throw "La app escucha pero no responde 200: $($_.Exception.Message)"
    }
}

Write-Host "[OK] Data Hunt v2 en linea: $verificado"
Write-Host "     PID: $($proc.Id)"
Write-Host "     Para detenerla: Stop-Process -Id $($proc.Id)"
