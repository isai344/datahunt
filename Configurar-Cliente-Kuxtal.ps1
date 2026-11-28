# Configura una PC cliente para abrir Data Hunt sin avisos de seguridad:
#   https://hospitalkuxtal.com/  (principal)
#   https://kuxtal.com/          (alias)
#   https://192.168.100.50/      (IP, tambien incluida en el certificado)
# Uso (en el cliente, como administrador):
#   powershell.exe -ExecutionPolicy Bypass -File C:\DataHunt\Configurar-Cliente-Kuxtal.ps1
#   Opcional: -SetDns para usar al servidor como DNS primario.
#   Opcional: -ServidorIp 100.109.230.106 si entra por Tailscale.
param(
    [string]$ServidorIp = '192.168.100.50',
    [switch]$SetDns
)

$ErrorActionPreference = 'Stop'
$HostsPath   = 'C:\Windows\System32\drivers\etc\hosts'
$Marcador    = '# Data Hunt dominios (gestionado por Configurar-Cliente-Kuxtal.ps1)'
$Thumbprint  = 'A5505BF4269ABD7D387B80E8B3D0ADC9C737BE9F'

# Certificado raiz autofirmado del servidor (CN=hospitalkuxtal.com).
$CertB64 = @'
MIIDfjCCAmagAwIBAgIQGxU2ruky+otIVoIy/S9bzzANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDDBJob3NwaXRhbGt1eHRhbC5jb20wHhcNMjYxMTI3MjExNTQ5WhcNMjgxMTI3MjEyNTQ5WjAdMRswGQYDVQQDDBJob3NwaXRhbGt1eHRhbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCia1Y/VIqwfrvQCgDhQPthXFMIMUE/Tt/Kl+OToHtsJ5oWj7/qKFWyx2epBFkpcUv1JFxj7u5nszkQxhOgW801Xa8wjFMcV2aDzwZaRU/2hK7r/JDlFECd2jxtw0zsuYuocDoSHJgRWjcqX720lICGoMKkyj98ToLk59rAUKHwMwhDiNvyb+QFIl3/vwS75wjG7mtVmFW0yoeXQmxWAjBLkJ3AyhGShulYLcL5PR4Ise8JCrMlWLb0xxJyPZecgirYcFyHo0FASgBD+G6LQPpVau/QBT9QeCXX4MiXlY1A9SX109m1kunXVbTgarBFI1XfUqPNlWJN8QYJDvCNSMPBAgMBAAGjgbkwgbYwDgYDVR0PAQH/BAQDAgWgMHAGA1UdEQRpMGeCEmhvc3BpdGFsa3V4dGFsLmNvbYIWd3d3Lmhvc3BpdGFsa3V4dGFsLmNvbYIKa3V4dGFsLmNvbYIOd3d3Lmt1eHRhbC5jb22CC3Nydi1ob3NwLTAxhwTAqGQyhwTAqGQ9hwRkbeZqMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBSG1znnbB86KrGlQiEkk6dtU/AHszANBgkqhkiG9w0BAQsFAAOCAQEAgM8T32Kdgux4CiFnG6js7o/pwMm1uQCrnKumcHbo6RrqGZecmLktuWzV9Bn3NIkLBC1piQpFG4H0bVpi8SzBS8l0YHvotXLl5Tabff8Xhb/Kz7eHniAKQ8oZd8E7v03Z4iPOKzXCaapiaHR2p1f6+iyKIQcEiVzdj0aLo0Opf5niYaQF+5v6+u682CJXKGFGCrAAmfJdyqFhyy47GquO/m530yRdNnnte4d9RKYlKozI49JXV0e/vhtUuiwNAPSHpW6rLF3z6gvhy28r0vMf2Py1bVV4IQBa2JML7PpVB5jnDZqLFGDDMSYGpuenE15iHoVAmJhUcQ+N+snTAc5lOQ==
'@

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath)) -Verb RunAs | Out-Null
    Write-Host 'Se solicitaron permisos de administrador.' -ForegroundColor Yellow
    exit
}

# 1) Certificado en Trusted Root: elimina el aviso "no es seguro".
try {
    $ya = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object Thumbprint -eq $Thumbprint)
    if ($ya.Count -eq 0) {
        $tmp = Join-Path $env:TEMP 'hospitalkuxtal-root.cer'
        [System.IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String($CertB64))
        Import-Certificate -FilePath $tmp -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop | Out-Null
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        Write-Host '[OK] Certificado importado en Trusted Root'
    } else {
        Write-Host '[OK] Certificado ya estaba en Trusted Root'
    }
} catch {
    Write-Warning "No se pudo importar el certificado: $($_.Exception.Message)"
}

# 2) Entradas hosts: funcionan aunque el DNS apunte al router.
$lineas = @(Get-Content -LiteralPath $HostsPath -ErrorAction Stop | Where-Object {
    $_ -notmatch '# Data Hunt'
})
$lineas += "$ServidorIp kuxtal.com www.kuxtal.com hospitalkuxtal.com www.hospitalkuxtal.com $Marcador"
Set-Content -LiteralPath $HostsPath -Value $lineas -Encoding ASCII -ErrorAction Stop
Write-Host "[OK] Dominios -> $ServidorIp en el archivo hosts"

# 3) Opcional: cliente usa al servidor como DNS primario.
if ($SetDns) {
    $servidores = Get-DnsClientServerAddress -AddressFamily IPv4 |
        Where-Object { $_.ServerAddresses.Count -gt 0 -and $_.InterfaceAlias -notmatch 'Loopback' }
    foreach ($nic in $servidores) {
        $actuales = @($nic.ServerAddresses | Where-Object { $_ -ne $ServidorIp })
        $nuevos = @($ServidorIp) + $actuales
        Set-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses $nuevos -ErrorAction Stop
        Write-Host "[OK] DNS de $($nic.InterfaceAlias): $($nuevos -join ', ')"
    }
} else {
    Write-Host '[INFO] No se cambio el DNS del cliente (uso -SetDns para hacerlo).'
}

ipconfig /flushdns | Out-Null

# 4) Verificacion validando certificado (sin -SkipCertificateCheck).
# Solo se prueban los dominios: estan en el SAN del certificado. La IP de una
# red ajena (ej. Wi-Fi de una escuela) no esta en el SAN, asi que no se usa
# como prueba HTTPS; se comprueba TCP abierto mas abajo.
foreach ($u in @('https://hospitalkuxtal.com/','https://kuxtal.com/')) {
    try {
        $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 15
        Write-Host "[OK] $u -> HTTP $([int]$r.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Warning "FAIL $u -> $($_.Exception.Message)"
    }
}
$tcp = Test-NetConnection -ComputerName $ServidorIp -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue
if ($tcp) {
    Write-Host "[OK] TCP 443 -> $ServidorIp abierto" -ForegroundColor Green
} else {
    Write-Warning "FAIL TCP 443 -> $ServidorIp (revisa la IP o que ambos esteen en la misma red)"
}

Write-Host ''
Write-Host 'Rollback: quita la linea marcada del hosts y el certificado de Trusted Root:'
Write-Host "  Remove-Item Cert:\LocalMachine\Root\$Thumbprint"
