# Configura kuxtal.com (DNS + TLS) para Data Hunt v2 en SRV-HOSP-01.
# Requiere administrador. Seguro para re-ejecutar (idempotente).
# NO toca el puerto 5990 (pertenece a MSStrgSvc).
$ErrorActionPreference = 'Stop'

$Dominio    = 'hospitalkuxtal.com'
$AliasDominio = 'kuxtal.com'
$IPInicial  = '192.168.100.50'
$AppId      = '{B1E4A0F2-3C5D-4E67-9A80-1D2F3C4B5E6A}'
$CerPath    = 'C:\DataHunt\hospitalkuxtal.com.cer'
$Base       = 'C:\DataHunt'

# ---------------------------------------------------------------- 0. ADMIN
$identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identidad)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $ejecutable = 'C:\Program Files\PowerShell\7\pwsh.exe'
    if (-not (Test-Path $ejecutable)) { $ejecutable = 'powershell.exe' }
    Start-Process -FilePath $ejecutable -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath)) -Verb RunAs | Out-Null
    Write-Host 'Se solicitaron permisos de administrador.' -ForegroundColor Yellow
    exit
}
$sidUsuario = $identidad.User.Value
Write-Host "[OK] Administrador: $($identidad.Name) (SID $sidUsuario)"

# ---------------------------------------------------------------- 1. CERTIFICADO
$cert = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
    $_.Subject -eq "CN=$Dominio" -and $_.NotAfter -gt (Get-Date) -and
    (($_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }).Format($true) -join ' ') -match 'hospitalkuxtal\.com'
} | Sort-Object NotAfter -Descending | Select-Object -First 1)

if ($cert.Count -eq 0) {
    Write-Host "Creando certificado autofirmado CN=$Dominio con SAN completo ..."
    $san = '2.5.29.17={text}DNS=hospitalkuxtal.com&DNS=www.hospitalkuxtal.com&DNS=kuxtal.com&DNS=www.kuxtal.com&DNS=srv-hosp-01&IPAddress=192.168.100.50&IPAddress=192.168.100.61&IPAddress=100.109.230.106'
    $eku = '2.5.29.37={text}1.3.6.1.5.5.7.3.1'
    $cert = @(New-SelfSignedCertificate `
        -Subject "CN=$Dominio" `
        -CertStoreLocation 'Cert:\LocalMachine\My' `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -TextExtension @($san,$eku) `
        -NotAfter (Get-Date).AddYears(2) `
        -FriendlyName "Data Hunt $Dominio")
} else {
    Write-Host "[OK] Certificado existente: $($cert[0].Thumbprint)"
}
$thumb = $cert[0].Thumbprint
Write-Host "[OK] Thumbprint: $thumb"

Export-Certificate -Cert $cert[0] -FilePath $CerPath -Force | Out-Null
Write-Host "[OK] Certificado exportado: $CerPath"

# Confianza local (para que el propio servidor valide https://kuxtal.com/)
if (-not @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object Thumbprint -eq $thumb).Count) {
    Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host '[OK] Certificado agregado a Trusted Root local'
} else {
    Write-Host '[OK] Certificado ya está en Trusted Root local'
}

# Confianza de dominio (equivalente a GPO de certificados raíz)
Write-Host 'Publicando en Trusted Root de Active Directory ...'
certutil -dspublish -f "$CerPath" RootCA 2>&1 | Out-Host
Write-Host '[OK] Publicación AD intentada (revisa salida de certutil)'

# ---------------------------------------------------------------- 2. TLS 443
foreach ($ipport in @('0.0.0.0:443','[::]:443')) {
    & netsh http delete sslcert "ipport=$ipport" 2>$null | Out-Null
    & netsh http add sslcert "ipport=$ipport" "certhash=$thumb" "appid=$AppId" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "No se pudo enlazar el certificado en $ipport" }
}
Write-Host '[OK] TLS enlazado en 0.0.0.0:443 y [::]:443'

# ---------------------------------------------------------------- 3. URL ACL
$sddl = "D:(A;;GX;;;S-1-5-18)(A;;GX;;;$sidUsuario)"
foreach ($url in @('https://+:443/','http://+:80/')) {
    & netsh http delete urlacl "url=$url" 2>$null | Out-Null
    & netsh http add urlacl "url=$url" "sddl=$sddl" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "No se pudo crear URL ACL $url" }
}
Write-Host '[OK] URL ACL https://+:443/ y http://+:80/ (SYSTEM + usuario actual)'

# ---------------------------------------------------------------- 4. FIREWALL
foreach ($puerto in @(443,80)) {
    $nombre = "DataHunt $puerto TLS"
    & netsh advfirewall firewall delete rule "name=$nombre" 2>$null | Out-Null
    & netsh advfirewall firewall add rule "name=$nombre" dir=in action=allow protocol=TCP "localport=$puerto" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "No se pudo crear regla de firewall para $puerto" }
}
Write-Host '[OK] Firewall TCP 443 y 80 habilitado'

# ---------------------------------------------------------------- 5. DNS (ambos dominios)
# Actualizar-DnsKuxtal.ps1 crea/actualiza kuxtal.com y hospitalkuxtal.com
# (zonas primarias locales, registro A y CNAME www) y el hosts del servidor.
Import-Module DnsServer
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Base 'Actualizar-DnsKuxtal.ps1') | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Warning 'La actualizacion inicial de DNS devolvio error; revisa dns_update.log' }

# ---------------------------------------------------------------- 6. TAREAS
Write-Host 'Creando tareas programadas ...'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Base 'Configurar-Tareas.ps1') | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'No se pudieron crear las tareas programadas' }

# ---------------------------------------------------------------- 7. RESUMEN
Write-Host ''
Write-Host '=== CONFIGURACION COMPLETADA ===' -ForegroundColor Green
Write-Host "URL principal: https://$Dominio/" -ForegroundColor Cyan
Write-Host "Alias: https://$AliasDominio/  |  http://$Dominio/ redirige a HTTPS (puerto 80)." -ForegroundColor Cyan
foreach ($z in @($AliasDominio,$Dominio)) {
    Write-Host "DNS $z -> $((Get-DnsServerResourceRecord -ZoneName $z -Name '@' -RRType A).RecordData.IPv4Address -join ', ')"
}
Write-Host 'Certificado: ' -NoNewline
Write-Host "$thumb (CN=$Dominio, SAN hospitalkuxtal.com/www/kuxtal.com/www/srv-hosp-01 + IPs, SHA-256, 2048 bits)"
Write-Host ''
Write-Host 'Rollback: C:\DataHunt\backup_kuxtalcom_20261127.txt'
