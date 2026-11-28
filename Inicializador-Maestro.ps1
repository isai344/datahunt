# ==============================================================================
# INICIALIZADOR MAESTRO - Data Hunt v2 / Hospital Integral Kuxtal
# ==============================================================================
# Punto unico de entrada para dejar el sistema en el estado acordado:
#   - HTTPS directo en 443 (hospitalkuxtal.com + alias kuxtal.com); 80 solo redirige.
#   - Puerto 5000 sin uso; puerto 5990 de MSStrgSvc INTACTO (solo se lee).
#   - Certificado CN=hospitalkuxtal.com vigente y confiable en el servidor.
#   - DNS local con zonas primarias, registro A y CNAME www para ambos dominios.
#   - hosts del servidor, URL ACL, firewall y tareas programadas.
#   - users.csv con las 82 cuentas; PasswordHash originales; TOTP existente NO se
#     sobrescribe (si esta vacio se restaura desde las fuentes originales).
#   - Paquetes para clientes y kit de exposicion generados.
#
# Uso (como administrador):
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\DataHunt\Inicializador-Maestro.ps1
#
# Opciones:
#   -SoloVerificar        No cambia nada; solo imprime el diagnostico.
#   -ForzarIp 10.0.0.5    Fuerza la IP de los registros A y del hosts.
#   -Preferir 'Wi-Fi'     Elige interfaz (por defecto Ethernet > Wi-Fi).
#   -ModoExposicion       Como -Preferir 'Wi-Fi' y ademas genera el paquete del amigo.
#   -OmitirPaquetes       No regenera los ZIP.
#   -OmitirTareas         No re-registra las tareas programadas.
#
# NO prueba login de cuentas privilegiadas y NO modifica sus claves ni secretos.
# ==============================================================================
param(
    [string]$ForzarIp = '',
    [string]$Preferir = '',
    [switch]$ModoExposicion,
    [switch]$SoloVerificar,
    [switch]$OmitirPaquetes,
    [switch]$OmitirTareas
)

$ErrorActionPreference = 'Stop'

$Base        = Split-Path -Parent $PSCommandPath
$Dominio     = 'hospitalkuxtal.com'
$Alias       = 'kuxtal.com'
$Thumb       = 'A5505BF4269ABD7D387B80E8B3D0ADC9C737BE9F'
$AppId       = '{B1E4A0F2-3C5D-4E67-9A80-1D2F3C4B5E6A}'
$CertPath    = Join-Path $Base 'hospitalkuxtal.com.cer'
$IpDelHospital = '192.168.100.50'
$Puerto      = 443
$PuertoHttp  = 80
$UsuarioApp  = 'KUXTAL\adm.isai'
$HostsPath   = 'C:\Windows\System32\drivers\etc\hosts'
$LogPath     = Join-Path $Base 'inicializador_maestro.log'
$Backups     = Join-Path $Base 'Backups-Maestro'
$Esperado5990 = @{
    '0.0.0.0:5990' = '594BB96ECE5C0CDEA58BFA54A67C033E2B3D4C1B'
    '[::]:5990'    = 'C0E0F9863A8A479508617C7C98050C0B6670C859'
}

# ---------------------------------------------------------------- 0. ADMIN
$identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identidad)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $ae = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath))
    if ($ForzarIp)       { $ae += @('-ForzarIp', $ForzarIp) }
    if ($Preferir)       { $ae += @('-Preferir', $Preferir) }
    if ($ModoExposicion) { $ae += '-ModoExposicion' }
    if ($SoloVerificar)  { $ae += '-SoloVerificar' }
    if ($OmitirPaquetes) { $ae += '-OmitirPaquetes' }
    if ($OmitirTareas)   { $ae += '-OmitirTareas' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $ae -Verb RunAs | Out-Null
    Write-Host 'Se solicitaron permisos de administrador.' -ForegroundColor Yellow
    exit
}

function Log([string]$mensaje, [string]$nivel = 'INFO') {
    $linea = "$(Get-Date -Format 'o') [$nivel] $mensaje"
    Add-Content -LiteralPath $LogPath -Value $linea -ErrorAction SilentlyContinue
    $color = switch ($nivel) { 'OK' {'Green'} 'WARN' {'Yellow'} 'ERROR' {'Red'} default {'Gray'} }
    Write-Host $linea -ForegroundColor $color
}

$PreferirEfectivo = $Preferir
if ($ModoExposicion -and -not $PreferirEfectivo -and -not $ForzarIp) { $PreferirEfectivo = 'Wi-Fi' }

# SIDs que deben poder enlazar 443/80: SYSTEM, quien ejecuta y la cuenta de la app.
$SidsRequeridos = @('S-1-5-18', $identidad.User.Value)
try {
    $SidsRequeridos += (New-Object Security.Principal.NTAccount($UsuarioApp)).Translate(
        [Security.Principal.SecurityIdentifier]).Value
} catch { }
$SidsRequeridos = @($SidsRequeridos | Select-Object -Unique)
$SddlUrl = 'D:' + (($SidsRequeridos | ForEach-Object { "(A;;GX;;;$_)" }) -join '')

function Obtener-Ip {
    if ($ForzarIp -match '^\d{1,3}(\.\d{1,3}){3}$' -and $ForzarIp -notmatch '^169\.254\.') { return $ForzarIp }
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notmatch '^169\.254\.' -and
        $_.PrefixOrigin -ne 'WellKnown' -and $_.InterfaceAlias -notmatch 'Tailscale'
    })
    $orden = @()
    if ($PreferirEfectivo) { $orden += $PreferirEfectivo }
    $orden += @('Ethernet','Wi-Fi')
    $orden = @($orden | Select-Object -Unique)
    foreach ($alias in $orden) {
        $c = @($ips | Where-Object { $_.InterfaceAlias -eq $alias } | Select-Object -First 1)
        if ($c.Count -gt 0) { return $c[0].IPAddress }
    }
    if ($ips.Count -gt 0) { return $ips[0].IPAddress }
    return $null
}

function Netsh-Ssl([string]$ipport) {
    return (( & netsh http show sslcert "ipport=$ipport" 2>$null ) -join "`n")
}
function Netsh-UrlAcl([string]$url) {
    return (( & netsh http show urlacl "url=$url" 2>$null ) -join "`n")
}
function Ssl-Hash([string]$ipport) {
    $s = Netsh-Ssl $ipport
    if ($s -match 'Certificate Hash\s*:\s*([0-9a-fA-F]+)') { return $Matches[1].ToUpperInvariant() }
    return ''
}
function Test-Url([string]$url, [int]$esperado = 200) {
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -MaximumRedirection 0 -ErrorAction Stop
        return [int]$r.StatusCode
    } catch {
        $resp = $_.Exception.Response
        if ($resp) { return [int]$resp.StatusCode }
        return 0
    }
}
function Test-Fw([int]$puerto) {
    $r = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -eq "DataHunt $puerto TLS" -and $_.Enabled -and
        $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Profile -eq 'Any'
    } | Select-Object -First 1)
    if ($r.Count -eq 0) { return $false }
    $pf = $r[0] | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    return ($null -ne $pf -and $pf.LocalPort -contains "$puerto")
}
function Test-Redirect([string]$url) {
    # curl no sigue redirecciones con -o NUL y devuelve el codigo real (301).
    $code = & curl.exe -m 15 -s -o NUL -w '%{http_code}' $url 2>$null
    if ($code -match '^\d{3}$') { return [int]$code }
    return 0
}
function Test-Zona([string]$zona, [string]$ip) {
    if (-not (Get-DnsServerZone -Name $zona -ErrorAction SilentlyContinue)) { return $false }
    $a = @(Get-DnsServerResourceRecord -ZoneName $zona -Name '@' -RRType A -ErrorAction SilentlyContinue |
        ForEach-Object { $_.RecordData.IPv4Address.ToString() })
    $c = @(Get-DnsServerResourceRecord -ZoneName $zona -Name 'www' -RRType CNAME -ErrorAction SilentlyContinue)
    return ($a.Count -eq 1 -and $a[0] -eq $ip -and $c.Count -ge 1)
}
function Test-Tarea([string]$nombre) {
    $t = Get-ScheduledTask -TaskName $nombre -ErrorAction SilentlyContinue
    return ($null -ne $t -and $t.State -eq 'Ready')
}
function Test-UrlAcl([string]$txt) {
    foreach ($sid in $SidsRequeridos) {
        if ($txt -match [regex]::Escape($sid)) { continue }
        # netsh muestra SYSTEM como alias SY o como "NT AUTHORITY\SYSTEM".
        if ($sid -eq 'S-1-5-18' -and
            ($txt -match [regex]::Escape('(A;;GX;;;SY)') -or
             $txt -match [regex]::Escape('NT AUTHORITY\SYSTEM'))) { continue }
        return $false
    }
    return $true
}

function Obtener-Estado {
    Import-Module DnsServer -ErrorAction SilentlyContinue
    $ip = Obtener-Ip
    $e = [ordered]@{}

    $e.Ip = $ip
    $e.CertMy = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumb -and $_.NotAfter -gt (Get-Date) }).Count -gt 0
    $e.Root = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumb }).Count -gt 0

    $s4 = Netsh-Ssl '0.0.0.0:443'; $s6 = Netsh-Ssl '[::]:443'
    $e.Cert443  = ($s4 -match [regex]::Escape($Thumb)) -and ($s4 -match [regex]::Escape($AppId))
    $e.Cert443v6 = ($s6 -match [regex]::Escape($Thumb)) -and ($s6 -match [regex]::Escape($AppId))

    $a4 = Netsh-UrlAcl 'https://+:443/'; $a8 = Netsh-UrlAcl 'http://+:80/'
    $e.UrlAcl443 = Test-UrlAcl $a4
    $e.UrlAcl80  = Test-UrlAcl $a8

    $e.Fw443 = Test-Fw $Puerto
    $e.Fw80  = Test-Fw $PuertoHttp

    $e.Dns = (Test-Zona $Dominio $ip) -and (Test-Zona $Alias $ip)
    $e.Hosts = @(Select-String -LiteralPath $HostsPath -Pattern '# Data Hunt' -SimpleMatch -ErrorAction SilentlyContinue |
        Where-Object { $_.Line -match [regex]::Escape([string]$ip) -and
                       $_.Line -match 'kuxtal\.com' -and $_.Line -match 'hospitalkuxtal\.com' }).Count -gt 0

    $filas = @(Import-Csv -LiteralPath (Join-Path $Base 'users.csv') -Encoding utf8 -ErrorAction SilentlyContinue)
    $e.Usuarios = $filas.Count
    $e.Duplicados = @($filas | Group-Object Email | Where-Object { $_.Count -gt 1 }).Count
    $e.HashesValidos = @($filas | Where-Object { $_.PasswordHash -match '^[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$' }).Count
    $e.ConTotp = @($filas | Where-Object { -not [string]::IsNullOrWhiteSpace($_.TotpSecret) }).Count
    $e.UsuariosOk = ($filas.Count -ge 80 -and $e.Duplicados -eq 0 -and $e.HashesValidos -eq $filas.Count)

    $e.Tareas = (Test-Tarea 'Kuxtal-DataHunt-Auto') -and (Test-Tarea 'Kuxtal-DNS-Actualizar') -and
                (Test-Tarea 'Kuxtal-DNS-Actualizar-Boot')
    $e.TareaVieja = @(Get-ScheduledTask -TaskName 'Kuxtal-DataHunt' -ErrorAction SilentlyContinue |
        Where-Object { $_.Principal.UserId -match 'svc_datahunt' -and $_.State -ne 'Disabled' }).Count

    $e.AppProcesos = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'app\.ps1' }).Count
    $e.Listen443 = @(Get-NetTCPConnection -LocalPort $Puerto -State Listen -ErrorAction SilentlyContinue).Count -gt 0
    $e.Listen5000 = @(Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue).Count -gt 0

    $e.HttpsPrincipal = Test-Url "https://$Dominio/" 200
    $e.HttpsAlias     = Test-Url "https://$Alias/" 200
    $e.HttpRedirect   = Test-Redirect "http://$Dominio/"

    $e.PaqueteCliente = Test-Path -LiteralPath (Join-Path $Base 'Paquete-Cliente-Kuxtal.zip')
    $e.KitExpo        = Test-Path -LiteralPath (Join-Path $Base 'Kit-Exposicion.zip')
    $e.ScriptCliente  = Test-Path -LiteralPath (Join-Path $Base 'Configurar-Cliente-Kuxtal.ps1')
    $e.ScriptExpo     = Test-Path -LiteralPath (Join-Path $Base 'Expo\Preparar-Exposicion.ps1')

    $e.C5990v4 = Ssl-Hash '0.0.0.0:5990'
    $e.C5990v6 = Ssl-Hash '[::]:5990'
    $e.C5990Ok = ($e.C5990v4 -eq $Esperado5990['0.0.0.0:5990']) -and
                 ($e.C5990v6 -eq $Esperado5990['[::]:5990'])
    return $e
}

function Respaldar {
    $b = Join-Path $Backups (Get-Date -Format 'yyyyMMdd_HHmmss')
    New-Item -ItemType Directory -Path $b -Force | Out-Null
    foreach ($f in @('users.csv','access_log.csv','adrian-emi.md','informe_para_emilio_20261127.txt')) {
        $origen = Join-Path $Base $f
        if (Test-Path -LiteralPath $origen) { Copy-Item -LiteralPath $origen -Destination $b -Force }
    }
    Copy-Item -LiteralPath $HostsPath -Destination (Join-Path $b 'hosts') -Force -ErrorAction SilentlyContinue
    (& netsh http show sslcert 2>$null) | Out-File (Join-Path $b 'sslcert.txt')
    (& netsh http show urlacl 2>$null) | Out-File (Join-Path $b 'urlacl.txt')
    Import-Module DnsServer -ErrorAction SilentlyContinue
    foreach ($z in @($Dominio,$Alias)) {
        Get-DnsServerResourceRecord -ZoneName $z -ErrorAction SilentlyContinue |
            Export-Csv -LiteralPath (Join-Path $b "dns_$z.csv") -NoTypeInformation -Encoding utf8
    }
    Get-ScheduledTask | Where-Object { $_.TaskName -like 'Kuxtal*' } |
        Export-Csv -LiteralPath (Join-Path $b 'tareas.csv') -NoTypeInformation -Encoding utf8
    Log "Respaldo previo: $b" 'OK'
    return $b
}

function Aplicar-Estado([System.Collections.IDictionary]$e) {
    Respaldar | Out-Null

    if (-not $e.CertMy) {
        throw "No existe el certificado $Thumb en LocalMachine\My. Restaura hospitalkuxtal.com.cer antes de continuar."
    }
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $Thumb } | Select-Object -First 1
    if (-not $e.Root) {
        Import-Certificate -FilePath $CertPath -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop | Out-Null
        Log 'Certificado importado en Trusted Root local' 'OK'
    }
    if (-not (Test-Path -LiteralPath $CertPath)) { Export-Certificate -Cert $cert -FilePath $CertPath -Force | Out-Null }

    foreach ($ipport in @('0.0.0.0:443','[::]:443')) {
        $s = Netsh-Ssl $ipport
        if (($s -notmatch [regex]::Escape($Thumb)) -or ($s -notmatch [regex]::Escape($AppId))) {
            & netsh http delete sslcert "ipport=$ipport" 2>$null | Out-Null
            & netsh http add sslcert "ipport=$ipport" "certhash=$Thumb" "appid=$AppId" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "No se pudo enlazar TLS en $ipport" }
            Log "TLS reenlazado en $ipport" 'OK'
        }
    }

    foreach ($entry in @(@('https://+:443/','UrlAcl443'), @('http://+:80/','UrlAcl80'))) {
        $url = $entry[0]; $clave = $entry[1]
        $txt = Netsh-UrlAcl $url
        if (-not (Test-UrlAcl $txt)) {
            & netsh http delete urlacl "url=$url" 2>$null | Out-Null
            & netsh http add urlacl "url=$url" "sddl=$SddlUrl" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "No se pudo corregir URL ACL $url" }
            Log "URL ACL corregida: $url" 'OK'
        }
    }

    foreach ($p in @($Puerto,$PuertoHttp)) {
        if (-not (Test-Fw $p)) {
            & netsh advfirewall firewall delete rule "name=DataHunt $p TLS" 2>$null | Out-Null
            & netsh advfirewall firewall add rule "name=DataHunt $p TLS" dir=in action=allow protocol=TCP "localport=$p" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "No se pudo crear la regla de firewall para $p" }
            Log "Regla firewall DataHunt $p TLS creada (Profile=Any)" 'OK'
        }
    }

    $argsDns = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f (Join-Path $Base 'Actualizar-DnsKuxtal.ps1')))
    if ($ForzarIp) { $argsDns += @('-ForzarIp', $ForzarIp) }
    if ($PreferirEfectivo) { $argsDns += @('-Preferir', $PreferirEfectivo) }
    & powershell.exe @argsDns 2>&1 | ForEach-Object { Log "DNS: $_" }
    Import-Module DnsServer -ErrorAction SilentlyContinue
    foreach ($z in @($Dominio,$Alias)) {
        $c = @(Get-DnsServerResourceRecord -ZoneName $z -Name 'www' -RRType CNAME -ErrorAction SilentlyContinue)
        if ($c.Count -eq 0) {
            Add-DnsServerResourceRecordCName -ZoneName $z -Name 'www' -HostNameAlias "$z." -ErrorAction Stop
            Log "CNAME www.$z creado" 'OK'
        }
    }
    Log "DNS y hosts apuntan a $($e.Ip)" 'OK'

    if ($e.Usuarios -eq 0) {
        Log 'users.csv estaba vacio: restaurando desde las fuentes originales' 'WARN'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Base 'Restaurar-Usuarios.ps1') 2>&1 |
            ForEach-Object { Log "Usuarios: $_" }
    } elseif (-not $e.UsuariosOk) {
        Log "users.csv tiene $($e.Usuarios) filas y $($e.Duplicados) duplicados. NO se reescribio para preservar TOTP." 'WARN'
    } else {
        Log "users.csv intacto: $($e.Usuarios) cuentas, $($e.ConTotp) con secreto TOTP preservado" 'OK'
    }

    if (-not $OmitirTareas) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Base 'Configurar-Tareas.ps1') 2>&1 |
            ForEach-Object { Log "Tareas: $_" }
    }
    if ($e.TareaVieja -gt 0) {
        Disable-ScheduledTask -TaskName 'Kuxtal-DataHunt' -ErrorAction SilentlyContinue | Out-Null
        Log 'Tarea antigua Kuxtal-DataHunt desactivada (usuario svc_datahunt$ inexistente)' 'OK'
    }

    if ($e.AppProcesos -eq 0 -or -not $e.Listen443) {
        $pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
        if (-not (Test-Path $pwsh)) { throw 'No se encontro PowerShell 7 (pwsh.exe).' }
        & $pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Base 'Iniciar-DataHunt.ps1') 2>&1 |
            ForEach-Object { Log "App: $_" }
    }

    if (-not $OmitirPaquetes) {
        $dirCliente = Join-Path $Base 'Paquete-Cliente'
        New-Item -ItemType Directory -Path $dirCliente -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $Base 'Configurar-Cliente-Kuxtal.ps1') `
            -Destination (Join-Path $dirCliente 'Configurar-Cliente-Kuxtal.ps1') -Force
        Copy-Item -LiteralPath $CertPath -Destination (Join-Path $dirCliente 'hospitalkuxtal.com.cer') -Force
        if (-not (Test-Path -LiteralPath (Join-Path $dirCliente 'INSTRUCCIONES.txt'))) {
            Set-Content -LiteralPath (Join-Path $dirCliente 'INSTRUCCIONES.txt') -Value @'
Copia esta carpeta a la PC cliente, ejecuta Configurar-Cliente-Kuxtal.ps1 como
administrador y abre kuxtal.com en el navegador (sin IP ni puerto).
'@ -Encoding UTF8
        }
        $zip = Join-Path $Base 'Paquete-Cliente-Kuxtal.zip'
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        Compress-Archive -Path (Join-Path $dirCliente '*') -DestinationPath $zip -CompressionLevel Optimal
        $shareZip = 'C:\Hospital\TI\Paquete-Cliente-Kuxtal.zip'
        if (Test-Path -LiteralPath 'C:\Hospital\TI') { Copy-Item -LiteralPath $zip -Destination $shareZip -Force }

        # GetTempPath devuelve la ruta larga real; $env:TEMP aqui viene en 8.3.
        $tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'kit_maestro_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $Base 'Expo\Preparar-Exposicion.ps1') -Destination $tmp -Force
        Copy-Item -LiteralPath (Join-Path $Base 'Expo\INSTRUCCIONES-EXPO.txt') -Destination $tmp -Force
        Copy-Item -LiteralPath $zip -Destination $tmp -Force
        $kit = Join-Path $Base 'Kit-Exposicion.zip'
        if (Test-Path -LiteralPath $kit) { Remove-Item -LiteralPath $kit -Force }
        Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $kit -CompressionLevel Optimal
        try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch { }
        Log 'Paquetes del cliente y kit de exposicion actualizados' 'OK'
    }

    if ($ModoExposicion) {
        $argsExpo = @('-NoProfile','-ExecutionPolicy','Bypass','-File',
                      ('"{0}"' -f (Join-Path $Base 'Expo\Preparar-Exposicion.ps1')),
                      '-ForzarIp', $e.Ip)
        & powershell.exe @argsExpo 2>&1 | ForEach-Object { Log "Expo: $_" }
    }
}

# ---------------------------------------------------------------- EJECUCION
Log '=== INICIALIZADOR MAESTRO - Data Hunt v2 ==='
Log "Administrador: $($identidad.Name)"
Log "Interprete: PowerShell $($PSVersionTable.PSVersion.ToString())"
Log "Modo: $(if ($SoloVerificar) { 'SOLO VERIFICAR' } elseif ($ModoExposicion) { 'EXPOSICION' } else { 'ESTADO FINAL' })"

$antes = Obtener-Estado
if (-not $antes.Ip) { throw 'No hay IP LAN valida. Conecta Ethernet o Wi-Fi.' }
Log "IP activa seleccionada: $($antes.Ip)"
Log "5990 antes: 0.0.0.0=$($antes.C5990v4) / [::]=$($antes.C5990v6)"

$criticosAntes = @(
    'CertMy','Cert443','Cert443v6','UrlAcl443','UrlAcl80','Fw443','Fw80',
    'Dns','Hosts','UsuariosOk','Tareas','Listen443'
)
$fallan = @($criticosAntes | Where-Object { -not $antes[$_] })
if ($fallan.Count -gt 0) { Log "Puntos a reparar: $($fallan -join ', ')" 'WARN' }

if ($SoloVerificar) {
    Log 'SoloVerificar: no se aplico ningun cambio.' 'OK'
} else {
    Aplicar-Estado $antes
}

$final = Obtener-Estado
if ($final.HttpRedirect -ne 301) { Log "HTTP 80 devolvio $($final.HttpRedirect) (esperado 301)" 'WARN' }

$checks = @(
    [pscustomobject]@{ Chequeo='Certificado 443'; Resultado=$final.Cert443 }
    [pscustomobject]@{ Chequeo='Certificado [::]:443'; Resultado=$final.Cert443v6 }
    [pscustomobject]@{ Chequeo='Certificado en Trusted Root'; Resultado=$final.Root }
    [pscustomobject]@{ Chequeo='URL ACL 443'; Resultado=$final.UrlAcl443 }
    [pscustomobject]@{ Chequeo='URL ACL 80'; Resultado=$final.UrlAcl80 }
    [pscustomobject]@{ Chequeo='Firewall 443'; Resultado=$final.Fw443 }
    [pscustomobject]@{ Chequeo='Firewall 80'; Resultado=$final.Fw80 }
    [pscustomobject]@{ Chequeo='DNS ambos dominios'; Resultado=$final.Dns }
    [pscustomobject]@{ Chequeo='Hosts del servidor'; Resultado=$final.Hosts }
    [pscustomobject]@{ Chequeo='users.csv (82, sin duplicados)'; Resultado=$final.UsuariosOk }
    [pscustomobject]@{ Chequeo='Tareas programadas'; Resultado=$final.Tareas }
    [pscustomobject]@{ Chequeo='App escuchando 443'; Resultado=$final.Listen443 }
    [pscustomobject]@{ Chequeo='Puerto 5000 libre'; Resultado=(-not $final.Listen5000) }
    [pscustomobject]@{ Chequeo="HTTPS $Dominio -> 200"; Resultado=($final.HttpsPrincipal -eq 200) }
    [pscustomobject]@{ Chequeo="HTTPS $Alias -> 200"; Resultado=($final.HttpsAlias -eq 200) }
    [pscustomobject]@{ Chequeo='HTTP 80 -> 301'; Resultado=($final.HttpRedirect -eq 301) }
    [pscustomobject]@{ Chequeo='Paquete cliente'; Resultado=$final.PaqueteCliente }
    [pscustomobject]@{ Chequeo='Kit exposicion'; Resultado=$final.KitExpo }
    [pscustomobject]@{ Chequeo='5990 sin cambios'; Resultado=(
        $final.C5990Ok -and $final.C5990v4 -eq $antes.C5990v4 -and $final.C5990v6 -eq $antes.C5990v6) }
)
$checks | ForEach-Object {
    $txt = if ($_.Resultado) { 'OK' } else { 'FALLO' }
    Log ("{0,-36} {1}" -f $_.Chequeo, $txt) $(if ($_.Resultado) { 'OK' } else { 'ERROR' })
}

Log "Usuarios: $($final.Usuarios); con TOTP: $($final.ConTotp); duplicados: $($final.Duplicados)"
Log 'Cuentas privilegiadas NO probadas por este inicializador; PasswordHash y secretos TOTP intactos.'
Log "URL principal: https://$Dominio/  |  Alias: https://$Alias/"

$erroresFinales = @($checks | Where-Object { -not $_.Resultado })
if ($erroresFinales.Count -gt 0) {
    Log "FINALIZO CON $($erroresFinales.Count) FALLOS. Revisa $LogPath y los respaldos." 'ERROR'
    exit 1
}
Log 'SISTEMA LISTO. No hace falta IP ni puerto: abre kuxtal.com.' 'OK'
exit 0
