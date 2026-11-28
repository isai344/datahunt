# Prepara el servidor y genera el paquete para la PC del amigo cuando el
# servidor se conecta a una red distinta (por ejemplo, Wi-Fi de una escuela).
#
# Uso en el SERVIDOR, como administrador:
#   powershell.exe -ExecutionPolicy Bypass -File C:\DataHunt\Expo\Preparar-Exposicion.ps1
# Opcional:
#   -ForzarIp 192.168.15.23   (si quieres elegir la IP a mano)
#   -SoloVerificar            (no cambia nada, solo muestra lo que haria)
#
# NO modifica cuentas, contraseñas ni el puerto 5990.
param(
    [string]$ForzarIp = '',
    [string]$Preferir = 'Wi-Fi',
    [switch]$SoloVerificar
)

$ExpoDir = Split-Path -Parent $PSCommandPath
$padre = Split-Path -Parent $ExpoDir
# Si el kit se descomprimio en otro sitio, usar siempre la instalacion real.
$DataDir = if (Test-Path -LiteralPath (Join-Path $padre 'Actualizar-DnsKuxtal.ps1')) {
    $padre
} else {
    'C:\DataHunt'
}
$LogPath = Join-Path $ExpoDir 'expo.log'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argsElev = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath))
    if ($ForzarIp) { $argsElev += @('-ForzarIp', $ForzarIp) }
    if ($Preferir) { $argsElev += @('-Preferir', $Preferir) }
    if ($SoloVerificar) { $argsElev += '-SoloVerificar' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $argsElev -Verb RunAs | Out-Null
    Write-Host 'Se solicitaron permisos de administrador.' -ForegroundColor Yellow
    exit
}

function Log([string]$mensaje) {
    $linea = "$(Get-Date -Format 'o') $mensaje"
    Add-Content -LiteralPath $LogPath -Value $linea -ErrorAction SilentlyContinue
    Write-Host $linea
}

function Obtener-Ip {
    if ($ForzarIp -match '^\d{1,3}(\.\d{1,3}){3}$' -and $ForzarIp -notmatch '^169\.254\.') {
        return $ForzarIp
    }
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
        $_.IPAddress -ne '127.0.0.1' -and
        $_.IPAddress -notmatch '^169\.254\.' -and
        $_.PrefixOrigin -ne 'WellKnown' -and
        $_.InterfaceAlias -notmatch 'Tailscale'
    })
    $orden = @()
    if ($Preferir) { $orden += $Preferir }
    $orden += @('Wi-Fi', 'Ethernet')
    $orden = @($orden | Select-Object -Unique)
    foreach ($alias in $orden) {
        $candidata = @($ips | Where-Object { $_.InterfaceAlias -eq $alias } | Select-Object -First 1)
        if ($candidata.Count -gt 0) { return $candidata[0].IPAddress }
    }
    if ($ips.Count -gt 0) { return $ips[0].IPAddress }
    return $null
}

function Verificar-Servidor([string]$ip) {
    $tcp = Test-NetConnection -ComputerName $ip -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue
    $app = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'app\.ps1' }).Count
    $reglas = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @(
            '{CD269EDF-13E8-494C-9C9F-24F09CE469E0}',
            '{CACF9902-88CE-4F7C-B8BB-7904B9F90EAC}'
        ) -and $_.Enabled }).Count
    [pscustomobject]@{ Tcp443 = [bool]$tcp; AppProcesos = $app; ReglasFW = $reglas }
}

function Probar-Url([string]$url) {
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        return "HTTP $([int]$r.StatusCode)"
    } catch {
        $resp = $_.Exception.Response
        return $(if ($resp) { "HTTP $([int]$resp.StatusCode)" } else { "ERROR $($_.Exception.Message)" })
    }
}

function Generar-Paquete([string]$ip) {
    $paquete = Join-Path $ExpoDir 'Paquete-Amigo'
    New-Item -ItemType Directory -Path $paquete -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $DataDir 'Configurar-Cliente-Kuxtal.ps1') `
        -Destination (Join-Path $paquete 'Configurar-Cliente-Kuxtal.ps1') -Force
    Copy-Item -LiteralPath (Join-Path $DataDir 'hospitalkuxtal.com.cer') `
        -Destination (Join-Path $paquete 'hospitalkuxtal.com.cer') -Force

    $cmd = @"
@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Configurar-Cliente-Kuxtal.ps1" -ServidorIp $ip
echo.
echo Terminado. Abre kuxtal.com en el navegador.
pause
"@
    Set-Content -LiteralPath (Join-Path $paquete 'Configurar-Amigo.cmd') -Value $cmd -Encoding ASCII

    $tsIp = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -match 'Tailscale' } | Select-Object -First 1).IPAddress
    if ($tsIp) {
        $tsCmd = @"
@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Configurar-Cliente-Kuxtal.ps1" -ServidorIp $tsIp
echo.
echo Terminado (modo Tailscale). Abre kuxtal.com en el navegador.
pause
"@
        Set-Content -LiteralPath (Join-Path $paquete 'Configurar-Amigo-Tailscale.cmd') -Value $tsCmd -Encoding ASCII
    }

    $instr = @"
DATA HUNT EN LA ESCUELA - PC DEL AMIGO
======================================

El servidor esta en la IP: $ip

1) Copia esta carpeta a la PC del amigo (USB, correo o OneDrive).
2) Clic derecho en Configurar-Amigo.cmd -> Ejecutar como administrador.
3) Acepta el aviso de UAC.
4) Abre el navegador y escribe solo:

   kuxtal.com

   Tambien funciona hospitalkuxtal.com. No escribas IP ni puerto.

El .cmd hace dos cosas: apunta kuxtal.com a $ip en el archivo hosts e importa
el certificado para que no aparezca el aviso "No es seguro".

VERIFICACION EN LA PC DEL AMIGO
-------------------------------
   Test-NetConnection $ip -Port 443
Debe dar TcpTestSucceeded : True

SI EL WIFI DE LA ESCUELA AISLA A LOS EQUIPOS
--------------------------------------------
Algunos Wi-Fi de escuela bloquean que un equipo vea a otro. Si el Test-NetConnection
anterior da False, instala Tailscale en la PC del amigo, entra a la misma tailnet
y ejecuta Configurar-Amigo-Tailscale.cmd en vez del otro. Eso funciona aunque
el Wi-Fi aisle a los equipos.

NOTA
----
Esto sirve para equipos en la MISMA red de la escuela. No publica la pagina en
Internet. Para acceso publico haria falta un tunel o redireccion de puertos y un
certificado publico (no cambiar sin aprobacion).
"@
    Set-Content -LiteralPath (Join-Path $paquete 'INSTRUCCIONES-AMIGO.txt') -Value $instr -Encoding UTF8

    $resumen = @"
PARA EL AMIGO - DATA HUNT (exposicion)
======================================
IP del servidor en esta red: $ip
Dominio en el navegador:     kuxtal.com

Opcion A: descomprimir Paquete-Amigo-Expo.zip y ejecutar Configurar-Amigo.cmd
          como administrador.
Opcion B (manual):
   powershell.exe -ExecutionPolicy Bypass -File .\Configurar-Cliente-Kuxtal.ps1 -ServidorIp $ip

$(if ($tsIp) { "Opcion C si el Wi-Fi asla equipos (Tailscale): Configurar-Amigo-Tailscale.cmd -> servidor $tsIp" } else { "Tailscale: no se detecto IP en esta sesion." })

El ZIP a enviar es: $(Join-Path $ExpoDir 'Paquete-Amigo-Expo.zip')
"@
    Set-Content -LiteralPath (Join-Path $ExpoDir 'PARA-EL-AMIGO.txt') -Value $resumen -Encoding UTF8

    $zip = Join-Path $ExpoDir 'Paquete-Amigo-Expo.zip'
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $paquete '*') -DestinationPath $zip -CompressionLevel Optimal
    return $zip
}

$ip = Obtener-Ip
if (-not $ip) { throw 'No se encontro una IP LAN valida. Conecta el Wi-Fi y vuelve a intentar.' }
$iface = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq $ip } | Select-Object -First 1).InterfaceAlias
Log "IP seleccionada: $ip ($iface). Modo: $(if ($SoloVerificar) { 'solo verificacion' } else { 'aplicar' })"

$estado = Verificar-Servidor $ip
Log "Servidor: TCP443=$($estado.Tcp443), procesos app=$($estado.AppProcesos), reglas firewall=$($estado.ReglasFW)/2"

if ($SoloVerificar) {
    Log "Propuesta: la PC del amigo debe ejecutar Configurar-Cliente-Kuxtal.ps1 -ServidorIp $ip y abrir kuxtal.com"
    Log 'No se modifico nada (SoloVerificar).'
    return
}

if ($estado.AppProcesos -eq 0) {
    Log 'La app no esta corriendo: iniciando tarea Kuxtal-DataHunt-Auto'
    Start-ScheduledTask -TaskName 'Kuxtal-DataHunt-Auto' -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $estado = Verificar-Servidor $ip
}
if (-not $estado.Tcp443) {
    throw "El puerto 443 no responde en $ip. Revisa que la app este activa antes de seguir."
}

$actualizador = Join-Path $DataDir 'Actualizar-DnsKuxtal.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $actualizador -ForzarIp $ip -Preferir $Preferir 2>&1 |
    ForEach-Object { Log "DNS: $_" }

Log "Local https://hospitalkuxtal.com/ -> $(Probar-Url 'https://hospitalkuxtal.com/')"
Log "Local https://kuxtal.com/ -> $(Probar-Url 'https://kuxtal.com/')"

$zip = Generar-Paquete $ip
Log "Paquete generado: $zip"
Log "Resumen para el amigo: $(Join-Path $ExpoDir 'PARA-EL-AMIGO.txt')"
Log 'LISTO. Entrega el ZIP al amigo; el debe abrir kuxtal.com (sin IP ni puerto).'
