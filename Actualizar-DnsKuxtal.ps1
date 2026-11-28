# Actualiza los registros A de kuxtal.com y hospitalkuxtal.com con la IP LAN activa.
# Se ejecuta al arrancar y cada 5 minutos (tareas Kuxtal-DNS-Actualizar*).
# Preferencia por defecto: Ethernet > Wi-Fi > cualquier otra IP LAN. Ignora Tailscale y APIPA.
# Modo exposición: -Preferir 'Wi-Fi' o -ForzarIp <ip> para usar la IP del Wi-Fi de la escuela.
param(
    [string]$ForzarIp = '',
    [string]$Preferir = ''
)
$ErrorActionPreference = 'Stop'
Import-Module DnsServer

$Dominios  = @('kuxtal.com','hospitalkuxtal.com')
$Log       = 'C:\DataHunt\dns_update.log'
$HostsPath = 'C:\Windows\System32\drivers\etc\hosts'
$Marcador  = '# Data Hunt dominios (gestionado por Actualizar-DnsKuxtal.ps1)'

function Set-HostsKuxtal([string]$ip) {
    try {
        $lineas = @(Get-Content -LiteralPath $HostsPath -ErrorAction Stop | Where-Object {
            $_ -notmatch '# Data Hunt'
        })
        $lineas += "$ip kuxtal.com www.kuxtal.com hospitalkuxtal.com www.hospitalkuxtal.com $Marcador"
        Set-Content -LiteralPath $HostsPath -Value $lineas -Encoding ASCII -ErrorAction Stop
        & ipconfig /flushdns 2>$null | Out-Null
        return $true
    } catch { return $false }
}

function Escribir([string]$mensaje) {
    $linea = "$(Get-Date -Format 'o') $mensaje"
    Add-Content -LiteralPath $Log -Value $linea -ErrorAction SilentlyContinue
    Write-Host $linea
}

try {
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
        $_.IPAddress -ne '127.0.0.1' -and
        $_.IPAddress -notmatch '^169\.254\.' -and
        $_.PrefixOrigin -ne 'WellKnown' -and
        $_.InterfaceAlias -notmatch 'Tailscale'
    })

    $ip = $null
    if ($ForzarIp -match '^\d{1,3}(\.\d{1,3}){3}$' -and $ForzarIp -notmatch '^169\.254\.') {
        $ip = $ForzarIp
    } else {
        $orden = @()
        if ($Preferir) { $orden += $Preferir }
        $orden += @('Ethernet', 'Wi-Fi')
        $orden = @($orden | Select-Object -Unique)
        foreach ($alias in $orden) {
            $candidata = @($ips | Where-Object { $_.InterfaceAlias -eq $alias } | Select-Object -First 1)
            if ($candidata.Count -gt 0) { $ip = $candidata[0].IPAddress; break }
        }
        if (-not $ip -and $ips.Count -gt 0) { $ip = $ips[0].IPAddress }
    }
    if (-not $ip) { Escribir 'ERROR: no hay IP LAN disponible'; exit 1 }

    $hostsOk = Set-HostsKuxtal $ip
    $cambios = @()

    foreach ($dominio in $Dominios) {
        if (-not (Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue)) {
            Add-DnsServerPrimaryZone -Name $dominio -ZoneFile "$dominio.dns" -DynamicUpdate None -ErrorAction Stop
            Add-DnsServerResourceRecordCName -ZoneName $dominio -Name 'www' -HostNameAlias "$dominio." -ErrorAction Stop
            $cambios += "$dominio (zona creada)"
        }
        $registros = @(Get-DnsServerResourceRecord -ZoneName $dominio -Name '@' -RRType A -ErrorAction SilentlyContinue)
        $actuales  = @($registros | ForEach-Object { $_.RecordData.IPv4Address.ToString() })
        if ($actuales.Count -eq 1 -and $actuales[0] -eq $ip) { continue }

        foreach ($r in $registros) {
            Remove-DnsServerResourceRecord -ZoneName $dominio -InputObject $r -Force -ErrorAction SilentlyContinue
        }
        Add-DnsServerResourceRecordA -ZoneName $dominio -Name '@' -IPv4Address $ip -ErrorAction Stop
        $cambios += "$dominio -> $ip (antes: $($actuales -join ','))"
    }

    if ($cambios.Count -eq 0) {
        Escribir "SIN CAMBIOS: $($Dominios -join ', ') -> $ip (hosts: $hostsOk)"
    } else {
        Escribir "ACTUALIZADO: $($cambios -join '; ') (hosts: $hostsOk)"
    }
} catch {
    Escribir "ERROR: $($_.Exception.Message)"
    exit 1
}
