# Hospital Integral Kuxtal - Reto 4: Pagina Web Data Hunt
# Version v2.0-SECURED - Arquitectura de UN SOLO ARCHIVO (app.ps1)
# Ejecucion: pwsh -File .\app.ps1  (recomendado detras de reverse proxy HTTPS)
# Toda modificacion de seguridad esta marcada con "# CORRECCIÓN H-XX".

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Warning "Este script esta certificado para PowerShell 7. Usa pwsh en produccion."
}

# ------------------------------------------------------------------------------
# 1. CONFIGURACION EDITABLE DEL SISTEMA
# ------------------------------------------------------------------------------
$CompanyName      = "Hospital Integral Kuxtal"
$AppVersion       = "v2.0-SECURED"
$DataPath         = "C:\DataHunt"
$UsersCsv         = Join-Path $DataPath "users.csv"
$AccessLogCsv     = Join-Path $DataPath "access_log.csv"
$PrivacyPolicyVer = "v1.0 (2026-11-25)"

$Direccion = "localhost"
$Puerto    = 5000

# CORRECCIÓN H-04: la aplicacion escucha HTTP local; el proxy IIS/nginx termina TLS.
# Si el proxy envia X-Forwarded-Proto, se fuerza HTTPS. En produccion poner $ExigirHttps = $true.
$ExigirHttps      = $false
$ProxyProtoHeader = "X-Forwarded-Proto"

$SessionTimeoutMin   = 30
$MaxBodyBytes        = 65536
$IteracionesPbkdf2   = 600000
$CookieSesion        = "kuxtal_sid"

# CORRECCIÓN H-02: RBAC según matriz de roles (R-01 Paciente, R-02 Admisión, R-03 TI, R-04 DPO, R-05 Médico, R-06 Facturación).
# Para promover una cuenta, agregar su correo a la tabla.
$RolesAdmin = @("R-02", "R-03", "R-04", "R-05", "R-06")
$RolesAuditoria = @("R-03", "R-04")
# CORRECCIÓN H-02/C-13: verificación en dos pasos (TOTP) obligatoria para las cuentas privilegiadas
# DPO (R-04), TI/administración (R-03) y Admisión (R-02), conforme al Anexo A.5 del aviso de privacidad.
$RolesConMfa = @("R-02", "R-03", "R-04")
$RolesPorEmail = @{
    "admin@kuxtal.test"       = "R-03"
    "dpo@kuxtal.test"         = "R-04"
    "admision@kuxtal.test"    = "R-02"
    "medico@kuxtal.test"      = "R-05"
    "facturacion@kuxtal.test" = "R-06"
    "rmedinal@kuxtal.example" = "R-02"
    "meuanp@kuxtal.example"   = "R-05"
    "vherrerap@kuxtal.example" = "R-06"
}

$EncabezadoUsuarios = "Id,Nombre,Email,PasswordHash,FechaNacimiento,Telefono,Jurisdiccion,AseguradoraPoliza,MotivoAlergias,Consentimiento,FechaConsentimiento,VersionAviso,FechaRegistro,TotpSecret,TotpActivado"
$EncabezadoAccesos  = "Fecha,Evento,Ruta,Exito,Nivel,IPAnonimizada"

# CORRECCIÓN H-07: selector jurisdiccional D-06.
$Jurisdicciones = [ordered]@{
    "México"                               = "LFPDPPP 2025"
    "Unión Europea (España, Alemania, etc.)" = "GDPR"
    "Estados Unidos - California"          = "CCPA"
    "Otro"                                 = "Estándar Internacional"
}

New-Item -ItemType Directory -Path $DataPath -Force | Out-Null

# ------------------------------------------------------------------------------
# 2. FUNCIONES DE SOPORTE: CRIPTOGRAFIA, CSV, HTML, SESIONES Y LOGS
# ------------------------------------------------------------------------------
function Ahora { (Get-Date -Format 'o') }

function New-RandomBytes([int]$cantidad) {
    $bytes = [byte[]]::new($cantidad)
    $generador = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generador.GetBytes($bytes) } finally { $generador.Dispose() }
    return $bytes
}

function Escapar([string]$texto) {
    if ($null -eq $texto) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$texto)
}

# CORRECCIÓN H-01: derivacion PBKDF2-SHA256 con sal aleatoria de 16 bytes.
# Formato exigido en users.csv: salt_base64:hash_base64 (hash de 32 bytes).
function Nuevo-HashContrasena([string]$contrasena) {
    $sal = New-RandomBytes 16
    $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        [System.Text.Encoding]::UTF8.GetBytes($contrasena),
        $sal,
        $IteracionesPbkdf2,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try { $hash = $derive.GetBytes(32) } finally { $derive.Dispose() }
    return "$([Convert]::ToBase64String($sal)):$([Convert]::ToBase64String($hash))"
}

# Comparacion en tiempo constante compatible con .NET Framework y .NET (PowerShell 7).
function Test-IgualdadTiempoConstante([byte[]]$a, [byte[]]$b) {
    if ($a.Length -ne $b.Length) { return $false }
    $diferencia = 0
    for ($i = 0; $i -lt $a.Length; $i++) { $diferencia = $diferencia -bor ($a[$i] -bxor $b[$i]) }
    return ($diferencia -eq 0)
}

function Probar-Contrasena([string]$contrasena, [string]$guardado) {
    if ([string]::IsNullOrWhiteSpace($guardado)) { return $false }
    $partes = $guardado -split ':', 2
    if ($partes.Count -ne 2) { return $false }
    try {
        $sal      = [Convert]::FromBase64String($partes[0])
        $esperado = [Convert]::FromBase64String($partes[1])
        if ($sal.Length -ne 16 -or $esperado.Length -ne 32) { return $false }
        $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            [System.Text.Encoding]::UTF8.GetBytes($contrasena),
            $sal,
            $IteracionesPbkdf2,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        try { $calculado = $derive.GetBytes($esperado.Length) } finally { $derive.Dispose() }
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            return [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($calculado, $esperado)
        }
        return Test-IgualdadTiempoConstante $calculado $esperado
    } catch { return $false }
}

# ------------------------------------------------------------------------------
# 2-bis. VERIFICACIÓN EN DOS PASOS (TOTP, RFC 6238 / RFC 4226) - compatible con Google Authenticator.
# Solo se exige a las cuentas privilegiadas (R-02 Admisión, R-03 TI, R-04 DPO). Ver $RolesConMfa.
# ------------------------------------------------------------------------------
$script:Base32Alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

function ConvertTo-Base32([byte[]]$bytes) {
    $resultado = [System.Text.StringBuilder]::new()
    $buffer = 0
    $bitsEnBuffer = 0
    foreach ($b in $bytes) {
        $buffer = ($buffer -shl 8) -bor $b
        $bitsEnBuffer += 8
        while ($bitsEnBuffer -ge 5) {
            $bitsEnBuffer -= 5
            $indice = ($buffer -shr $bitsEnBuffer) -band 0x1F
            [void]$resultado.Append($script:Base32Alfabeto[$indice])
        }
    }
    if ($bitsEnBuffer -gt 0) {
        $indice = ($buffer -shl (5 - $bitsEnBuffer)) -band 0x1F
        [void]$resultado.Append($script:Base32Alfabeto[$indice])
    }
    return $resultado.ToString()
}

function ConvertFrom-Base32([string]$base32) {
    $limpio = $base32.ToUpperInvariant() -replace '[^A-Z2-7]', ''
    $bytesLista = [System.Collections.Generic.List[byte]]::new()
    $buffer = 0
    $bitsEnBuffer = 0
    foreach ($c in $limpio.ToCharArray()) {
        $indice = $script:Base32Alfabeto.IndexOf($c)
        if ($indice -lt 0) { continue }
        $buffer = ($buffer -shl 5) -bor $indice
        $bitsEnBuffer += 5
        if ($bitsEnBuffer -ge 8) {
            $bitsEnBuffer -= 8
            $bytesLista.Add([byte](($buffer -shr $bitsEnBuffer) -band 0xFF))
        }
    }
    return $bytesLista.ToArray()
}

# Secreto compartido de 160 bits (20 bytes), tamaño recomendado por RFC 4226.
function Nueva-TotpSecret {
    return ConvertTo-Base32 (New-RandomBytes 20)
}

function Get-CodigoTotp([string]$secretoBase32, [int64]$pasoUnix) {
    $clave = ConvertFrom-Base32 $secretoBase32
    $contadorBytes = [BitConverter]::GetBytes([int64]$pasoUnix)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($contadorBytes) }
    $hmac = [System.Security.Cryptography.HMACSHA1]::new($clave)
    try { $hash = $hmac.ComputeHash($contadorBytes) } finally { $hmac.Dispose() }
    $offset = $hash[$hash.Length - 1] -band 0x0F
    $binario = (([int]($hash[$offset] -band 0x7F)) -shl 24) -bor
               (([int]$hash[$offset + 1]) -shl 16) -bor
               (([int]$hash[$offset + 2]) -shl 8) -bor
               ([int]$hash[$offset + 3])
    $codigo = $binario % 1000000
    return $codigo.ToString("D6")
}

# Acepta el paso de 30s actual y el anterior/siguiente, para tolerar un pequeño desfase de reloj.
function Test-CodigoTotp([string]$secretoBase32, [string]$codigoIngresado) {
    if ([string]::IsNullOrWhiteSpace($secretoBase32)) { return $false }
    if ([string]::IsNullOrWhiteSpace($codigoIngresado)) { return $false }
    $codigoLimpio = $codigoIngresado -replace '\s', ''
    if ($codigoLimpio -notmatch '^\d{6}$') { return $false }
    $pasoActual = [int64][Math]::Floor(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) / 30)
    foreach ($delta in -1, 0, 1) {
        $esperado = Get-CodigoTotp $secretoBase32 ($pasoActual + $delta)
        $a = [System.Text.Encoding]::UTF8.GetBytes($esperado)
        $b = [System.Text.Encoding]::UTF8.GetBytes($codigoLimpio)
        if (Test-IgualdadTiempoConstante $a $b) { return $true }
    }
    return $false
}

# CORRECCIÓN H-06: hash SHA-256 de integridad de los CSV (consumible por verify.ps1 de TI).
function Get-FileSha256([string]$ruta) {
    if (-not (Test-Path -LiteralPath $ruta)) { return "NO_DISPONIBLE" }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.IO.File]::ReadAllBytes($ruta))
        return ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

# CORRECCIÓN H-06: ACL restrictiva en reposo (solo SYSTEM, Administradores y el usuario del servicio).
# Se conserva el formato CSV UTF-8 exigido por la especificacion.
function Set-ProteccionArchivo([string]$ruta) {
    try {
        $acl = Get-Acl -LiteralPath $ruta
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($regla in @($acl.Access)) { $acl.RemoveAccessRule($regla) | Out-Null }
        $identidades = @(
            [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18"),
            [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544"),
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        )
        foreach ($id in $identidades) {
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($id, "FullControl", "Allow"))
        }
        Set-Acl -LiteralPath $ruta -AclObject $acl
    } catch { }
}

function Inicializar-Csv {
    if (-not (Test-Path -LiteralPath $UsersCsv)) {
        Set-Content -LiteralPath $UsersCsv -Value $EncabezadoUsuarios -Encoding utf8
    }
    if (-not (Test-Path -LiteralPath $AccessLogCsv)) {
        Set-Content -LiteralPath $AccessLogCsv -Value $EncabezadoAccesos -Encoding utf8
    }
    Migrar-ColumnasUsuarios
    Set-ProteccionArchivo $UsersCsv
    Set-ProteccionArchivo $AccessLogCsv
}

# Agrega TotpSecret/TotpActivado a un users.csv creado antes de la verificación en dos pasos.
function Migrar-ColumnasUsuarios {
    $primeraLinea = Get-Content -LiteralPath $UsersCsv -TotalCount 1 -Encoding utf8
    if ($primeraLinea -eq $EncabezadoUsuarios) { return }
    $filas = @(Import-Csv -LiteralPath $UsersCsv -Encoding utf8)
    $migradas = @(foreach ($f in $filas) {
        [pscustomobject][ordered]@{
            Id                  = $f.Id
            Nombre              = $f.Nombre
            Email               = $f.Email
            PasswordHash        = $f.PasswordHash
            FechaNacimiento     = $f.FechaNacimiento
            Telefono            = $f.Telefono
            Jurisdiccion        = $f.Jurisdiccion
            AseguradoraPoliza   = $f.AseguradoraPoliza
            MotivoAlergias      = $f.MotivoAlergias
            Consentimiento      = $f.Consentimiento
            FechaConsentimiento = $f.FechaConsentimiento
            VersionAviso        = $f.VersionAviso
            FechaRegistro       = $f.FechaRegistro
            TotpSecret          = if ($f.PSObject.Properties['TotpSecret']) { $f.TotpSecret } else { "" }
            TotpActivado        = if ($f.PSObject.Properties['TotpActivado']) { $f.TotpActivado } else { "False" }
        }
    })
    Escribir-Csv $UsersCsv $EncabezadoUsuarios $migradas
}

function Leer-Csv([string]$ruta) {
    if (-not (Test-Path -LiteralPath $ruta)) { return @() }
    return @(Import-Csv -LiteralPath $ruta -Encoding utf8)
}

function Agregar-Csv([string]$ruta, $registro) {
    [pscustomobject]$registro | Export-Csv -LiteralPath $ruta -Append -NoTypeInformation -Encoding utf8
    Set-ProteccionArchivo $ruta
}

function Escribir-Csv([string]$ruta, [string]$encabezado, [array]$registros) {
    $lineas = @($encabezado)
    if ($registros.Count -gt 0) {
        $convertido = @($registros | ConvertTo-Csv -NoTypeInformation)
        $lineas += $convertido[1..($convertido.Count - 1)]
    }
    Set-Content -LiteralPath $ruta -Value $lineas -Encoding utf8
    Set-ProteccionArchivo $ruta
}

# CORRECCIÓN H-05: la IP se anonimiza (ultimo octeto /64 en IPv6) y nunca se guarda el User-Agent.
function Get-IpAnonimizada($ctx) {
    $ip = $ctx.Request.RemoteEndPoint.Address.ToString()
    if ($ip -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$') {
        return "$($Matches[1]).$($Matches[2]).$($Matches[3]).x"
    }
    if ($ip -like '*:*') {
        $grupos = $ip -split ':'
        $hasta = [Math]::Min(3, $grupos.Count - 1)
        return "$(($grupos[0..$hasta] -join ':'))::/64"
    }
    return "RED_ANONIMIZADA"
}

$Sesiones = @{}
$MetadatosAutorizados = @{}

# Verificaciones en dos pasos pendientes (login con contraseña correcta, falta el código TOTP).
$PendientesMfa = @{}
$MfaTimeoutMin = 5

function Nueva-PendienteMfa([string]$email, [string]$rol, [bool]$metadatos, [string]$secreto, [bool]$esNuevo) {
    $token = [Convert]::ToBase64String((New-RandomBytes 24))
    $PendientesMfa[$token] = [pscustomobject]@{
        Email     = $email
        Rol       = $rol
        Metadatos = $metadatos
        Secreto   = $secreto
        EsNuevo   = $esNuevo
        Intentos  = 0
        Expira    = (Get-Date).AddMinutes($MfaTimeoutMin)
    }
    return $token
}

function Get-PendienteMfa([string]$token) {
    if (-not $token -or -not $PendientesMfa.ContainsKey($token)) { return $null }
    $p = $PendientesMfa[$token]
    if ([datetime]$p.Expira -lt (Get-Date)) { $PendientesMfa.Remove($token) | Out-Null; return $null }
    return $p
}

function Get-TokenSesion($ctx) {
    $cabecera = $ctx.Request.Headers["Cookie"]
    if (-not $cabecera) { return $null }
    foreach ($parte in ($cabecera -split ';')) {
        $kv = $parte.Trim() -split '=', 2
        if ($kv.Count -eq 2 -and $kv[0] -eq $CookieSesion) { return $kv[1] }
    }
    return $null
}

function Get-SesionActual($ctx) {
    $token = Get-TokenSesion $ctx
    if (-not $token -or -not $Sesiones.ContainsKey($token)) { return $null }
    $sesion = $Sesiones[$token]
    if ([datetime]$sesion.Expira -lt (Get-Date)) { $Sesiones.Remove($token) | Out-Null; return $null }
    $sesion.Expira = (Get-Date).AddMinutes($SessionTimeoutMin)
    return $sesion
}

function Get-Rol([string]$email) {
    if ($RolesPorEmail.Contains($email)) { return $RolesPorEmail[$email] }
    return "R-01"
}

# CORRECCIÓN H-04: cookies HttpOnly + SameSite=Strict y Secure cuando hay TLS.
function Test-EsSeguro($ctx) {
    if ($ctx.Request.IsSecureConnection) { return $true }
    $proto = $ctx.Request.Headers[$ProxyProtoHeader]
    if ($proto -and ($proto -split ',')[0].Trim() -ieq "https") { return $true }
    return $false
}

function Set-Header($ctx, [string]$nombre, [string]$valor) {
    try { $ctx.Response.Headers[$nombre] = $valor } catch { }
}

function Nueva-Sesion($ctx, [string]$email, [string]$rol, [bool]$metadatos) {
    $token = [Convert]::ToBase64String((New-RandomBytes 32))
    $Sesiones[$token] = [pscustomobject]@{
        Email    = $email
        Rol      = $rol
        Metadatos = $metadatos
        Creada   = Get-Date
        Expira   = (Get-Date).AddMinutes($SessionTimeoutMin)
    }
    $seguro = if (Test-EsSeguro $ctx) { "; Secure" } else { "" }
    Set-Header $ctx "Set-Cookie" "$CookieSesion=$token; Path=/; HttpOnly; SameSite=Strict$seguro"
    return $token
}

function Cerrar-Sesion($ctx) {
    $token = Get-TokenSesion $ctx
    if ($token) { $Sesiones.Remove($token) | Out-Null }
    $seguro = if (Test-EsSeguro $ctx) { "; Secure" } else { "" }
    Set-Header $ctx "Set-Cookie" "$CookieSesion=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict$seguro"
}

# CORRECCIÓN H-03: bitacora estructurada SOLO con eventos operativos, sin PII.
function Registrar-Evento($ctx, [string]$evento, [string]$ruta, [bool]$exito, [string]$nivel = "INFO", [bool]$metadatos = $false) {
    $sesion = Get-SesionActual $ctx
    if ($sesion) { $metadatos = [bool]$sesion.Metadatos }
    $ip = if ($metadatos) { Get-IpAnonimizada $ctx } else { "NO_REGISTRADA" }
    Agregar-Csv $AccessLogCsv ([ordered]@{
        Fecha         = Ahora
        Evento        = $evento
        Ruta          = $ruta
        Exito         = [int]$exito
        Nivel         = $nivel
        IPAnonimizada = $ip
    })
}

function Get-EmailEnmascarado([string]$email) {
    $i = $email.IndexOf('@')
    if ($i -le 0) { return "***" }
    return "$($email.Substring(0, 1))***$($email.Substring($i))"
}

function Get-TelefonoEnmascarado([string]$telefono) {
    if ($telefono.Length -le 4) { return "****" }
    return "****-**$($telefono.Substring($telefono.Length - 4))"
}

function Get-PolizaEnmascarada([string]$poliza) {
    $digitos = ($poliza -replace '\D', '')
    $final = if ($digitos.Length -ge 4) { $digitos.Substring($digitos.Length - 4) } else { "****" }
    return "POL-***-$final"
}

$script:CspNonce = $null
function Nuevo-Nonce {
    if (-not $script:CspNonce) {
        $script:CspNonce = [Convert]::ToBase64String((New-RandomBytes 16))
    }
    return $script:CspNonce
}

# CORRECCIÓN H-04: cabeceras de transporte/seguridad para reverse proxy HTTPS.
function Set-CabecerasSeguras($ctx) {
    if (-not $script:CspNonce) { Nuevo-Nonce | Out-Null }
    $nonce = $script:CspNonce
    Set-Header $ctx "X-Content-Type-Options" "nosniff"
    Set-Header $ctx "X-Frame-Options" "DENY"
    Set-Header $ctx "Referrer-Policy" "no-referrer"
    Set-Header $ctx "Cache-Control" "no-store"
    Set-Header $ctx "Content-Security-Policy" "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-$nonce'"
    if (Test-EsSeguro $ctx) {
        Set-Header $ctx "Strict-Transport-Security" "max-age=31536000; includeSubDomains"
    }
}

function Enviar($ctx, [string]$html, [int]$codigo = 200) {
    if (-not $script:CspNonce) { Nuevo-Nonce | Out-Null }
    Set-CabecerasSeguras $ctx
    $ctx.Response.StatusCode = $codigo
    $ctx.Response.ContentType = "text/html; charset=utf-8"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
    $ctx.Response.ContentLength64 = $bytes.Length
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.Close()
    $script:CspNonce = $null
}

function Enviar-Archivo($ctx, [byte[]]$bytes, [string]$nombreArchivo) {
    if (-not $script:CspNonce) { Nuevo-Nonce | Out-Null }
    Set-CabecerasSeguras $ctx
    Set-Header $ctx "Content-Disposition" "attachment; filename=$nombreArchivo"
    $ctx.Response.StatusCode = 200
    $ctx.Response.ContentType = "text/csv; charset=utf-8"
    $ctx.Response.ContentLength64 = $bytes.Length
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.Close()
    $script:CspNonce = $null
}

# Iconos del diseño: PNG incrustados en Base64 para conservar la arquitectura de un solo archivo.
function Enviar-Imagen($ctx, [byte[]]$bytes) {
    if (-not $script:CspNonce) { Nuevo-Nonce | Out-Null }
    Set-CabecerasSeguras $ctx
    $ctx.Response.StatusCode = 200
    $ctx.Response.ContentType = "image/png"
    Set-Header $ctx "Cache-Control" "public, max-age=86400"
    $ctx.Response.ContentLength64 = $bytes.Length
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.Close()
    $script:CspNonce = $null
}

function Redirigir($ctx, [string]$destino, [int]$codigo = 302) {
    try { $ctx.Response.RedirectLocation = $destino } catch { }
    $html = "<!doctype html><html><body><a href='$(Escapar $destino)'>Continuar</a></body></html>"
    Enviar $ctx $html $codigo
}

function Leer-Formulario($ctx, [int]$limite = $MaxBodyBytes) {
    $memoria = [System.IO.MemoryStream]::new()
    $buffer = [byte[]]::new(4096)
    $total = 0
    try {
        while (($leidos = $ctx.Request.InputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $leidos
            if ($total -gt $limite) { throw "Cuerpo de peticion fuera de limite" }
            $memoria.Write($buffer, 0, $leidos)
        }
        $cuerpo = [System.Text.Encoding]::UTF8.GetString($memoria.ToArray())
    } finally { $memoria.Dispose() }

    $datos = @{}
    foreach ($par in ($cuerpo -split '&')) {
        if (-not $par) { continue }
        $partes = $par -split '=', 2
        $clave = [System.Net.WebUtility]::UrlDecode($partes[0])
        $valor = if ($partes.Count -gt 1) { [System.Net.WebUtility]::UrlDecode($partes[1]) } else { "" }
        $datos[$clave] = $valor.Trim()
    }
    return $datos
}

function Tabla-Html([array]$filas, [string[]]$columnas = $null) {
    if ($filas.Count -eq 0) { return "<p>Sin registros.</p>" }
    if (-not $columnas) { $columnas = @($filas[0].PSObject.Properties.Name) }
    $html = "<div class='tabla-scroll'><table><thead><tr>"
    foreach ($columna in $columnas) { $html += "<th>$(Escapar $columna)</th>" }
    $html += "</tr></thead><tbody>"
    foreach ($fila in $filas) {
        $html += "<tr>"
        foreach ($columna in $columnas) {
            $valor = $fila.PSObject.Properties[$columna]
            $texto = if ($valor) { [string]$valor.Value } else { "" }
            $html += "<td>$(Escapar $texto)</td>"
        }
        $html += "</tr>"
    }
    return "$html</tbody></table></div>"
}

$css = @'
<style>
:root{
  color-scheme:light;
  --maroon:#7a1537; --maroon-dark:#4a0e22; --maroon-darker:#33081790;
  --teal:#149a92; --teal-dark:#0d756f;
  --bg:#f3f1f2; --surface:#ffffff; --surface-alt:#f6f7f8;
  --border:#e1dee0;
  --text:#262223; --text-muted:#6b6467;
  --ok:#116b2a; --ok-bg:#e8f7ec; --ok-border:#8fd4a4;
  --err:#a11212; --err-bg:#fdecec; --err-border:#f1b3b3;
  --warn:#8a5a00; --warn-bg:#fff6e5; --warn-border:#f0cf8a;
  --radius:10px; --shadow:0 2px 10px rgba(0,0,0,.08);
}
*{box-sizing:border-box}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  margin:0;color:var(--text);line-height:1.55;font-size:15.5px;background:var(--bg);min-height:100vh;
}
.bar-inner{max-width:1120px;margin:0 auto;padding:0 24px}
header.topbar{background:var(--maroon);color:#fff;box-shadow:0 1px 0 rgba(0,0,0,.08)}
header.topbar .bar-inner{display:flex;align-items:center;gap:14px;padding:14px 24px}
.brand-mark{
  width:40px;height:40px;border-radius:50%;object-fit:cover;flex-shrink:0;
  border:2px solid rgba(255,255,255,.55);background:#fff;
}
.brand-text h1{margin:0;font-size:20px;font-weight:800;line-height:1.25;letter-spacing:.2px}
.subbar{background:var(--maroon-dark);border-bottom:3px solid var(--teal)}
.subbar .bar-inner{display:flex;align-items:center;justify-content:flex-end;flex-wrap:wrap;gap:4px;padding:0 24px}
nav{display:flex;flex-wrap:wrap;align-items:center;gap:2px;padding:4px 0}
nav a,nav button{
  font-size:13.5px;font-weight:600;color:#fff;text-decoration:none;position:relative;
  padding:11px 13px;border-radius:0;background:transparent;border:0;cursor:pointer;font-family:inherit;
}
nav a::after{content:'';position:absolute;left:13px;right:13px;bottom:0;height:3px;background:var(--teal);transform:scaleX(0);transition:transform .15s ease}
nav a:hover,nav a:focus-visible{background:rgba(255,255,255,.1);outline:none}
nav a:hover::after,nav a:focus-visible::after{transform:scaleX(1)}
nav button:hover,nav button:focus-visible{background:rgba(255,255,255,.1);outline:none}
nav form{display:flex;margin:0}
.breadcrumb{background:var(--surface);border-bottom:1px solid var(--border)}
.breadcrumb .bar-inner{padding:10px 24px;font-size:13px;color:var(--text-muted)}
.breadcrumb a{color:var(--maroon-dark);font-weight:700;text-decoration:none}
.breadcrumb a:hover{text-decoration:underline}
.breadcrumb .sep{margin:0 6px;color:#b8b3b5}
.bc-home{width:14px;height:14px;vertical-align:-2px;margin-right:2px}
main{max-width:1120px;margin:0 auto;background:var(--surface);padding:30px 24px 28px}
main>h2{margin-top:0;font-size:24px;font-weight:800;color:var(--text);padding-bottom:14px;position:relative;letter-spacing:.1px}
main>h2::after{content:'';display:block;width:64px;height:4px;background:var(--teal);border-radius:2px;margin-top:12px}
section h2{color:var(--maroon-dark);font-size:19px;font-weight:800;margin:24px 0 12px}
h3{color:var(--maroon-dark);font-size:16.5px;font-weight:700;margin:24px 0 10px}
h4{color:var(--text);font-size:14.5px;margin:16px 0 8px}
hr{border:0;border-top:1px solid var(--border);margin:26px 0}
a{color:var(--teal-dark)}
main a{color:var(--teal-dark);font-weight:600;text-decoration:none}
main a:hover{text-decoration:underline}
.hero{
  background:linear-gradient(120deg,var(--maroon) 0%,var(--maroon-dark) 100%);color:#fff;
  border-radius:16px;padding:26px 30px;margin:4px 0 24px;box-shadow:var(--shadow);
}
.hero h3{color:#fff;font-size:22px;margin:0 0 8px}
.hero p{margin:0;opacity:.95;max-width:640px}
.card-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin:18px 0 24px}
.card-grid a{
  display:block;background:var(--surface-alt);border:1px solid var(--border);border-radius:12px;
  padding:18px 16px;text-align:center;font-weight:700;color:var(--maroon-dark)!important;
  text-decoration:none!important;transition:transform .12s ease,box-shadow .12s ease,border-color .12s ease;
}
.card-grid a:hover{transform:translateY(-2px);box-shadow:var(--shadow);border-color:var(--teal)}
.card-grid img{display:block;width:40px;height:40px;margin:0 auto 10px;object-fit:contain}
label{display:block;margin:14px 0 4px;font-weight:600;font-size:13.5px;color:var(--text)}
input,select,textarea{
  display:block;width:100%;max-width:480px;padding:10px 12px;margin-top:5px;
  border:1.5px solid var(--border);border-radius:7px;font:inherit;color:var(--text);
  background:var(--surface);transition:border-color .15s ease,box-shadow .15s ease;
}
input:focus,select:focus,textarea:focus{
  outline:none;border-color:var(--teal);box-shadow:0 0 0 3px rgba(20,154,146,.18);
}
textarea{min-height:92px;max-width:640px;resize:vertical}
input[type=checkbox],input[type=radio]{
  display:inline-block;width:auto;max-width:none;flex-shrink:0;margin:3px 0 0;accent-color:var(--maroon);
}
label:has(> input[type=checkbox]),label:has(> input[type=radio]){
  display:flex;align-items:flex-start;gap:10px;font-weight:500;
  background:var(--surface-alt);padding:12px 14px;border-radius:9px;max-width:640px;border:1px solid var(--border);
}
button,input[type=submit]{
  padding:10px 20px;background:var(--teal);color:#fff;border:0;border-radius:6px;cursor:pointer;
  font:inherit;font-weight:700;font-size:14px;letter-spacing:.2px;transition:background .12s ease,transform .12s ease;
}
button:hover,input[type=submit]:hover{background:var(--teal-dark);transform:translateY(-1px)}
button:active,input[type=submit]:active{transform:translateY(0)}
button:focus-visible{outline:2px solid var(--maroon);outline-offset:2px}
.aviso,.ccpa,.err,.ok{border-radius:9px;padding:13px 16px;margin:16px 0;font-size:14px}
.aviso{background:var(--surface-alt);border:1px solid var(--border);border-left:4px solid var(--teal);color:var(--text)}
.aviso::before{content:'\2139 ';font-weight:700;color:var(--teal-dark)}
.ccpa{background:var(--warn-bg);border:1px solid var(--warn-border);border-left:4px solid var(--warn);color:var(--warn)}
.ccpa::before{content:'\26A0 ';font-weight:700}
.err{background:var(--err-bg);border:1px solid var(--err-border);border-left:4px solid var(--err);color:var(--err);font-weight:600}
.err::before{content:'\2715 ';font-weight:700}
.ok{background:var(--ok-bg);border:1px solid var(--ok-border);border-left:4px solid var(--ok);color:var(--ok);font-weight:600}
.ok::before{content:'\2713 ';font-weight:700}
.tabla-scroll{overflow-x:auto;margin:12px 0;border-radius:9px;border:1px solid var(--border);-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{border-bottom:1px solid var(--border);padding:9px 11px;text-align:left;vertical-align:top;white-space:nowrap}
th{background:var(--maroon-dark);color:#fff;font-weight:600;font-size:12.5px;text-transform:uppercase;letter-spacing:.3px}
tbody tr:nth-child(even){background:var(--surface-alt)}
tbody tr:hover{background:#f0eceb}
tbody td:first-child{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;color:var(--text-muted)}
code{word-break:break-all;background:var(--surface-alt);padding:2px 6px;border-radius:5px;font-size:.9em;color:var(--maroon-dark)}
footer{color:var(--text-muted);font-size:12px;margin-top:30px;padding-top:16px;border-top:1px solid var(--border)}
section#arco{margin-top:4px}
@media (max-width:640px){
  header.topbar .bar-inner,.subbar .bar-inner,.breadcrumb .bar-inner{padding-left:16px;padding-right:16px}
  main{margin:0;padding:18px 16px}
  input,select,textarea,label:has(> input[type=checkbox]),label:has(> input[type=radio]){max-width:100%}
  .hero{padding:20px}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
'@

function Nueva-Pagina([string]$titulo, [string]$contenido, $ctx = $null) {
    $nonce = Nuevo-Nonce
    $nav = "<a href='/'>Inicio</a><a href='/registro'>Registro</a><a href='/login'>Iniciar sesión</a>"
    $sesion = if ($ctx) { Get-SesionActual $ctx } else { $null }
    if ($sesion -and $sesion.Rol -in $RolesAdmin) { $nav += "<a href='/admin'>Administración</a>" }
    if ($sesion) {
        $nav += "<a href='/mi-cuenta'>Mi cuenta</a><a href='/ajustes'>Ajustes</a>"
        $nav += "<form method='post' action='/logout' style='display:inline'><button type='submit' style='margin:0;padding:4px 9px'>Cerrar sesión ($(Escapar $sesion.Rol))</button></form>"
    }
    $nombre = Escapar $CompanyName
    $tituloEscapado = Escapar $titulo
    $iconoInicio = "<img src='/assets/home.png' class='bc-home' alt='' aria-hidden='true'>"
    $miga = if ($titulo -eq "Inicio") {
        "<a href='/'>$iconoInicio Inicio</a>"
    } else {
        "<a href='/'>$iconoInicio Inicio</a><span class='sep'>&rsaquo;</span><span>$tituloEscapado</span>"
    }
    return @"
<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>$tituloEscapado - $nombre</title>$css</head><body>
<header class='topbar'><div class='bar-inner'><img src='/assets/cruz.png' class='brand-mark' alt='' aria-hidden='true'><div class='brand-text'><h1>$nombre</h1></div></div></header>
<div class='subbar'><div class='bar-inner'><nav>$nav</nav></div></div>
<div class='breadcrumb'><div class='bar-inner'>$miga</div></div>
<main><h2>$tituloEscapado</h2>$contenido
<footer>Información ficticia para fines de demostración. Aviso de privacidad: $(Escapar $PrivacyPolicyVer).</footer></main></body></html>
"@
}

function Formulario-Login([string]$mensaje = "") {
    $alerta = if ($mensaje) { "<p class='err'>$(Escapar $mensaje)</p>" } else { "" }
    return @"
$alerta<form method='post' action='/login'>
<label>Correo electrónico <input type='email' name='email' required autocomplete='username'></label>
<label>Contraseña <input type='password' name='password' required autocomplete='current-password'></label>
<button type='submit'>Entrar</button></form>
<p>¿Aún no tienes cuenta? <a href='/registro'>Regístrate aquí</a>.</p>
"@
}

# CORRECCIÓN H-02/C-13: segundo factor (TOTP) para R-02, R-03 y R-04. $esNuevo=true la primera vez
# que esa cuenta inicia sesión (todavía no tiene secreto guardado): hay que enrolarla primero.
function Formulario-Mfa([string]$token, [bool]$esNuevo, [string]$secreto = "", [string]$mensaje = "") {
    $alerta = if ($mensaje) { "<p class='err'>$(Escapar $mensaje)</p>" } else { "" }
    $intro = if ($esNuevo) {
        "<div class='aviso'><strong>Esta cuenta requiere verificación en dos pasos.</strong> " +
        "Abre tu app de autenticación (Google Authenticator u otra compatible con TOTP), elige " +
        "<em>Agregar cuenta &rarr; Ingresar una clave de configuración</em> y captura:</div>" +
        "<p>Cuenta: <code>$(Escapar $CompanyName)</code><br>Clave secreta: <code>$(Escapar $secreto)</code></p>" +
        "<p>Después escribe aquí el código de 6 dígitos que te muestra la app, para confirmar que quedó " +
        "bien sincronizada y activar la verificación en dos pasos de tu cuenta.</p>"
    } else {
        "<p>Escribe el código de 6 dígitos de tu app de autenticación.</p>"
    }
    return @"
$alerta$intro
<form method='post' action='/login-verificar'>
<input type='hidden' name='token' value='$(Escapar $token)'>
<label>Código de verificación <input type='text' name='codigo' inputmode='numeric' pattern='[0-9]{6}' maxlength='6' autocomplete='one-time-code' required autofocus></label>
<button type='submit'>Verificar</button></form>
"@
}

function Seccion-Arco($usuario, [string]$email) {
    if ($null -eq $usuario) {
        return "<hr><section id='arco'><h3>Derechos ARCO</h3><p>Tu cuenta no tiene un registro de paciente asociado en <code>users.csv</code>.</p></section>"
    }
    return @"
<hr><section id='arco'>
<h3>Derechos ARCO (Rectificación, Cancelación y Oposición)</h3>
<p>Ejerce tus derechos <strong>ARCO</strong> (LFPDPPP 2025 / GDPR / CCPA) sobre tu cuenta autenticada. Para consultar tus datos completos ve a <a href='/mi-cuenta'>Mi cuenta</a>.</p>
<h4>Rectificación de datos</h4>
<form method='post' action='/ajustes'>
<input type='hidden' name='email' value='$(Escapar $email)'>
<label>Nombre completo <input type='text' name='nombre' maxlength='120' value='$(Escapar $usuario.Nombre)' required></label>
<label>Teléfono <input type='tel' name='telefono' maxlength='20' value='$(Escapar $usuario.Telefono)' required></label>
<label>Aseguradora y póliza <input type='text' name='aseguradora_poliza' maxlength='200' value='$(Escapar $usuario.AseguradoraPoliza)' required></label>
<label>Motivo de consulta y alergias <textarea name='motivo_alergias' maxlength='1000' required>$(Escapar $usuario.MotivoAlergias)</textarea></label>
<button type='submit' name='accion' value='rectificar'>Guardar rectificación</button></form>
<h4>Cancelación u oposición</h4>
<p>Esta acción elimina tus datos de pre-registro de Data Hunt y cierra tu sesión.</p>
<form method='post' action='/ajustes'>
<label>Correo de la cuenta <input type='email' name='email' value='$(Escapar $email)' readonly></label>
<button type='submit' name='accion' value='cancelar'>Cancelar / oponerme al tratamiento y eliminar mis datos</button></form>
</section>
"@
}

function Formulario-Ajustes([string]$mensaje = "", [bool]$esError = $true, $usuario = $null, [string]$email = "") {
    $clase = if ($esError) { "err" } else { "ok" }
    $alerta = if ($mensaje) { "<p class='$clase'>$(Escapar $mensaje)</p>" } else { "" }
    $arco = if ($email) { Seccion-Arco $usuario $email } else { "" }
    return @"
$alerta<h3>Cambiar contraseña</h3>
<form method='post' action='/ajustes'>
<input type='hidden' name='accion' value='password'>
<label>Contraseña actual <input type='password' name='password_actual' required autocomplete='current-password' maxlength='128'></label>
<label>Nueva contraseña <input type='password' name='password_nueva' required autocomplete='new-password' minlength='8' maxlength='128'></label>
<label>Confirmar nueva contraseña <input type='password' name='password_confirmacion' required autocomplete='new-password' minlength='8' maxlength='128'></label>
<button type='submit'>Guardar contraseña</button></form>
<p>La nueva contraseña debe tener entre 8 y 128 caracteres y ser diferente de la actual. Al guardarla se cierran todas las sesiones de la cuenta.</p>
<p>Si tu cuenta aún no tiene contraseña, solicítala al administrador.</p>
$arco
"@
}

function Pagina-Privacidad {
    # CORRECCIÓN H-07: aviso integral, adaptado a las jurisdicciones de D-06 (LFPDPPP, GDPR, CCPA y HIPAA).
    $plantilla = @'
<h3>1. Identidad y domicilio del responsable</h3>
<p>{COMPANY}, persona moral con domicilio en Calle 21 No. 100, Col. Centro, C.P. 97000, Mérida, Yucatán, México, y unidad ambulatoria en Cancún, Quintana Roo. Área dueña del tratamiento: DEP-01 (Admisión y Atención al Paciente). Oficina de Protección de Datos Personales (DPO): <strong>{CONTACTO}</strong>. El CISO del hospital dirige la seguridad técnica y la respuesta a vulneraciones.</p>
<h3>2. Datos que recabamos</h3>
<p>Identificación y contacto (nombre, correo, fecha de nacimiento, teléfono), cuenta (contraseña, guardada solo como hash PBKDF2-SHA256 con sal), país o estado de residencia, motivo de consulta y alergias (<strong>dato sensible de salud</strong>, requiere tu consentimiento expreso), aseguradora y número de póliza (<strong>dato financiero</strong>, opcional y con consentimiento aparte), y datos de uso del portal (IP anonimizada, navegador, idioma, bitácora de accesos). También guardamos la fecha y la versión del aviso que aceptaste, como prueba de tu consentimiento.</p>
<h3>3. Finalidades y conservación</h3>
<p>Usamos tus datos para crear y proteger tu cuenta, identificarte clínicamente, preparar tu cita, determinar la ley de protección de datos que te aplica y, solo si lo autorizas, facturar a tu aseguradora. No los usamos para publicidad ni los vendemos. Los conservamos mientras tu cuenta esté activa; el expediente clínico se conserva al menos 5 años desde tu última atención (NOM-004-SSA3-2012); los datos de facturación, 10 años por obligaciones fiscales; la bitácora de accesos, 1 año; la IP, 90 días.</p>
<h3>4. Transferencias y encargados</h3>
<p>Encargados que tratan datos por nuestra cuenta, bajo contrato de confidencialidad: Amazon Web Services (copias cifradas de respaldo, posiblemente fuera de México), un laboratorio clínico externo y un proveedor de soporte de TI. Transferimos tu nombre, aseguradora y número de póliza a <strong>tu aseguradora</strong> únicamente si diste tu consentimiento, para gestionar el cobro de tu atención; si no lo autorizas, te facturamos directamente. Podemos comunicar datos sin tu consentimiento cuando lo exija una ley, una autoridad competente o tu propia atención médica bajo secreto profesional.</p>
<h3>5. Derechos ARCO y revocación</h3>
<p>Puedes acceder, rectificar, cancelar u oponerte al tratamiento (ARCO), así como revocar tu consentimiento o limitar su uso, desde <a href='/ajustes#arco'>el apartado de derechos ARCO en Ajustes</a> o escribiendo a {CONTACTO}. Respondemos en un máximo de 20 días hábiles y, si procede, lo hacemos efectivo en los 15 días siguientes; ambos plazos pueden ampliarse una vez por un periodo igual. El ejercicio de tus derechos es gratuito, salvo costos de reproducción o envío. Tu expediente clínico no puede cancelarse antes del plazo que fija la norma sanitaria (NOM-004-SSA3-2012); mientras tanto se bloquea y solo lo consulta personal autorizado.</p>
<h3>6. Menores de edad o personas con incapacidad</h3>
<p>Si el paciente es menor de 18 años o tiene una incapacidad legal, su madre, padre o tutor realiza el pre-registro, otorga los consentimientos y ejerce los derechos ARCO en su nombre, acreditando su identidad y su representación.</p>
<h3>7. GDPR (pacientes de la Unión Europea)</h3>
<p>Si resides en la UE también te aplica el Reglamento General de Protección de Datos. Base legal: tu consentimiento explícito, específico para el tratamiento en general (art. 6.1.a) y para los datos de salud (art. 9.2.a). Tienes derecho de acceso, rectificación, supresión, limitación, portabilidad y oposición, y a presentar una reclamación ante la autoridad de protección de datos de tu país. Tus datos pueden tratarse en México y almacenarse en servidores de AWS fuera de la UE, protegidos con cláusulas contractuales tipo. Respondemos en un mes, ampliable. El hospital cuenta con un representante designado en la UE conforme al art. 27 del GDPR.</p>
<h3>8. CCPA/CPRA (pacientes de California)</h3>
<p id='ccpa'>Si resides en California, tu información de salud está protegida por HIPAA (sección 9) y el resto de tu información personal por la CCPA. <strong>No vendemos ni compartimos</strong> tu información personal con fines de publicidad. Tienes derecho a saber qué información tenemos, eliminarla, corregirla, limitar el uso de tu información sensible y no sufrir discriminación por ejercerlos, escribiendo a {CONTACTO}. Respondemos en 45 días, ampliables otros 45. No vendemos ni compartimos información de menores de 16 años.</p>
<h3>9. HIPAA (pacientes de Estados Unidos)</h3>
<p>Si resides en Estados Unidos, el hospital es una entidad cubierta por la ley federal HIPAA porque factura electrónicamente a aseguradoras de ese país. Podemos usar y divulgar tu información para tu tratamiento, el pago de tu atención (por ejemplo a tu aseguradora) y las operaciones del hospital, sin necesitar tu autorización adicional; cualquier otro uso, como mercadotecnia, requiere tu autorización por escrito y puedes revocarla en cualquier momento. Puedes pedir restricciones sobre el uso de tu información, recibir comunicaciones confidenciales por otro medio, ver y recibir copia de tu expediente (respondemos en 30 días, ampliables 30 más), pedir que se corrija (60 días, ampliables 30 más) y recibir un informe de las divulgaciones que hicimos (60 días). Contacto del oficial de privacidad: {CONTACTO}. Si crees que violamos tus derechos, puedes presentar una queja ante nosotros o ante la Oficina de Derechos Civiles del Departamento de Salud y Servicios Humanos de EE. UU. (HHS), sin que haya represalias por hacerlo.</p>
<h3>10. Cómo protegemos tus datos</h3>
<p>Cifrado de los archivos con tus datos y verificación de su integridad; contraseñas con hash PBKDF2-SHA256 y sal, comparadas en tiempo constante; sesiones HttpOnly y SameSite=Strict; ACL restrictiva en los archivos; anonimización de IP; bitácora de eventos sin datos personales. El acceso es por roles, con el mínimo de permisos necesarios, y <strong>verificación en dos pasos obligatoria</strong> para las cuentas con más privilegios (Admisión, TI/Administración y la DPO). Si ocurre una vulneración que afecte de forma significativa tus derechos, te lo informaremos de inmediato.</p>
<h3>11. Cambios al aviso</h3>
<p>Cualquier cambio se publica en esta misma página con su número de versión y su fecha, y se solicita de nuevo el consentimiento cuando el cambio es sustantivo. Versión vigente: {VERSION}.</p>
'@
    return $plantilla.Replace('{COMPANY}', (Escapar $CompanyName)).Replace('{CONTACTO}', (Escapar "privacidad@kuxtal.test")).Replace('{VERSION}', (Escapar $PrivacyPolicyVer))
}

function Pagina-Error([string]$titulo, [string]$mensaje, $ctx) {
    return Nueva-Pagina $titulo "<p class='err'>$(Escapar $mensaje)</p><p><a href='/'>Volver al inicio</a></p>" $ctx
}

# ------------------------------------------------------------------------------
# 3. RUTAS
# ------------------------------------------------------------------------------
$Rutas = @{}

# Iconos del diseño (PNG en Base64, incrustados para conservar la arquitectura de un solo archivo).
$Assets = @{
    "/assets/cruz.png" = [Convert]::FromBase64String('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')
    "/assets/home.png" = [Convert]::FromBase64String('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')
    "/assets/login.png" = [Convert]::FromBase64String('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')
    "/assets/registro.png" = [Convert]::FromBase64String('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')
    "/assets/privacidad.png" = [Convert]::FromBase64String('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')
}
foreach ($rutaAsset in $Assets.Keys) {
    $Rutas[$rutaAsset] = {
        param($ctx)
        $rutaActual = $ctx.Request.Url.AbsolutePath.TrimEnd('/')
        Enviar-Imagen $ctx $Assets[$rutaActual]
    }
}

$Rutas["/"] = {
    param($ctx)
    $contenido = "<div class='hero'><h3>Bienvenido a $(Escapar $CompanyName)</h3><p>Consulta información relevante de tu atención y realiza tu pre-registro como paciente.</p></div>"
    $contenido += "<div class='card-grid'>"
    $contenido += "<a href='/registro'><img src='/assets/registro.png' alt='' aria-hidden='true'>Pre-registro</a>"
    $contenido += "<a href='/login'><img src='/assets/login.png' alt='' aria-hidden='true'>Iniciar sesión</a>"
    $contenido += "<a href='#aviso-privacidad'><img src='/assets/privacidad.png' alt='' aria-hidden='true'>Aviso de privacidad</a>"
    $contenido += "</div>"
    $contenido += "<hr><section id='aviso-privacidad'><h2>Aviso de privacidad integral</h2>$(Pagina-Privacidad)</section>"
    Enviar $ctx (Nueva-Pagina "Inicio" $contenido $ctx)
}

$Rutas["/registro"] = {
    param($ctx)

    if ($ctx.Request.HttpMethod -eq "GET") {
        $nonce = Nuevo-Nonce
        $html = "<p>Captura de datos para tu pre-registro. Todos los campos son necesarios para la atención.</p>"
        $html += "<form method='post' action='/registro'>"
        $html += "<label>D-01 Nombre completo <input type='text' name='nombre' maxlength='120' required></label>"
        $html += "<label>D-02 Correo electrónico <input type='email' name='email' maxlength='254' required></label>"
        $html += "<label>D-03 Contraseña <input type='password' name='password' minlength='8' maxlength='128' required autocomplete='new-password'></label>"
        $html += "<label>D-04 Fecha de nacimiento <input type='date' name='fecha_nacimiento' required></label>"
        $html += "<label>D-05 Teléfono <input type='tel' name='telefono' maxlength='20' required></label>"
        $html += "<label>D-06 País / Estado de residencia <select id='jurisdiccion' name='jurisdiccion' required><option value=''>Selecciona...</option>"
        foreach ($nombreJurisdiccion in $Jurisdicciones.Keys) {
            $html += "<option value='$(Escapar $nombreJurisdiccion)'>$(Escapar $nombreJurisdiccion) - $(Escapar $Jurisdicciones[$nombreJurisdiccion])</option>"
        }
        $html += "</select></label>"
        $html += "<label>D-07 Aseguradora y número de póliza <input type='text' name='aseguradora_poliza' maxlength='200' required></label>"
        $html += "<label>D-08 Motivo de consulta y alergias (dato sensible de salud) <textarea name='motivo_alergias' maxlength='1000' required></textarea></label>"

        # CORRECCIÓN H-07: resumen visible + enlace al aviso integral + checkbox obligatorio sin marcar.
        $html += "<div class='aviso'><strong>Aviso de privacidad simplificado.</strong> "
        $html += "Usamos tus datos para tu atención médica y la gestión de tu aseguradora; no los vendemos. "
        $html += "Puedes ejercer tus derechos ARCO y revocar tu consentimiento. "
        $html += "<a href='/#aviso-privacidad'>Consultar el aviso de privacidad integral (versión $(Escapar $PrivacyPolicyVer))</a>.</div>"
        $html += "<label><input type='checkbox' id='consent' name='consent' value='True' required> "
        $html += "D-13: Leí y acepto el aviso de privacidad y el tratamiento de mis datos, incluidos los de salud.</label>"

        # CORRECCIÓN H-05: metadatos no esenciales solo si el usuario lo autoriza expresamente.
        $html += "<label><input type='checkbox' id='metadata' name='metadata' value='True'> "
        $html += "D-14 (opcional): Autorizo registrar una IP anonimizada para detectar accesos no autorizados. "
        $html += "Si no marcas esta casilla no se registrará IP ni navegador.</label>"
        $html += "<button type='submit'>Crear pre-registro</button></form>"

        # CORRECCIÓN H-07: CCPA visible solo cuando se selecciona California (Estados Unidos - California).
        $html += "<div id='ccpa' class='ccpa' style='display:none'><strong>CCPA - California.</strong> "
        $html += "<a href='/#ccpa'>Do Not Sell My Personal Information</a> | "
        $html += "<a href='/ajustes#arco'>Solicitar eliminación de mis datos personales</a></div>"
        $html += "<script nonce='$nonce'>function actualizaJurisdiccion(){var s=document.getElementById('jurisdiccion');"
        $html += "var d=document.getElementById('ccpa');d.style.display=(s.value.indexOf('California')>=0)?'block':'none';}"
        $html += "document.getElementById('jurisdiccion').addEventListener('change',actualizaJurisdiccion);"
        $html += "actualizaJurisdiccion();</script>"

        Enviar $ctx (Nueva-Pagina "Pre-registro de pacientes" $html $ctx)
        return
    }

    if ($ctx.Request.HttpMethod -ne "POST") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Usa GET o POST en esta ruta." $ctx) 405
        return
    }

    # CORRECCIÓN H-03: la consola solo registra el evento operativo, nunca datos del paciente.
    Write-Host "[INFO] $(Ahora) POST /registro recibido (sin datos personales en consola)"

    $form = Leer-Formulario $ctx
    foreach ($clave in @($form.Keys)) { $form[$clave] = (($form[$clave] -replace '[\r\n]+', ' ')).Trim() }

    $requeridos = @("nombre", "email", "password", "fecha_nacimiento", "telefono", "jurisdiccion", "aseguradora_poliza", "motivo_alergias")
    $falla = $false
    $correoReservado = $false
    foreach ($campo in $requeridos) {
        if (-not $form.ContainsKey($campo) -or [string]::IsNullOrWhiteSpace($form[$campo])) { $falla = $true; break }
    }
    if (-not $falla -and $form["email"].Length -gt 254) { $falla = $true }
    if (-not $falla -and $form["email"] -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]{2,}$') { $falla = $true }
    if (-not $falla -and ($form["password"].Length -lt 8 -or $form["password"].Length -gt 128)) { $falla = $true }
    if (-not $falla -and $form["nombre"].Length -gt 120) { $falla = $true }
    if (-not $falla -and $form["telefono"] -notmatch '^[0-9+\-() ]{7,20}$') { $falla = $true }
    if (-not $falla -and $form["aseguradora_poliza"].Length -gt 200) { $falla = $true }
    if (-not $falla -and $form["motivo_alergias"].Length -gt 1000) { $falla = $true }
    if (-not $falla -and -not $Jurisdicciones.Contains($form["jurisdiccion"])) { $falla = $true }

    $fechaNac = [datetime]::MinValue
    if (-not $falla) {
        $formatoOk = [datetime]::TryParseExact($form["fecha_nacimiento"], "yyyy-MM-dd", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$fechaNac)
        if (-not $formatoOk -or $fechaNac -gt (Get-Date)) { $falla = $true }
    }

    # CORRECCIÓN H-07: sin consentimiento expreso no se persiste ningun dato.
    $consentido = $form.ContainsKey("consent") -and $form["consent"] -ieq "True"
    if (-not $falla -and -not $consentido) { $falla = $true }
    if (-not $falla) {
        $correoNormalizado = $form["email"].ToLowerInvariant()
        foreach ($correoRol in $RolesPorEmail.Keys) {
            if ($correoNormalizado -eq $correoRol.ToLowerInvariant()) { $correoReservado = $true; break }
        }
    }
    if (-not $falla -and $correoReservado) { $falla = $true }
    if (-not $falla -and @(Leer-Csv $UsersCsv | Where-Object { $_.Email -ieq $form["email"] }).Count -gt 0) { $falla = $true }

    if ($falla) {
        Registrar-Evento $ctx "REGISTRO_RECHAZADO" "/registro" $false "WARN"
        $mensajeFalla = if ($correoReservado) {
            "Ese correo pertenece a una cuenta predefinida; solicita la contraseña al administrador o usa otro correo."
        } else {
            "No se pudo completar el registro. Revisa los campos, el formato de fecha, el consentimiento y que el correo no esté ya registrado."
        }
        $html = "<p class='err'>$mensajeFalla</p>"
        $html += "<p><a href='/registro'>Volver al formulario</a></p>"
        Enviar $ctx (Nueva-Pagina "Registro no completado" $html $ctx) 400
        return
    }

    $autorizaMetadatos = $form.ContainsKey("metadata") -and $form["metadata"] -ieq "True"
    $registro = [ordered]@{
        Id                  = [guid]::NewGuid().ToString()
        Nombre              = $form["nombre"]
        Email               = $form["email"]
        # CORRECCIÓN H-01: nunca se escribe la contraseña en texto plano.
        PasswordHash        = Nuevo-HashContrasena $form["password"]
        FechaNacimiento     = $form["fecha_nacimiento"]
        Telefono            = $form["telefono"]
        Jurisdiccion        = $form["jurisdiccion"]
        AseguradoraPoliza   = $form["aseguradora_poliza"]
        MotivoAlergias      = $form["motivo_alergias"]
        Consentimiento      = "True"
        FechaConsentimiento = Ahora
        VersionAviso        = $PrivacyPolicyVer
        FechaRegistro       = Ahora
    }
    Agregar-Csv $UsersCsv $registro
    $MetadatosAutorizados[$form["email"].ToLowerInvariant()] = $autorizaMetadatos

    # CORRECCIÓN H-05: la bitacora no contiene correo, póliza, motivo ni User-Agent.
    Registrar-Evento $ctx "REGISTRO_OK" "/registro" $true "INFO" $autorizaMetadatos

    $html = "<p class='ok'>Pre-registro creado correctamente.</p>"
    $html += "<p>Jurisdicción declarada: $(Escapar $form['jurisdiccion']) - $(Escapar $Jurisdicciones[$form['jurisdiccion']]).</p>"
    if ($form["jurisdiccion"] -like "*California*") {
        # CORRECCIÓN H-07: recordatorio CCPA también en la confirmación del servidor.
        $html += "<div class='ccpa'><a href='/#ccpa'>Do Not Sell My Personal Information</a> | "
        $html += "<a href='/ajustes#arco'>Solicitar eliminación de mis datos personales</a></div>"
    }
    $html += "<p><a href='/login'>Iniciar sesión</a></p>"
    Enviar $ctx (Nueva-Pagina "Registro confirmado" $html $ctx)
}

$Rutas["/login"] = {
    param($ctx)

    if ($ctx.Request.HttpMethod -eq "GET") {
        Enviar $ctx (Nueva-Pagina "Iniciar sesión" (Formulario-Login) $ctx)
        return
    }
    if ($ctx.Request.HttpMethod -ne "POST") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Usa GET o POST en esta ruta." $ctx) 405
        return
    }

    $form = Leer-Formulario $ctx
    foreach ($clave in @($form.Keys)) { $form[$clave] = (($form[$clave] -replace '[\r\n]+', ' ')).Trim() }

    # CORRECCIÓN H-03: consola sin correo, contraseña ni tokens.
    Write-Host "[INFO] $(Ahora) intento de autenticacion recibido (credenciales omitidas)"

    $email = if ($form.ContainsKey("email")) { $form["email"] } else { "" }
    $claveValida = $form.ContainsKey("password") -and $form["password"].Length -ge 1 -and $form["password"].Length -le 128
    $usuario = @(Leer-Csv $UsersCsv | Where-Object { $_.Email -ieq $email } | Select-Object -First 1)
    $correcto = $false
    if ($usuario.Count -eq 1 -and $claveValida) {
        # CORRECCIÓN H-01: comparacion contra hash PBKDF2 en tiempo constante.
        $correcto = Probar-Contrasena $form["password"] $usuario[0].PasswordHash
    }

    $autoriza = [bool]$MetadatosAutorizados[$email.ToLowerInvariant()]
    Registrar-Evento $ctx "LOGIN_OK" "/login" $correcto $(if ($correcto) { "INFO" } else { "WARN" }) $autoriza

    if (-not $correcto) {
        # Mensaje generico: no revela si falló el correo o la contraseña.
        Enviar $ctx (Nueva-Pagina "Iniciar sesión" (Formulario-Login "Correo o contraseña incorrectos.") $ctx)
        return
    }

    # CORRECCIÓN H-02: la sesion autenticada determina el rol para /admin o /mi-cuenta.
    $rol = Get-Rol $usuario[0].Email

    # CORRECCIÓN H-02/C-13: segundo factor obligatorio para cuentas privilegiadas (R-02, R-03, R-04).
    if ($rol -in $RolesConMfa) {
        $secretoGuardado = ""
        if ($usuario[0].PSObject.Properties['TotpSecret']) { $secretoGuardado = $usuario[0].TotpSecret }
        if ([string]::IsNullOrWhiteSpace($secretoGuardado)) {
            $nuevoSecreto = Nueva-TotpSecret
            $token = Nueva-PendienteMfa $usuario[0].Email $rol $autoriza $nuevoSecreto $true
            Registrar-Evento $ctx "MFA_ENROLAMIENTO_INICIADO" "/login" $true
            Enviar $ctx (Nueva-Pagina "Verificación en dos pasos" (Formulario-Mfa $token $true $nuevoSecreto) $ctx)
            return
        }
        $token = Nueva-PendienteMfa $usuario[0].Email $rol $autoriza $secretoGuardado $false
        Registrar-Evento $ctx "MFA_SOLICITADA" "/login" $true
        Enviar $ctx (Nueva-Pagina "Verificación en dos pasos" (Formulario-Mfa $token $false) $ctx)
        return
    }

    Nueva-Sesion $ctx $usuario[0].Email $rol $autoriza | Out-Null
    $destino = if ($rol -in $RolesAdmin) { "/admin" } else { "/mi-cuenta" }
    Redirigir $ctx $destino
}

$Rutas["/login-verificar"] = {
    param($ctx)
    if ($ctx.Request.HttpMethod -ne "POST") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Usa POST en esta ruta." $ctx) 405
        return
    }

    $form = Leer-Formulario $ctx
    $token = if ($form.ContainsKey("token")) { $form["token"] } else { "" }
    $codigo = if ($form.ContainsKey("codigo")) { $form["codigo"] } else { "" }

    $pendiente = Get-PendienteMfa $token
    if (-not $pendiente) {
        Registrar-Evento $ctx "MFA_TOKEN_INVALIDO" "/login-verificar" $false "WARN"
        Enviar $ctx (Pagina-Error "Verificación expirada" "Tu verificación expiró o no es válida. Inicia sesión de nuevo." $ctx) 400
        return
    }

    $pendiente.Intentos = $pendiente.Intentos + 1
    if ($pendiente.Intentos -gt 5) {
        $PendientesMfa.Remove($token) | Out-Null
        Registrar-Evento $ctx "MFA_BLOQUEADA" "/login-verificar" $false "WARN"
        Enviar $ctx (Pagina-Error "Demasiados intentos" "Por seguridad, inicia sesión de nuevo." $ctx) 429
        return
    }

    if (-not (Test-CodigoTotp $pendiente.Secreto $codigo)) {
        Registrar-Evento $ctx "MFA_CODIGO_INCORRECTO" "/login-verificar" $false "WARN"
        Enviar $ctx (Nueva-Pagina "Verificación en dos pasos" (Formulario-Mfa $token $pendiente.EsNuevo $pendiente.Secreto "Código incorrecto. Intenta de nuevo.") $ctx) 400
        return
    }

    if ($pendiente.EsNuevo) {
        $usuarios = @(Leer-Csv $UsersCsv)
        $u = @($usuarios | Where-Object { $_.Email -ieq $pendiente.Email } | Select-Object -First 1)
        if ($u.Count -eq 1) {
            $u[0].TotpSecret = $pendiente.Secreto
            $u[0].TotpActivado = "True"
            Escribir-Csv $UsersCsv $EncabezadoUsuarios $usuarios
        }
        Registrar-Evento $ctx "MFA_ACTIVADA" "/login-verificar" $true
    } else {
        Registrar-Evento $ctx "MFA_OK" "/login-verificar" $true
    }

    $PendientesMfa.Remove($token) | Out-Null
    Nueva-Sesion $ctx $pendiente.Email $pendiente.Rol $pendiente.Metadatos | Out-Null
    $destino = if ($pendiente.Rol -in $RolesAdmin) { "/admin" } else { "/mi-cuenta" }
    Redirigir $ctx $destino
}

$Rutas["/logout"] = {
    param($ctx)
    if ($ctx.Request.HttpMethod -ne "POST") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Cierra sesión desde el botón del menú." $ctx) 405
        return
    }
    Registrar-Evento $ctx "LOGOUT" "/logout" $true
    Cerrar-Sesion $ctx
    Redirigir $ctx "/"
}

$Rutas["/ajustes"] = {
    param($ctx)

    $sesion = Get-SesionActual $ctx
    if (-not $sesion) {
        Registrar-Evento $ctx "ACCESO_DENEGADO" "/ajustes" $false "WARN"
        Redirigir $ctx "/login"
        return
    }

    $usuarios = @(Leer-Csv $UsersCsv)
    $usuario = @($usuarios | Where-Object { $_.Email -ieq $sesion.Email } | Select-Object -First 1)
    $u = if ($usuario.Count -eq 1) { $usuario[0] } else { $null }

    if ($ctx.Request.HttpMethod -eq "GET") {
        Registrar-Evento $ctx "AJUSTES_VIEW" "/ajustes" $true
        Enviar $ctx (Nueva-Pagina "Ajustes de la cuenta" (Formulario-Ajustes "" $true $u $sesion.Email) $ctx)
        return
    }
    if ($ctx.Request.HttpMethod -ne "POST") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Usa GET o POST en esta ruta." $ctx) 405
        return
    }

    $form = Leer-Formulario $ctx
    foreach ($clave in @($form.Keys)) { $form[$clave] = (($form[$clave] -replace '[\r\n]+', ' ')).Trim() }

    $accion = if ($form.ContainsKey("accion")) { $form["accion"] } else { "password" }
    if ($accion -in @("rectificar", "cancelar")) {
        if ($null -eq $u) {
            Enviar $ctx (Pagina-Error "Cuenta no encontrada" "No se encontró el registro de tu cuenta." $ctx) 404
            return
        }
        $email = if ($form.ContainsKey("email")) { $form["email"] } else { "" }
        if ($email -ine $sesion.Email) {
            Registrar-Evento $ctx "ARCO_RECHAZADO" "/ajustes" $false "WARN"
            Enviar $ctx (Pagina-Error "Solicitud rechazada" "Solo puedes ejercer derechos sobre tu propia cuenta." $ctx) 403
            return
        }
        if ($accion -eq "rectificar") {
            $nombre = if ($form.ContainsKey("nombre")) { $form["nombre"] } else { "" }
            $telefono = if ($form.ContainsKey("telefono")) { $form["telefono"] } else { "" }
            $poliza = if ($form.ContainsKey("aseguradora_poliza")) { $form["aseguradora_poliza"] } else { "" }
            $motivo = if ($form.ContainsKey("motivo_alergias")) { $form["motivo_alergias"] } else { "" }
            if ([string]::IsNullOrWhiteSpace($nombre) -or $nombre.Length -gt 120 -or
                $telefono -notmatch '^[0-9+\-() ]{7,20}$' -or
                [string]::IsNullOrWhiteSpace($poliza) -or $poliza.Length -gt 200 -or
                [string]::IsNullOrWhiteSpace($motivo) -or $motivo.Length -gt 1000) {
                Registrar-Evento $ctx "ARCO_RECTIFICACION_RECHAZADA" "/ajustes" $false "WARN"
                Enviar $ctx (Nueva-Pagina "Ajustes de la cuenta" (Formulario-Ajustes "Revisa los campos de rectificación e inténtalo de nuevo." $true $u $sesion.Email) $ctx) 400
                return
            }
            $u.Nombre = $nombre
            $u.Telefono = $telefono
            $u.AseguradoraPoliza = $poliza
            $u.MotivoAlergias = $motivo
            Escribir-Csv $UsersCsv $EncabezadoUsuarios $usuarios
            Registrar-Evento $ctx "ARCO_RECTIFICACION_OK" "/ajustes" $true
            Enviar $ctx (Nueva-Pagina "Ajustes de la cuenta" (Formulario-Ajustes "Tu solicitud de rectificación ARCO fue aplicada correctamente." $false $u $sesion.Email) $ctx)
            return
        }

        $resto = @($usuarios | Where-Object { $_.Email -ine $email })
        Escribir-Csv $UsersCsv $EncabezadoUsuarios $resto
        $MetadatosAutorizados.Remove($email.ToLowerInvariant()) | Out-Null
        Registrar-Evento $ctx "ARCO_CANCELACION_OK" "/ajustes" $true
        Cerrar-Sesion $ctx
        $html = "<p class='ok'>Tu solicitud de cancelación/oposición fue registrada, los datos fueron eliminados y tu sesión se cerró.</p>"
        $html += "<p><a href='/'>Volver al inicio</a></p>"
        Enviar $ctx (Nueva-Pagina "Solicitud ARCO atendida" $html $ctx)
        return
    }

    $actual = if ($form.ContainsKey("password_actual")) { $form["password_actual"] } else { "" }
    $nueva = if ($form.ContainsKey("password_nueva")) { $form["password_nueva"] } else { "" }
    $confirmacion = if ($form.ContainsKey("password_confirmacion")) { $form["password_confirmacion"] } else { "" }

    $rechazar = {
        param([string]$mensaje)
        Registrar-Evento $ctx "PASSWORD_CAMBIO_RECHAZADO" "/ajustes" $false "WARN"
        Enviar $ctx (Nueva-Pagina "Ajustes de la cuenta" (Formulario-Ajustes $mensaje $true $u $sesion.Email) $ctx) 400
    }

    if ($actual.Length -lt 1 -or $actual.Length -gt 128) { & $rechazar "La contraseña actual no es válida."; return }
    if ($nueva.Length -lt 8 -or $nueva.Length -gt 128) { & $rechazar "La nueva contraseña debe tener entre 8 y 128 caracteres."; return }
    if ($nueva -cne $confirmacion) { & $rechazar "La confirmación de la nueva contraseña no coincide."; return }

    if ($null -eq $u) { & $rechazar "No se encontró la cuenta autenticada."; return }

    if (-not (Probar-Contrasena $actual $u.PasswordHash)) { & $rechazar "La contraseña actual es incorrecta."; return }
    if (Probar-Contrasena $nueva $u.PasswordHash) { & $rechazar "La nueva contraseña debe ser diferente de la actual."; return }

    $u.PasswordHash = Nuevo-HashContrasena $nueva
    Escribir-Csv $UsersCsv $EncabezadoUsuarios $usuarios

    foreach ($token in @($Sesiones.Keys)) {
        if ($Sesiones[$token].Email -ieq $sesion.Email) { $Sesiones.Remove($token) | Out-Null }
    }
    Registrar-Evento $ctx "PASSWORD_CAMBIADO" "/ajustes" $true
    Cerrar-Sesion $ctx

    $html = "<p class='ok'>Contraseña actualizada. Todas las sesiones de la cuenta fueron cerradas.</p>"
    $html += "<p><a href='/login'>Iniciar sesión de nuevo</a></p>"
    Enviar $ctx (Nueva-Pagina "Contraseña actualizada" $html $ctx)
}

$Rutas["/admin"] = {
    param($ctx)

    # CORRECCIÓN H-02: /admin exige sesion autenticada; sin sesion se redirige a /login.
    $sesion = Get-SesionActual $ctx
    if (-not $sesion) {
        Registrar-Evento $ctx "ACCESO_DENEGADO" "/admin" $false "WARN"
        Redirigir $ctx "/login"
        return
    }
    if ($sesion.Rol -notin $RolesAdmin) {
        Registrar-Evento $ctx "ACCESO_DENEGADO" "/admin" $false "WARN"
        Enviar $ctx (Pagina-Error "403 Prohibido" "Tu rol ($($sesion.Rol)) no tiene acceso a esta sección." $ctx) 403
        return
    }

    Registrar-Evento $ctx "ADMIN_VIEW" "/admin" $true
    $usuarios = @(Leer-Csv $UsersCsv)
    $contenido = "<p>Sesión: $(Escapar $sesion.Rol) | Registros: $($usuarios.Count)</p>"

    if ($sesion.Rol -eq "R-02") {
        # CORRECCIÓN H-02: rol R-02 (Admisión) ve registros ENMASCARADOS.
        $columnas = @("Id", "Nombre", "Email", "Jurisdiccion", "Telefono", "AseguradoraPoliza", "MotivoAlergias", "Consentimiento", "FechaConsentimiento", "VersionAviso", "FechaRegistro")
        $filas = @(foreach ($u in $usuarios) {
            [pscustomobject][ordered]@{
                Id                  = $u.Id
                Nombre              = $u.Nombre
                Email               = Get-EmailEnmascarado $u.Email
                Jurisdiccion        = $u.Jurisdiccion
                Telefono            = Get-TelefonoEnmascarado $u.Telefono
                AseguradoraPoliza   = Get-PolizaEnmascarada $u.AseguradoraPoliza
                MotivoAlergias      = "********"
                Consentimiento      = $u.Consentimiento
                FechaConsentimiento = $u.FechaConsentimiento
                VersionAviso        = $u.VersionAviso
                FechaRegistro       = $u.FechaRegistro
            }
        })
        $contenido += "<p><strong>Vista de admisión (R-02):</strong> campos sensibles enmascarados; la bitácora y los hashes no están disponibles para este rol.</p>"
        $contenido += "<h3>Pre-registros</h3>" + (Tabla-Html $filas $columnas)
    } elseif ($sesion.Rol -eq "R-05") {
        # CORRECCIÓN H-02: rol R-05 (Médico / DEP-02) solo lectura de motivo de consulta y alergias.
        $columnas = @("Id", "Nombre", "FechaNacimiento", "MotivoAlergias")
        $filas = @(foreach ($u in $usuarios) {
            [pscustomobject][ordered]@{
                Id              = $u.Id
                Nombre          = $u.Nombre
                FechaNacimiento = $u.FechaNacimiento
                MotivoAlergias  = $u.MotivoAlergias
            }
        })
        $contenido += "<p><strong>Vista clínica (R-05 - Servicios Médicos):</strong> acceso de solo lectura a identificación básica y motivo de consulta/alergias (sin datos financieros ni bitácora).</p>"
        $contenido += "<h3>Pre-registros clínicos</h3>" + (Tabla-Html $filas $columnas)
    } elseif ($sesion.Rol -eq "R-06") {
        # CORRECCIÓN H-02: rol R-06 (Facturación / DEP-05) solo lectura de aseguradora y póliza, sin datos de salud.
        $columnas = @("Id", "Nombre", "Email", "AseguradoraPoliza")
        $filas = @(foreach ($u in $usuarios) {
            [pscustomobject][ordered]@{
                Id                = $u.Id
                Nombre            = $u.Nombre
                Email             = $u.Email
                AseguradoraPoliza = $u.AseguradoraPoliza
            }
        })
        $contenido += "<p><strong>Vista de facturación (R-06 - Administración y Finanzas):</strong> acceso de solo lectura a aseguradora y póliza (sin datos sensibles de salud).</p>"
        $contenido += "<h3>Aseguradoras y pólizas</h3>" + (Tabla-Html $filas $columnas)
    } elseif ($sesion.Rol -eq "R-03") {
        # CORRECCIÓN H-02: segregación de funciones para R-03 (TI). Administra la app sin consultar datos personales de pacientes.
        $contenido += "<p><strong>Vista de administración de TI (R-03):</strong> por segregación de funciones y mínimo privilegio, este rol no consulta datos personales ni clínicos de pacientes.</p>"
    } else {
        # CORRECCIÓN H-02: R-04 (DPO / ARCO) tiene acceso de auditoría/ARCO. Nunca se muestra PasswordHash.
        $columnas = @("Id", "Nombre", "Email", "FechaNacimiento", "Telefono", "Jurisdiccion", "AseguradoraPoliza", "MotivoAlergias", "Consentimiento", "FechaConsentimiento", "VersionAviso", "FechaRegistro")
        $filas = @(foreach ($u in $usuarios) {
            [pscustomobject][ordered]@{
                Id                  = $u.Id
                Nombre              = $u.Nombre
                Email               = $u.Email
                FechaNacimiento     = $u.FechaNacimiento
                Telefono            = $u.Telefono
                Jurisdiccion        = $u.Jurisdiccion
                AseguradoraPoliza   = $u.AseguradoraPoliza
                MotivoAlergias      = $u.MotivoAlergias
                Consentimiento      = $u.Consentimiento
                FechaConsentimiento = $u.FechaConsentimiento
                VersionAviso        = $u.VersionAviso
                FechaRegistro       = $u.FechaRegistro
            }
        })
        $contenido += "<h3>Pre-registros</h3>" + (Tabla-Html $filas $columnas)
    }

    if ($sesion.Rol -in $RolesAuditoria) {
        $accesos = @(Leer-Csv $AccessLogCsv)
        [array]::Reverse($accesos)
        $contenido += "<h3>Bitácora de eventos (sin datos personales)</h3>" + (Tabla-Html $accesos @("Fecha", "Evento", "Ruta", "Exito", "Nivel", "IPAnonimizada"))
    }
    if ($sesion.Rol -eq "R-03") {
        # CORRECCIÓN H-06: verificacion de integridad de los archivos de datos.
        $contenido += "<h3>Integridad SHA-256</h3><p>users.csv: <code>$(Escapar (Get-FileSha256 $UsersCsv))</code><br>"
        $contenido += "access_log.csv: <code>$(Escapar (Get-FileSha256 $AccessLogCsv))</code></p>"
        $contenido += "<h3>Descargas</h3><ul>"
        $contenido += "<li><a href='/descargar?archivo=accesos'>Descargar access_log.csv</a></li>"
        $contenido += "</ul><p>Por segregación de funciones, R-03 solo descarga la bitácora operativa.</p>"
    } elseif ($sesion.Rol -eq "R-04") {
        # CORRECCIÓN H-02: descarga de users.csv (sin PasswordHash) restringida a R-04 (DPO / ARCO).
        $contenido += "<h3>Descargas</h3><ul>"
        $contenido += "<li><a href='/descargar?archivo=usuarios'>Descargar users.csv (sin PasswordHash)</a></li>"
        $contenido += "<li><a href='/descargar?archivo=accesos'>Descargar access_log.csv</a></li>"
        $contenido += "</ul><p>Cada descarga se registra en la bitácora sin datos personales.</p>"
    } else {
        $contenido += "<p>Las descargas de archivos completos están restringidas a auditoría (R-03 bitácora, R-04 DPO/ARCO).</p>"
    }
    Enviar $ctx (Nueva-Pagina "Administración" $contenido $ctx)
}

$Rutas["/descargar"] = {
    param($ctx)

    # CORRECCIÓN H-02: control de acceso RBAC también sobre la descarga de datos.
    $sesion = Get-SesionActual $ctx
    if (-not $sesion) {
        Registrar-Evento $ctx "DESCARGA_DENEGADA" "/descargar" $false "WARN"
        Redirigir $ctx "/login"
        return
    }
    if ($sesion.Rol -notin $RolesAuditoria) {
        Registrar-Evento $ctx "DESCARGA_DENEGADA" "/descargar" $false "WARN"
        Enviar $ctx (Pagina-Error "403 Prohibido" "Tu rol no puede descargar los archivos completos." $ctx) 403
        return
    }
    if ($ctx.Request.HttpMethod -ne "GET") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Usa GET para descargar." $ctx) 405
        return
    }

    $parametros = @{}
    foreach ($par in ($ctx.Request.Url.Query.TrimStart('?') -split '&')) {
        if (-not $par) { continue }
        $partes = $par -split '=', 2
        $clave = [System.Net.WebUtility]::UrlDecode($partes[0])
        $valor = if ($partes.Count -gt 1) { [System.Net.WebUtility]::UrlDecode($partes[1]) } else { "" }
        $parametros[$clave] = $valor
    }
    $archivo = $parametros["archivo"]

    if ($archivo -eq "usuarios") {
        if ($sesion.Rol -ne "R-04") {
            Registrar-Evento $ctx "DESCARGA_DENEGADA" "/descargar?archivo=usuarios" $false "WARN"
            Enviar $ctx (Pagina-Error "403 Prohibido" "Por segregación de funciones, solo R-04 (DPO/ARCO) puede descargar users.csv." $ctx) 403
            return
        }
        # CORRECCIÓN H-02: R-04 audita sin recibir los hashes de contraseñas.
        $filas = @(Leer-Csv $UsersCsv | Select-Object -Property * -ExcludeProperty PasswordHash)
        $lineas = @($filas | ConvertTo-Csv -NoTypeInformation)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes(($lineas -join "`r`n"))
        $nombre = "users.csv"
        Registrar-Evento $ctx "DESCARGA_USUARIOS" "/descargar?archivo=usuarios" $true
    } elseif ($archivo -eq "accesos") {
        $bytes = [System.IO.File]::ReadAllBytes($AccessLogCsv)
        $nombre = "access_log.csv"
        Registrar-Evento $ctx "DESCARGA_ACCESOS" "/descargar?archivo=accesos" $true
    } else {
        Enviar $ctx (Pagina-Error "Archivo no válido" "Usa los enlaces de descarga del panel de administración." $ctx) 400
        return
    }

    Enviar-Archivo $ctx $bytes $nombre
}

$Rutas["/mi-cuenta"] = {
    param($ctx)

    $sesion = Get-SesionActual $ctx
    if (-not $sesion) {
        Registrar-Evento $ctx "ACCESO_DENEGADO" "/mi-cuenta" $false "WARN"
        Redirigir $ctx "/login"
        return
    }

    $usuario = @(Leer-Csv $UsersCsv | Where-Object { $_.Email -ieq $sesion.Email } | Select-Object -First 1)
    if ($usuario.Count -ne 1) {
        Enviar $ctx (Pagina-Error "Cuenta no encontrada" "No se encontraron datos para tu cuenta." $ctx) 404
        return
    }

    Registrar-Evento $ctx "MI_CUENTA_VIEW" "/mi-cuenta" $true
    $u = $usuario[0]
    $filas = @([pscustomobject][ordered]@{
        Id                  = $u.Id
        Nombre              = $u.Nombre
        Email               = $u.Email
        FechaNacimiento     = $u.FechaNacimiento
        Telefono            = $u.Telefono
        Jurisdiccion        = $u.Jurisdiccion
        AseguradoraPoliza   = $u.AseguradoraPoliza
        MotivoAlergias      = $u.MotivoAlergias
        Consentimiento      = $u.Consentimiento
        FechaConsentimiento = $u.FechaConsentimiento
        VersionAviso        = $u.VersionAviso
        FechaRegistro       = $u.FechaRegistro
    })
    $html = "<p><strong>Derecho de Acceso (ARCO):</strong> estos son los datos personales registrados en tu cuenta (<code>$(Escapar $sesion.Rol)</code>).</p>"
    $html += Tabla-Html $filas @("Id", "Nombre", "Email", "FechaNacimiento", "Telefono", "Jurisdiccion", "AseguradoraPoliza", "MotivoAlergias", "Consentimiento", "FechaConsentimiento", "VersionAviso", "FechaRegistro")
    $html += "<p><a href='/ajustes#arco'>Ejercer derechos ARCO (rectificar o eliminar)</a> | <a href='/ajustes'>Cambiar contraseña</a></p>"
    Enviar $ctx (Nueva-Pagina "Mi cuenta" $html $ctx)
}

# ------------------------------------------------------------------------------
# 4. SERVIDOR Y DESPACHADOR
# ------------------------------------------------------------------------------
Inicializar-Csv

$servidor = [System.Net.HttpListener]::new()
$servidor.Prefixes.Add("http://$($Direccion):$Puerto/")
$servidor.Start()

Write-Host "=== $CompanyName | $AppVersion ==="
Write-Host "Escuchando en http://$($Direccion):$Puerto/ (usar reverse proxy HTTPS en produccion)"
Write-Host "Rutas: $(($Rutas.Keys | Sort-Object) -join ', ')"

try {
    while ($servidor.IsListening) {
        $tarea = $servidor.GetContextAsync()
        while (-not $tarea.Wait(200)) { if (-not $servidor.IsListening) { break } }
        if (-not $tarea.IsCompleted) { continue }

        $ctx = $tarea.Result
        $ruta = $ctx.Request.Url.AbsolutePath.TrimEnd('/')
        if (-not $ruta) { $ruta = "/" }
        $metodo = $ctx.Request.HttpMethod

        # CORRECCIÓN H-03: unicamente evento operativo (metodo + ruta), sin query ni PII.
        Write-Host "[INFO] $(Ahora) $metodo $ruta"

        try {
            $proto = $ctx.Request.Headers[$ProxyProtoHeader]
            $protoNormalizado = if ($proto) { ($proto -split ',')[0].Trim() } else { "" }
            $debeRedirigir = ($protoNormalizado -and $protoNormalizado -ine "https") -or ($ExigirHttps -and -not (Test-EsSeguro $ctx))
            if ($debeRedirigir) {
                # CORRECCIÓN H-04: TLS terminado en el reverse proxy.
                $hostHeader = $ctx.Request.Headers["Host"]
                Redirigir $ctx "https://$hostHeader$ruta" 301
            }
            elseif ($Rutas.Contains($ruta)) {
                $manejador = $Rutas[$ruta]
                & $manejador $ctx
            }
            else {
                Enviar $ctx (Pagina-Error "Página no encontrada" "La ruta $ruta no existe." $ctx) 404
            }
        } catch {
            Write-Host "[ERROR] $(Ahora) fallo operativo; detalles omitidos para evitar PII en consola"
            try {
                if (-not $ctx.Response.OutputStream.CanWrite) { continue }
                Enviar $ctx (Pagina-Error "Error interno" "Ocurrió un error al procesar la solicitud." $ctx) 500
            } catch { }
        }
    }
} finally {
    $servidor.Stop()
    $servidor.Close()
}
