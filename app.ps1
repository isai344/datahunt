# Hospital Integral Kuxtal - Reto 4: Pagina Web Data Hunt
# Version v4 - Arquitectura de UN SOLO ARCHIVO (app.ps1)
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
$AppVersion       = "v4"
$DataPath         = "C:\DataHunt"
$UsersCsv         = Join-Path $DataPath "users.csv"
$AccessLogCsv     = Join-Path $DataPath "access_log.csv"
$ArcoSolicitudesCsv = Join-Path $DataPath "arco_solicitudes.csv"
$PrivacyPolicyVer = "v2.1 (2026-11-26)"

$Direccion = "+"
$Puerto    = 443
$PuertoRedireccion = 80

# CORRECCIÓN H-04: TLS termina en el propio HttpListener (https://kuxtal.com/, puerto 443).
# El puerto 80 solo redirige a HTTPS. Se conserva X-Forwarded-Proto por si se añade proxy.
$ExigirHttps      = $true
$ProxyProtoHeader = "X-Forwarded-Proto"

$SessionTimeoutMin   = 30
$MaxBodyBytes        = 65536
$IteracionesPbkdf2   = 600000
$CookieSesion        = "kuxtal_sid"

# CORRECCIÓN H-02: RBAC según matriz de roles (R-01 Paciente, R-02 Admisión, R-03 TI, R-04 DPO, R-05 Médico, R-06 Facturación, R-07 Privacidad).
# Para promover una cuenta, agregar su correo a la tabla.
$RolesAdmin = @("R-02", "R-03", "R-04", "R-05", "R-06")
$RolesAuditoria = @("R-03", "R-04")
$RolPrivacidad = "R-07"
# CORRECCIÓN H-02/C-13: verificación en dos pasos (TOTP) obligatoria para las cuentas privilegiadas
# DPO (R-04), TI/administración (R-03), Admisión (R-02) y Oficina de Privacidad (R-07), conforme al Anexo A.5 del aviso de privacidad.
$RolesConMfa = @("R-02", "R-03", "R-04", "R-07")
$RolesPorEmail = @{
    "admin@kuxtal.test"       = "R-03"
    "dpo@kuxtal.test"         = "R-04"
    "admision@kuxtal.test"    = "R-02"
    "medico@kuxtal.test"      = "R-05"
    "facturacion@kuxtal.test" = "R-06"
    "privacidad@kuxtal.test"  = "R-07"
    "rmedinal@kuxtal.example" = "R-02"
    "meuanp@kuxtal.example"   = "R-05"
    "vherrerap@kuxtal.example" = "R-06"
}

$EncabezadoUsuarios = "Id,Nombre,Email,PasswordHash,FechaNacimiento,Telefono,Jurisdiccion,AseguradoraPoliza,MotivoAlergias,Consentimiento,FechaConsentimiento,VersionAviso,FechaRegistro,TotpSecret,TotpActivado"
$EncabezadoAccesos  = "Fecha,Evento,Ruta,Exito,Nivel,IPAnonimizada"
$EncabezadoArco     = "Id,EmailSolicitante,NombreSolicitante,Derecho,Motivo,Estado,FechaSolicitud,FechaResolucion,Resolutor,Decision,DetalleResolucion"

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
# Solo se exige a las cuentas privilegiadas (R-02 Admisión, R-03 TI, R-04 DPO, R-07 Privacidad). Ver $RolesConMfa.
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
    if (-not (Test-Path -LiteralPath $ArcoSolicitudesCsv)) {
        Set-Content -LiteralPath $ArcoSolicitudesCsv -Value $EncabezadoArco -Encoding utf8
    }
    Migrar-ColumnasUsuarios
    Set-ProteccionArchivo $UsersCsv
    Set-ProteccionArchivo $AccessLogCsv
    Set-ProteccionArchivo $ArcoSolicitudesCsv
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
    [pscustomobject]$registro | Export-Csv -LiteralPath $ruta -Append -NoTypeInformation -Encoding utf8 -Force
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

function Get-DestinoInicio([string]$rol) {
    if ($rol -eq $RolPrivacidad) { return "/privacidad" }
    if ($rol -in $RolesAdmin) { return "/admin" }
    return "/mi-cuenta"
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

function Cerrar-Sesiones-De([string]$email) {
    foreach ($token in @($Sesiones.Keys)) {
        if ($Sesiones[$token].Email -ieq $email) { $Sesiones.Remove($token) | Out-Null }
    }
    foreach ($token in @($PendientesMfa.Keys)) {
        if ($PendientesMfa[$token].Email -ieq $email) { $PendientesMfa.Remove($token) | Out-Null }
    }
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

# Las peticiones HEAD declaran Content-Length pero no envian cuerpo.
function Escribir-Cuerpo($ctx, [byte[]]$bytes) {
    if ($ctx.Request.HttpMethod -eq 'HEAD') { return }
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
}

function Enviar($ctx, [string]$html, [int]$codigo = 200) {
    if (-not $script:CspNonce) { Nuevo-Nonce | Out-Null }
    Set-CabecerasSeguras $ctx
    $ctx.Response.StatusCode = $codigo
    $ctx.Response.ContentType = "text/html; charset=utf-8"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
    $ctx.Response.ContentLength64 = $bytes.Length
    Escribir-Cuerpo $ctx $bytes
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
    Escribir-Cuerpo $ctx $bytes
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
    Escribir-Cuerpo $ctx $bytes
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
  --maroon:#2e4a33; --maroon-dark:#203727; --maroon-darker:#17291dcc;
  --teal:#7a4b2a; --teal-dark:#5e3720;
  --bg:#f4f1e5; --surface:#fffdf4; --surface-alt:#f0ecdd;
  --border:#dad4c2;
  --text:#222b20; --text-muted:#6b6658;
  --ok:#2f6b3a; --ok-bg:#e9f3e7; --ok-border:#a6cf9f;
  --err:#8d3327; --err-bg:#f9eae6; --err-border:#e6b2a7;
  --warn:#8a6420; --warn-bg:#fbf2dd; --warn-border:#e3c98e;
  --radius:10px; --shadow:0 2px 10px rgba(0,0,0,.10);
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
  width:52px;height:52px;object-fit:contain;flex-shrink:0;
  background:transparent;filter:brightness(2.35) saturate(1.15);
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
  outline:none;border-color:var(--teal);box-shadow:0 0 0 3px rgba(122,75,42,.20);
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
tbody tr:hover{background:#eae4d2}
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
    $sesion = if ($ctx) { Get-SesionActual $ctx } else { $null }
    $nav = "<a href='/'>Inicio</a>"
    if (-not $sesion) { $nav += "<a href='/registro'>Registro</a><a href='/login'>Iniciar sesión</a>" }
    if ($sesion -and $sesion.Rol -in $RolesAdmin) { $nav += "<a href='/admin'>Administración</a>" }
    if ($sesion -and $sesion.Rol -eq $RolPrivacidad) { $nav += "<a href='/privacidad'>Privacidad</a>" }
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
<header class='topbar'><div class='bar-inner'><img src='/assets/kuxtal_logo.png' class='brand-mark' alt='' aria-hidden='true'><div class='brand-text'><h1>$nombre</h1></div></div></header>
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

# CORRECCIÓN H-02/C-13: segundo factor (TOTP) para R-02, R-03, R-04 y R-07. $esNuevo=true la primera vez
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
    $solicitudes = @(Leer-Csv $ArcoSolicitudesCsv | Where-Object { $_.EmailSolicitante -ieq $email })
    $historial = if ($solicitudes.Count -gt 0) {
        $filas = @($solicitudes | Select-Object -Property Id, Derecho, Estado, FechaSolicitud, FechaResolucion, Decision, DetalleResolucion)
        Tabla-Html $filas @("Id", "Derecho", "Estado", "FechaSolicitud", "FechaResolucion", "Decision", "DetalleResolucion")
    } else {
        "<p>Aún no has enviado solicitudes ARCO.</p>"
    }
    return @"
<hr><section id='arco'>
<h3>Derechos ARCO (Acceso, Rectificación, Cancelación y Oposición)</h3>
<p>Ejerce tus derechos <strong>ARCO</strong> (LFPDPPP 2025 / GDPR / CCPA) sobre tu cuenta autenticada. Para consultar tus datos completos ve a <a href='/mi-cuenta'>Mi cuenta</a>. Tu solicitud se envía al Departamento de Privacidad, que valida tu identidad y decide entre eliminar tus datos, entregarte un reporte o rechazar la petición con motivo.</p>
<form method='post' action='/ajustes'>
<input type='hidden' name='accion' value='solicitar_arco'>
<input type='hidden' name='email' value='$(Escapar $email)'>
<label>Derecho que deseas ejercer
<select name='derecho' required>
<option value='Acceso'>Acceso</option>
<option value='Rectificación'>Rectificación</option>
<option value='Cancelación'>Cancelación</option>
<option value='Oposición'>Oposición</option>
</select></label>
<label>Motivo de la solicitud <textarea name='motivo' maxlength='500' required></textarea></label>
<button type='submit'>Enviar solicitud al Departamento de Privacidad</button></form>
<h4>Seguimiento de tus solicitudes</h4>
$historial
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
<p>Puedes acceder, rectificar, cancelar u oponerte al tratamiento (ARCO), así como revocar tu consentimiento o limitar su uso, desde <a href='/ajustes#arco'>el apartado de derechos ARCO en Ajustes</a> o escribiendo a {CONTACTO}. Tu solicitud se registra con un folio y pasa al Departamento de Privacidad (R-07), que valida tu identidad y resuelve si procede eliminar tus datos, entregarte un reporte o rechazar la petición con un motivo. Respondemos en un máximo de 20 días hábiles y, si procede, lo hacemos efectivo en los 15 días siguientes; ambos plazos pueden ampliarse una vez por un periodo igual. El ejercicio de tus derechos es gratuito, salvo costos de reproducción o envío. Tu expediente clínico no puede cancelarse antes del plazo que fija la norma sanitaria (NOM-004-SSA3-2012); mientras tanto se bloquea y solo lo consulta personal autorizado.</p>
<h3>6. Menores de edad o personas con incapacidad</h3>
<p>Si el paciente es menor de 18 años o tiene una incapacidad legal, su madre, padre o tutor realiza el pre-registro, otorga los consentimientos y ejerce los derechos ARCO en su nombre, acreditando su identidad y su representación.</p>
<h3>7. GDPR (pacientes de la Unión Europea)</h3>
<p>Si resides en la UE también te aplica el Reglamento General de Protección de Datos. Base legal: tu consentimiento explícito, específico para el tratamiento en general (art. 6.1.a) y para los datos de salud (art. 9.2.a). Tienes derecho de acceso, rectificación, supresión, limitación, portabilidad y oposición, y a presentar una reclamación ante la autoridad de protección de datos de tu país. Tus datos pueden tratarse en México y almacenarse en servidores de AWS fuera de la UE, protegidos con cláusulas contractuales tipo. Respondemos en un mes, ampliable. El hospital cuenta con un representante designado en la UE conforme al art. 27 del GDPR.</p>
<h3>8. CCPA/CPRA (pacientes de California)</h3>
<p id='ccpa'>Si resides en California, tu información de salud está protegida por HIPAA (sección 9) y el resto de tu información personal por la CCPA. <strong>No vendemos ni compartimos</strong> tu información personal con fines de publicidad. Tienes derecho a saber qué información tenemos, eliminarla, corregirla, limitar el uso de tu información sensible y no sufrir discriminación por ejercerlos, escribiendo a {CONTACTO}. Respondemos en 45 días, ampliables otros 45. No vendemos ni compartimos información de menores de 16 años.</p>
<h3>9. HIPAA (pacientes de Estados Unidos)</h3>
<p>Si resides en Estados Unidos, el hospital es una entidad cubierta por la ley federal HIPAA porque factura electrónicamente a aseguradoras de ese país. Podemos usar y divulgar tu información para tu tratamiento, el pago de tu atención (por ejemplo a tu aseguradora) y las operaciones del hospital, sin necesitar tu autorización adicional; cualquier otro uso, como mercadotecnia, requiere tu autorización por escrito y puedes revocarla en cualquier momento. Puedes pedir restricciones sobre el uso de tu información, recibir comunicaciones confidenciales por otro medio, ver y recibir copia de tu expediente (respondemos en 30 días, ampliables 30 más), pedir que se corrija (60 días, ampliables 30 más) y recibir un informe de las divulgaciones que hicimos (60 días). Contacto del oficial de privacidad: {CONTACTO}. Si crees que violamos tus derechos, puedes presentar una queja ante nosotros o ante la Oficina de Derechos Civiles del Departamento de Salud y Servicios Humanos de EE. UU. (HHS), sin que haya represalias por hacerlo.</p>
<h3>10. Cómo protegemos tus datos</h3>
<p>Cifrado de los archivos con tus datos y verificación de su integridad; contraseñas con hash PBKDF2-SHA256 y sal, comparadas en tiempo constante; sesiones HttpOnly y SameSite=Strict; ACL restrictiva en los archivos; anonimización de IP; bitácora de eventos sin datos personales. El acceso es por roles, con el mínimo de permisos necesarios, y <strong>verificación en dos pasos obligatoria</strong> para las cuentas con más privilegios (Admisión, TI/Administración, la DPO y la Oficina de Privacidad). Si ocurre una vulneración que afecte de forma significativa tus derechos, te lo informaremos de inmediato.</p>
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
    "/assets/kuxtal_logo.png" = [Convert]::FromBase64String('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')
    "/assets/cruz.png" = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAABngSURBVHhe7V0JsBRVlhUBFxYVcQGUxl0xFIwRBJVWAVfEZZpFRwURFbdWo7VHBlBA3LXVHnvsMdAeHbDtGQ11NKLdu21bO3BldcMWFQUUbD4/8+XLrP8/cOeem5X5M6uyqC1r/fUjTmT9qnz53rv3vHvvW3O7RCJxCOOsBjomtiOiOYzGXwf9205rPce2bWqgY6JBgA6OBgE6OBoE6OBoEKCDo0GADo6OQQDHITuRILu1ley2NrK3bCF761ayuRvkA//je/yO+3A/0kU9r45QfwSA4jZvJoeVmmD4VyhYa3J+/JHs1avJ+vJLsj//nJyPPyHNV/n/22/d33Ef3x9Kz8Bz5flR+dYoap8AaKXccn1F8We9di3ZixaR8d8LSM2eTfYlU8k85RTaNHgw6QP2J2fPPcjp2ZMS3bpRYqed5Ir/nT335N8PoE1HHUXmqaeSnjqV1Jw5ZCxcSPa775Fet46JESAELEaNW4naJACEnlQEoNd8R9bzz5Pxy38lNXIkqb59KLHddoI2xhYGFQCkQ/oWoFMnMvv1I2v0aDJuuomsF17gfNf4ZRAXUoNkqC0CtLb5LV2zyVaPPEJq7Fiy9trLV/ZWRqoi8V2hiHqWRwpr771JnXM2qUfnk/5qlZRLLANiiKjyVyFqgABo7Ul/bBhkPfcsmePGkbXrrqKE1NbdrrxOkd/jfg+bAwh+790blT71e9wvZOjVi8yJE8UyOEq5VgEuIrJO1YPqJgALUQTJwZl5112kBg6Ulg6hpyolqBj8DqU6DJt9vNO/P5lDh1ITrMWkyWRffz1ZM/6NLI4P9Lx5csX/znXX8e+TqOnMM8kcMoScffcle8cd5TkeSbw8MuWL8qkjjiB1371kr3VdhPQyoupXBahOAnDLEcGtWkXmL38pJr41IOhUweMzzLINcBBnnPvPZN1+O6nnniNr+TKyN2wgh/2z5z4AfE5F6Dfcz+mspUtJPfssWbfNI4PNvd5/f8kn1d2klgnltfr2JcXEsr/5xq3PFu5FRNW3gqgiAmiyW1pcBfzwA5mzZpLVe3cRdLuQO/lCxhVC1t125sBvFKk77iDr7bfJaWrylekp1m5jwfOzJUjbZqCW/N3hrh7ub3NjDu95osSNG8l6669kzruNrBNPJM0WZlvkRPkt7l2gN4EupjwDz47Mv/yoCgJoBoTcwi1EzZ9PiltZqlC9z55pV8cfR+rBB0h/8gklgl2zNg7AtqnkIgBiJEkhhODYRK9YTupX95EaPkwsA8oXVW7URx10EKnHH6cWTidljcqjzKg8AThillaxeDH3vU8RHxolQGlJPXuQOfUS0n99ixKsCF/plRqc4Xx9MrS2kH7zTTInTybdvVuK5Wr/jPqZHGPYy5e79a6wNagcAXSy1XNrUPffT1b37mnBHT6L4jniV7/4hYzctXAaUXpLlY3IsSKlPigbWyXz2p+T7tnTtwjBOqGe1i67kPrNQ+310ewCo55bYlSIAI7ber9dTebZZ/utPlVIuksXMq+6iuyVK93WAvjmvTICywoun0+ETz8j87LLyN5+e79ewTqKNRg/npx169z6RT2vxCg/AdhsQjj6T38i84D9Qy0EV18wp59OetEilyiFCgeuIS5EPT8jXHJ6RNBvc9A4enQk0VF/85BD5B7UVeedV3EoLwHYb0Mg6re/JYv7157CPWGg1au99ybrkUf8QEkXEdA57JcdBG1FoZWfU/jIHsqPeiQ2bxGTb/XeI+Dq3MEq1N9Cb+bRR13LUcaRxPIQAP6NBYDKmdOnSxTvVdxTvrT6s8aS86U7pOoGRwWaeW5FCb4al04le9gw0iNGRMLO8DkETt88bRolQMRiWmcy2HU4jjFPO01GD1NlgF6Emn2LSwLMPJYhLig9AVAJbs0tLABjypRQxXEF4OvVPffE1z1i8oAA9sCBISEXCnPQIHKg/KIjdp20BpvJvO020hwbBMuHz5CPccUV3CXe4g4ll5gEpSUACs+VaOHWY5430e/be5UVk79PP9KvvNJu+rh30P6MAs2/R4Cjj46FAGr48JgI4EKza0F9rRdfFJeHPIJyERJMniSNBpYzLJN4UToCiNnfzJVoi1Q+gh9j8GCyP/vUNflF+Po0VDkBBFxfqffy5WQefnggLnCvkJcxaRIlYAWYMKWyBKUjALNXfP6Ui9OUj769MWoUJdavj8fkp6IWCJCEuIS1a8kccXxaj0hIAHcAGcEaRKQvFiUhALoyovybpqf5fFH+GWdQwjBc5ZeC2TVEAKk/SNC0kQzuKqaSQILj2bNdEqAMUc8oAvETgE0bCouuXjDaxxWVax7DyrfcYKhUZq2mCACwHMQSmAY1jx6VRgLpHfzXY67LiEpfBGInAAqp//xn0sl+vlcJ8fkjTypty/dQawQAPBJs3Ejm8celxQRWt25k/+1vruyi0heI+AiQrICDxRsD9gsJEJVBV8r3+aVUPlCLBACS8yMSExx2WFo5zIMPJuf7H9wVzlHpC0BsBNAQOkesxtgz00yY6tuXo/3PYmdvRtQqAYAkCexly2QdQVCOYkXHjXPjgZjKEgsBMJ8P06/u/1Va0Ke7dpV+fin8V0bUMgGSgLywvtDu3DkkTwSF6uGHXVcbkS5fFE8Aj7FLl8qUbrCwIIN5993C2GLG9PNGHRDAC6bNuXPTGhWmku1PP43FohZPABZKS1sb9+tHi6/3hIbP6O7JkGZL+SY3BPVAAID7/lj4Yo4alSZbc8wYkS1cb2TaHFE0AcT0z58fmuoUlmL3zapVLktLOJQZiXohAEPkx/GTtdtuIflC3tbCBUW71uIIgD14HNmr/v3TCqce+c/y+v0g6ogAgDSyBx9McwXqwAPI4W6jzBxGpMsFBRPAD/xmzPTXv3kCk8UPWAJdbtPvoc4IIK6AYY4Y4ZcJ9cJQsZp3a1ENrXALAN/+1SqyeoVNk0T9ixYlA5QS9/czod4IwIA89V/+IsvLgvJGV9H+7ruC9xwURgAn2fpvuCHU+tFPNS+/zGVkOaP+VNQhAWSRC8vVnHSRyBnlQt0gfzVrVsFWIE8CuErFFmywztqjd4iNWAVrf/GFu1M2LW0ZUY8ESC4msT/+mHS3biG5W336yGaaQmKBgiyAtP477/SneQFh4vXXu6NUhS7kiAt1SQCGN9E2bVrICkgs8MADBVmB/AmARZKmQeqQg33h4qp79CD785WxjlMXjHolAEOswPLlsiUtKH9sSHUwx5LnuoG8CYACYIt2sN8vAxMXX+y2/kr6fg91TADIV2KB887zB4dQR0y9Wy/9MRl8R6TLgPwI4CQDkZ/9zBcOMrc7dSL91lvJzCsU+QdRzwRgSCN87dXQeguQQV1wgesG8miE+REA5n3VV6R32cXPGFcICP3UahFQvRMAZh7b19VRR4X0YO3ei4Pzb90uelS6CORFAAn+sGkjmSHgBiD3FxSAlAz1TgCG6OKOO/xuOAC9qCeeyEsXuROABYAHm2PH+oJBpnrnnWWLdlUEfx7qngBul1AvXkz2Djv4dRQ3MGG8S4Ac3UDuBIBZWbOG9J57+Bniqkae5I4LQEBR6SqBDkAAlAVb19Sxw/1yoq7WPv3kRJRcxwRyJoAEHs8/70f/gJj/22+vLvMP1D0BXIgbmDUrNCYA/eiXX865N5AzASSzm24KZeZsvz3pd97OObOyoYMQQNzA669zb6D9RDQ0SuOW2Tk3ytwIwJXHej9z5MikUNwMcZQLzuSxN7dFp6sUOggBxMxvWE82m/1gPS3su0BMlsgeB+RGAPj4devI7tMnlJE+91xhWsblXp7Qyg0WTALXIUPiIcCxx4q/1RB4al7lAOSYQb5QNM5S8MoqDXPAALJx5nEOcUBOBICpUYsWhXazwtRgh2smU+Mw0AoxPCnXEDiKjfycz2+p/wc+s9BacD06JgKwBUiwsPHc9vw85Frebf2W+n/gc1J+UTIGIH/r5pvDcUCXLuQsXpLT+YQ5E8BesECUjgwA9Dn1c89F+38Iq7WVmi6/nPSgQaTZFFvlBLd85NnWvXuaMgtBa/ce/Lwh8tzI/EoIxfIzr7xStpRHWQLI33rqqVBwjs/m009H6yYFORFAAsC5c0IskxM0ly2LZhkIwHGBccwxcm+qQGsNlawD+vb2cce7u4QzEeD9D8jmVu8RQKzzXXfFRIDk5MOmqVNDBDB+0p/0+gxz0CAAVgqfeEJdEKCSEALIErsMYy0sf2ftWnL22suXtaS5+uqYCABlcqChTznFLxQy0scMEb8YuSzZJ8CJDQIUiawEwLyAZZE16MhQOn3WWW58FpUmgOwESAY+9uDBIWXqMWOSDIvoATQIEBuyEgCy5gbadPJoPw1kvmnYMfxbsheRmiaA7ARgRSb+wV2KAw/wlQlXoC+6SAjgNAhQUmQlALto6MGYMMFPA5ljc6m9qVkW8KSlCSArATDOb61eTSrgYzADZVx3nWtiosYAGgSIDbkQQPQw7Qq5F2kgc3uffTg2WJd1LCA7Afjh5sqVZPTs6SsTUebGmTPdjCPSNAgQH7ISgCF6uOGGEAGc3XuR/vprsrdyuog0HnIigMLZt93cjZ8ACNA0d26DAGVALgSAjqwZM8IE4AYrb0LLMk2fGwFWrCC1884hAmyal3kUsEGA+JAzAWbNChOgR3ey/v73mAjQsAAVQxVYgK0SAzQn1wECCAIbMUB5kAsBMsYA33AMsKVIAmAmMKoX0NzoBZQFWQng9wKmhQmAXgBmcIvtBbjjAP8g58ADfWXKOMCF21iC3CBAbMiFAHABzePH+2kgc3PgQHKaYxgHkJFAKDl1JPCMMyTjBgFKi6wEgKz5tya+x0sDmTcNG9a+niA1TQDZCYAMthLpU08NZaCHDHWPUI/KoEGA2JCVAJgLUIqsI1PmAvAmFo7fdJZVQdkJwEqGqd906aXh2cD+/Uln2pHaIEBsyEoA/t5ZuyY0Gygu+ufXuBY69f4UZCcAAwRQt84NEcDZYQeyl2ZYdeIRYOjQihEgznwrSWIhwLHHZiSAdNPfe490F/c4OUDWA9xztxujpdyfipwIIEx6cqE82MsEK4KsZ5+NZhkI0NpCzVddRQ6TwMGauhCGZ/gc9VsB9x7n/t/Wo0ekUPNFK/ep25+bigLKl/Zb6v+Be1l+eAOZA0ubgQDW758M7dbCZ/OZZ+IlgHr3XdKd3TWBAMhgZDmfpoULLOA4oaxgYeFqx7UmkJWBo/C855YVLD+su4iSLwD5WzNnhqxzomsXcpYsiW6cKciJALLqBP6+b9+QQK2zk4sO8EbNqHRccCwYKTu4vFgVrGNbFcytkQmA50bmV1KwbDMRAOTYupXMlADd3G+/eFcFi0lnH4Tz7IMZqf0GFH1MWUnAgnP3BcS3Khj7AqCQyPxKjgyRPOTODVOnNswxY5L7AjJbDg+5EYCBlq6mTw+bmtC5ANHpKgKfAB1gZ9Cr4XMCMEqL42Vz8f9AzgSQYOOFF0KZIQ4o9py6kqCDEAByN2fMCDdKhn71tZwbZc4EkP7munWkA/1NXNUJJ7hr1qtJOB2AAHBHOJRDDRvmlxN1tfbtn7P/B3InQHLM2TznnFCG9k47kV6xonE+QLnButAffkR2165+HTFmoM47LxmYb3sE0EPuBGBIHDB/fqjPKW7gvnuryw10AAKILtj9wuejjKgnzL+1cGFeusiLALJJ9Ouv5HXunmBxVUPdPQIVOxs4FfVOAIz/25rUoCNDerD22EMO8RA9RaWLQH4ESCSPKJswQcyNlzHeaoUXRVVNb6DOCSAB+csvpZ8SNnmS2/pzNP9AfgRgIHOd0huQzC+6KO/MS4Y6JgDeySiNcPz4UCOEPqxXX8m7EeZNALu1jRJKkTrsMF+4uOL8Wo3XmFRDMFjHBJAGuGSJbM4N1k0NHuTu4GL3EJUuE/InAAMMVPfe608OoQDoi6qrr64OK1CvBGC5ynuEpl4S6vsjKFcPPeTKPirdNlAAAbQ7N7B2bdprzXT37vJ6k1wOJigp6pQAYt6XLU07J9jqtw85OCqmgKN6CrIAgFiB6dOlG4JCAGClecmU5JnBLLCIdGVBPRKA85fWf/75odYvQ79z5hTU+oGCCSBdjW9Wk9XbfWcAAhJcdefOpN+u8Mlh9UaA5FtZ9Ruvy7nMXp1wVXhXQA6rfzOhYAJ47wzCm62DsQBgYni4jc1RpQRWbwTgwA7jLGbKsK/4/rvuKrj1A4VbAACxwI8/ktpv/xArpWD/XlhQEgvqjADibu+9xx+B9cplHnIoJWQLeOHH9BVHAIYU7onHQ+MCuMrJ1StXVsYV1AsBvLeyrlhB1i7tu7NxhbzV//yh6EZWNAFE2Ju3kHnaaf7ABIDPxsmjXVeQZ9+0aNQLAVh2WNlk/vSnabLFpJwE2yhXVNocUTwBGMLSjz8mK3CGAK7iCrz1AuUcG6gDAmDET6L+GTNDMRauqtdu5PjWtbgXdMRCAP8lkhiMSCms9ApefLFoU5UX6oAAkJf1zDNpUb/M+D06PzZ5xkIAAYTOhTLOPVf6qcFCy8sNl69wGYsXG0WljxM1TgCR04cfkdWrV0iOkKvxL+e7ysdi0Yi0+SI+AjAwD4A+qXnQQWlCxKFFibXrykOCWiVAMuhzvvmGjAMPTCuHefjh0uvKZ7o3G2IlACDsfOdtspIniqDguErgghMvsYq41CSoRQIkB3sS69eTOXSoyCsoP9WzB+n333cbUFT6AhE7AQCQQD32WFrXUM4VGD1a3jtYUktQawRItvxEUxMZHPGnulCst7CeXOhG/TG/lLMkBPAiWDX7lrSgECTA/gJYgrjZ7KOWCBBo+cYJJ6QpH/LDy6FE+SWYXykJAQStrAQutDFtWlo3BpU0jz+enDVrSkOCGiIAZASfbx5zTJry0Y02rr3WVX6JltuVjgBs1jCQ0cIBizlpUhoJJCY4fCDZy5aJEDK+dKIQ1AABUF+Jlz74kMyDD0rz+aL8yy7le7YWNdSbDaUjAAASbN4i69eNyZNDY9neFWcPWS/8nyuMuCpazQRA3IOGwfVFP9/afXfJI0r5LVs2FzzLlytKSwAAFWYrAEtgXHFFKCbwKozBDnXrrTJsDJeAgaXIZ+UKjwCHti9bKwbqyCNiIQDqhfph1685axZpfnaqLCAf/xheKL9UgXISpScAgEpwZSQwnDMn1DvwKi6sP+Vksj/91K28zB8UWHlWFgjQfM01ZI0aRdappxYMxek3XX89JRCAgQSpeeUKro/48hXLyTjppIBL7OTLANG+H/CV0OwHUR4CeEgKQf3ud2R16+ZX3LvCD6pevUj9+te+NShmDgFb1rCrGTtlCwbS52WGU0jL5Zcon4Nidd99ZO2ya5q/xxWzfWphsqsXh6vJEeUlAMcE3rJm+513yDz00FDk6wkEZtDkVqLffNMVCEM7Ec/LBrTYOFAICZOKR/nxbj9zxIhQDOTVVZZ0HXEE2e+/58qlzEvpykuAJLzJo8T335MxcUJkXIArTKI5ZQrZH69whSMCKuOsYiEIKn7pEjIvulDqEawXrgBcoXHhhZTYsEHSFB37FICKEECAuIArDcWqh/+D1G67hUyjJyhYCOw5MK+6kvRyt8sorqGMZjInsHsTU8/Qi5eQwhvTdtop0sKJq+vdm9T8R10Lt5XhB3sFxj0FonIE8MCKFCF88gkZZ5/tB4iu0NoDJCECC1RdcAHp114jh02lTwa8GiXq2aUGl91TOjZlWK+8TGriRNI77BipeAD1M8eNI+fzzyVdxcqeROUJkIQnSGvhAokNvCg5VYhoPRCi4j6+uvNO2SWD83t8MiBgK5UfRTyAwDJZVrwbEVu01W3zyDzqKClXlBUDUB/M5ll/cJdxSVmj8igzqoYAYvpakq16Y5O8lVT12TsjETyh2jt0JfO44+Qt2tYbb5C9fr2vIEDiBo7kpVvpBXSZ4gjvN9yH+5Eu8CxR2g8/kGILpGbMIHP4cHlfX7Yyqn36uat3m5vlOQiEI/OvAKqIAAFwKxOBf/ctmbfcTGrfff0IOkrIAKJpmTjhe60zTifj5lmkuLXZH3xAFuYcLEsUGCRHFLx7HEtJOvv998l86vdkzJxJ6rTTSPXrJ/kgv9TyBMuE8qoBPyHz1ltlFxWe7Q7sRNS3gqhOAnhAPxyC41ZnPvggqRQzGxS+97/3HVoelJDo3JmMPn1IDx5MevRo0uPHk5o2jTbdeCNtnDGTNrLl2MitedMNN8r3evw4uc8aNIjT7U2J7beX50DhUfkEv/Pck3n0P5F66DfkrN/glp/rEVm/KkB1E0DAJhmDMWiVHClbL/1Ruk44DAGKCSrAU0jwu1RASQjQoNBU4Hv8nim9++z2wBTA/SiHtddeZE6e7G7RZjfitvj4Vu6UCjVAgAACXS3729WyH8GcOIE0Xo7ASoACU5XnKi0ahd4HsiA/q39/2aunFiwge813LklRNsQPUeWvQtQWATwgUGOr4PtrDvzUyy+RNXs2GaefQTbea9y1q7RMkMJr2UFFZoNnKQD4fI3DsQcMIGPMGLLmziWF8/k2uCZelI6AMVNwWcWoTQIEAaEHu2YAtqt99BFZT/8vaY6+N119NamzxpI9dAg53MW02GKYvXeX9yA19+xJBl/N3r1JcwDpDDyM7xvK95/F6a4hffc9Mm2rFi+W5wbzcbuctaf0IGqfACGwMtDFSk4kecoKmmZ0xWyOytVXX5H5xRfyQixc8b+9dh0lDCPkanxSIT1m6KqoCxcH6owAGYBWCsVh+LiVlQiLwZG5AMrFFS4FLRr+G/chTeQEVG23+FR0DAI0kBENAnRwNAjQwdEgQAdHgwAdHA0CdHBsx72gOYzGX4f8I/p/m1jXvfgohIAAAAAASUVORK5CYII=')
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
    $sesion = Get-SesionActual $ctx
    $contenido = if ($sesion) {
        "<div class='hero'><h3>Bienvenido a $(Escapar $CompanyName)</h3><p>Consulta información relevante de tu atención desde tu cuenta.</p></div>"
    } else {
        "<div class='hero'><h3>Bienvenido a $(Escapar $CompanyName)</h3><p>Consulta información relevante de tu atención y realiza tu pre-registro como paciente.</p></div>"
    }
    $contenido += "<div class='card-grid'>"
    if ($sesion) {
        $contenido += "<a href='/mi-cuenta'><img src='/assets/home.png' alt='' aria-hidden='true'>Mi cuenta</a>"
        $contenido += "<a href='/ajustes'><img src='/assets/home.png' alt='' aria-hidden='true'>Ajustes</a>"
    } else {
        $contenido += "<a href='/registro'><img src='/assets/registro.png' alt='' aria-hidden='true'>Pre-registro</a>"
        $contenido += "<a href='/login'><img src='/assets/login.png' alt='' aria-hidden='true'>Iniciar sesión</a>"
    }
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
    $motivo = ""
    $correoReservado = $false
    $correoDuplicado = $false
    $faltantes = @()
    foreach ($campo in $requeridos) {
        if (-not $form.ContainsKey($campo) -or [string]::IsNullOrWhiteSpace($form[$campo])) { $faltantes += $campo }
    }
    if ($faltantes.Count -gt 0) { $motivo = "Faltan campos obligatorios: $($faltantes -join ', ')."; $falla = $true }
    if (-not $falla -and $form["email"].Length -gt 254) { $motivo = "El correo electrónico es demasiado largo."; $falla = $true }
    if (-not $falla -and $form["email"] -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]{2,}$') { $motivo = "El correo electrónico no tiene un formato válido."; $falla = $true }
    if (-not $falla -and ($form["password"].Length -lt 8 -or $form["password"].Length -gt 128)) { $motivo = "La contraseña debe tener entre 8 y 128 caracteres."; $falla = $true }
    if (-not $falla -and $form["nombre"].Length -gt 120) { $motivo = "El nombre es demasiado largo."; $falla = $true }
    if (-not $falla -and $form["telefono"] -notmatch '^[0-9+\-() ]{7,20}$') { $motivo = "El teléfono debe tener entre 7 y 20 caracteres y solo números, espacios o + - ( )."; $falla = $true }
    if (-not $falla -and $form["aseguradora_poliza"].Length -gt 200) { $motivo = "La aseguradora/póliza es demasiado larga."; $falla = $true }
    if (-not $falla -and $form["motivo_alergias"].Length -gt 1000) { $motivo = "El motivo de consulta/alergias es demasiado largo."; $falla = $true }
    if (-not $falla -and -not $Jurisdicciones.Contains($form["jurisdiccion"])) { $motivo = "Selecciona una jurisdicción válida."; $falla = $true }

    $fechaNac = [datetime]::MinValue
    if (-not $falla) {
        $formatoOk = [datetime]::TryParseExact($form["fecha_nacimiento"], "yyyy-MM-dd", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$fechaNac)
        if (-not $formatoOk) { $motivo = "La fecha de nacimiento debe tener formato AAAA-MM-DD."; $falla = $true }
        elseif ($fechaNac -gt (Get-Date)) { $motivo = "La fecha de nacimiento no puede ser futura."; $falla = $true }
    }

    # CORRECCIÓN H-07: sin consentimiento expreso no se persiste ningun dato.
    $consentido = $form.ContainsKey("consent") -and $form["consent"] -ieq "True"
    if (-not $falla -and -not $consentido) { $motivo = "Debes aceptar el aviso de privacidad para continuar."; $falla = $true }
    if (-not $falla) {
        $correoNormalizado = $form["email"].ToLowerInvariant()
        foreach ($correoRol in $RolesPorEmail.Keys) {
            if ($correoNormalizado -eq $correoRol.ToLowerInvariant()) { $correoReservado = $true; break }
        }
        if (-not $correoReservado -and @(Leer-Csv $UsersCsv | Where-Object { $_.Email -ieq $form["email"] }).Count -gt 0) { $correoDuplicado = $true }
    }
    if (-not $falla -and $correoReservado) { $falla = $true }
    if (-not $falla -and $correoDuplicado) { $falla = $true }

    if ($falla) {
        Registrar-Evento $ctx "REGISTRO_RECHAZADO" "/registro" $false "WARN"
        $mensajeFalla = if ($correoReservado) {
            "Ese correo pertenece a una cuenta predefinida; solicita la contraseña al administrador o usa otro correo."
        } elseif ($correoDuplicado) {
            "Ese correo ya está registrado. Inicia sesión con él o usa un correo diferente."
        } elseif ($motivo) {
            $motivo
        } else {
            "No se pudo completar el registro. Revisa los campos e inténtalo de nuevo."
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
        TotpSecret          = ""
        TotpActivado        = "False"
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

    # CORRECCIÓN H-02/C-13: segundo factor obligatorio para cuentas privilegiadas (R-02, R-03, R-04, R-07).
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
    $destino = Get-DestinoInicio $rol
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
    $destino = Get-DestinoInicio $pendiente.Rol
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
    if ($accion -eq "solicitar_arco") {
        if ($null -eq $u) {
            Enviar $ctx (Pagina-Error "Cuenta no encontrada" "No se encontró el registro de tu cuenta." $ctx) 404
            return
        }
        $email = if ($form.ContainsKey("email")) { $form["email"] } else { "" }
        if ($email -ine $sesion.Email) {
            Registrar-Evento $ctx "ARCO_SOLICITUD_RECHAZADA" "/ajustes" $false "WARN"
            Enviar $ctx (Pagina-Error "Solicitud rechazada" "Solo puedes ejercer derechos sobre tu propia cuenta." $ctx) 403
            return
        }
        $derecho = if ($form.ContainsKey("derecho")) { $form["derecho"] } else { "" }
        $motivo = if ($form.ContainsKey("motivo")) { $form["motivo"] } else { "" }
        $derechosValidos = @("Acceso", "Rectificación", "Cancelación", "Oposición")
        if ($derecho -notin $derechosValidos -or [string]::IsNullOrWhiteSpace($motivo) -or $motivo.Length -gt 500) {
            Registrar-Evento $ctx "ARCO_SOLICITUD_RECHAZADA" "/ajustes" $false "WARN"
            Enviar $ctx (Nueva-Pagina "Ajustes de la cuenta" (Formulario-Ajustes "Revisa el derecho solicitado y el motivo (máximo 500 caracteres)." $true $u $sesion.Email) $ctx) 400
            return
        }
        $solicitud = [ordered]@{
            Id                = [guid]::NewGuid().ToString()
            EmailSolicitante  = $sesion.Email
            NombreSolicitante = $u.Nombre
            Derecho           = $derecho
            Motivo            = $motivo
            Estado            = "PENDIENTE"
            FechaSolicitud    = Ahora
            FechaResolucion   = ""
            Resolutor         = ""
            Decision          = ""
            DetalleResolucion = ""
        }
        Agregar-Csv $ArcoSolicitudesCsv $solicitud
        Registrar-Evento $ctx "ARCO_SOLICITUD_CREADA" "/ajustes" $true
        $html = "<p class='ok'>Tu solicitud fue enviada al Departamento de Privacidad. Folio: <code>$(Escapar $solicitud.Id)</code>. Podrás ver el estado en el apartado de derechos ARCO.</p>"
        $html += "<p><a href='/ajustes#arco'>Ver seguimiento de mis solicitudes</a></p>"
        Enviar $ctx (Nueva-Pagina "Solicitud ARCO enviada" $html $ctx)
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

function Exigir-SesionPrivacidad($ctx, [string]$ruta = "/privacidad") {
    $sesion = Get-SesionActual $ctx
    if (-not $sesion) {
        Registrar-Evento $ctx "ACCESO_DENEGADO" $ruta $false "WARN"
        Redirigir $ctx "/login"
        return $null
    }
    if ($sesion.Rol -ne $RolPrivacidad) {
        Registrar-Evento $ctx "ACCESO_DENEGADO" $ruta $false "WARN"
        Enviar $ctx (Pagina-Error "403 Prohibido" "Tu rol no puede gestionar solicitudes ARCO." $ctx) 403
        return $null
    }
    return $sesion
}

function Leer-Parametros-Consulta($ctx) {
    $parametros = @{}
    foreach ($par in ($ctx.Request.Url.Query.TrimStart('?') -split '&')) {
        if (-not $par) { continue }
        $partes = $par -split '=', 2
        $clave = [System.Net.WebUtility]::UrlDecode($partes[0])
        $valor = if ($partes.Count -gt 1) { [System.Net.WebUtility]::UrlDecode($partes[1]) } else { "" }
        $parametros[$clave] = $valor
    }
    return $parametros
}

$Rutas["/privacidad"] = {
    param($ctx)
    $sesion = Exigir-SesionPrivacidad $ctx "/privacidad"
    if (-not $sesion) { return }
    if ($ctx.Request.HttpMethod -ne "GET") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Usa GET en esta ruta." $ctx) 405
        return
    }
    Registrar-Evento $ctx "PRIVACIDAD_VIEW" "/privacidad" $true
    $solicitudes = @(Leer-Csv $ArcoSolicitudesCsv)
    $pendientes = @($solicitudes | Where-Object { $_.Estado -eq "PENDIENTE" })
    $resueltas = @($solicitudes | Where-Object { $_.Estado -ne "PENDIENTE" })
    $html = "<p>Bandeja del Departamento de Privacidad (<code>$(Escapar $RolPrivacidad)</code>). Revisa cada solicitud, confirma que validaste la identidad y elige la resolución.</p>"
    $html += "<h3>Solicitudes pendientes</h3>"
    if ($pendientes.Count -eq 0) {
        $html += "<p>No hay solicitudes pendientes.</p>"
    } else {
        $html += "<div class='tabla-scroll'><table><thead><tr><th>Folio</th><th>Solicitante</th><th>Derecho</th><th>Motivo</th><th>Fecha</th><th>Resolución</th></tr></thead><tbody>"
        foreach ($s in $pendientes) {
            $id = Escapar $s.Id
            $html += "<tr><td><code>$id</code></td><td>$(Escapar $s.NombreSolicitante)<br>$(Escapar $s.EmailSolicitante)</td><td>$(Escapar $s.Derecho)</td><td>$(Escapar $s.Motivo)</td><td>$(Escapar $s.FechaSolicitud)</td>"
            $html += "<td><form method='post' action='/privacidad/resolver'>"
            $html += "<input type='hidden' name='id' value='$id'>"
            $html += "<label>Decisión <select name='decision' required><option value='eliminar'>Eliminar cuenta</option><option value='reporte'>Enviar reporte</option><option value='rechazar'>Rechazar petición</option></select></label>"
            $html += "<label>Motivo de la resolución <textarea name='detalle' maxlength='500' required></textarea></label>"
            $html += "<label><input type='checkbox' name='validado' value='1' required> Validé identidad y solicitud</label>"
            $html += "<button type='submit'>Aplicar decisión</button></form></td></tr>"
        }
        $html += "</tbody></table></div>"
    }
    $html += "<h3>Solicitudes resueltas</h3>"
    $html += Tabla-Html $resueltas @("Id", "EmailSolicitante", "Derecho", "Estado", "FechaResolucion", "Resolutor", "Decision", "DetalleResolucion")
    Enviar $ctx (Nueva-Pagina "Bandeja de Privacidad" $html $ctx)
}

$Rutas["/privacidad/resolver"] = {
    param($ctx)
    $sesion = Exigir-SesionPrivacidad $ctx "/privacidad/resolver"
    if (-not $sesion) { return }
    if ($ctx.Request.HttpMethod -ne "POST") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Usa POST en esta ruta." $ctx) 405
        return
    }
    $form = Leer-Formulario $ctx
    foreach ($clave in @($form.Keys)) { $form[$clave] = (($form[$clave] -replace '[\r\n]+', ' ')).Trim() }
    $id = if ($form.ContainsKey("id")) { $form["id"] } else { "" }
    $decision = if ($form.ContainsKey("decision")) { $form["decision"] } else { "" }
    $detalle = if ($form.ContainsKey("detalle")) { $form["detalle"] } else { "" }
    $validado = if ($form.ContainsKey("validado")) { $form["validado"] } else { "" }
    $decisiones = @("eliminar", "reporte", "rechazar")
    if ([string]::IsNullOrWhiteSpace($id) -or $decision -notin $decisiones -or
        [string]::IsNullOrWhiteSpace($detalle) -or $detalle.Length -gt 500 -or $validado -ne "1") {
        Registrar-Evento $ctx "ARCO_RESOLUCION_RECHAZADA" "/privacidad/resolver" $false "WARN"
        Enviar $ctx (Pagina-Error "Resolución no válida" "Confirma la validación, elige una decisión y escribe un motivo de hasta 500 caracteres." $ctx) 400
        return
    }
    $solicitudes = @(Leer-Csv $ArcoSolicitudesCsv)
    $indice = -1
    for ($i = 0; $i -lt $solicitudes.Count; $i++) {
        if ($solicitudes[$i].Id -eq $id -and $solicitudes[$i].Estado -eq "PENDIENTE") { $indice = $i; break }
    }
    if ($indice -lt 0) {
        Enviar $ctx (Pagina-Error "Solicitud no encontrada" "El folio no existe o ya fue resuelto." $ctx) 404
        return
    }
    $s = $solicitudes[$indice]
    $usuarios = @(Leer-Csv $UsersCsv)
    $u = @($usuarios | Where-Object { $_.Email -ieq $s.EmailSolicitante } | Select-Object -First 1)
    $s.Estado = "RESUELTA"
    $s.FechaResolucion = Ahora
    $s.Resolutor = $sesion.Email
    $s.Decision = $decision.ToUpperInvariant()
    $s.DetalleResolucion = $detalle
    $evento = ""
    $mensaje = ""
    if ($decision -eq "eliminar") {
        if ($u.Count -eq 1) {
            $resto = @($usuarios | Where-Object { $_.Email -ine $s.EmailSolicitante })
            Escribir-Csv $UsersCsv $EncabezadoUsuarios $resto
            $MetadatosAutorizados.Remove($s.EmailSolicitante.ToLowerInvariant()) | Out-Null
            Cerrar-Sesiones-De $s.EmailSolicitante
        }
        $evento = "ARCO_RESOLUCION_ELIMINAR_OK"
        $mensaje = "La cuenta del solicitante fue eliminada y sus sesiones cerradas."
    } elseif ($decision -eq "reporte") {
        $evento = "ARCO_RESOLUCION_REPORTE_OK"
        $mensaje = "El reporte fue generado. <a href='/privacidad/reporte?id=$(Escapar $s.Id)'>Descargar reporte</a>."
    } else {
        $evento = "ARCO_RESOLUCION_RECHAZO_OK"
        $mensaje = "La solicitud fue rechazada y el motivo quedó registrado para el solicitante."
    }
    Escribir-Csv $ArcoSolicitudesCsv $EncabezadoArco $solicitudes
    Registrar-Evento $ctx $evento "/privacidad/resolver" $true
    $html = "<p class='ok'>$mensaje</p><p><a href='/privacidad'>Volver a la bandeja</a></p>"
    Enviar $ctx (Nueva-Pagina "Solicitud ARCO resuelta" $html $ctx)
}

$Rutas["/privacidad/reporte"] = {
    param($ctx)
    $sesion = Exigir-SesionPrivacidad $ctx "/privacidad/reporte"
    if (-not $sesion) { return }
    if ($ctx.Request.HttpMethod -ne "GET") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Usa GET en esta ruta." $ctx) 405
        return
    }
    $parametros = Leer-Parametros-Consulta $ctx
    $id = if ($parametros.ContainsKey("id")) { $parametros["id"] } else { "" }
    if ($id -notmatch '^[0-9a-fA-F-]{36}$') {
        Enviar $ctx (Pagina-Error "Folio no válido" "El folio de la solicitud no es válido." $ctx) 400
        return
    }
    $s = @(Leer-Csv $ArcoSolicitudesCsv | Where-Object { $_.Id -eq $id -and $_.Decision -eq "REPORTE" } | Select-Object -First 1)
    if ($s.Count -ne 1) {
        Enviar $ctx (Pagina-Error "Reporte no disponible" "No existe una resolución de reporte para ese folio." $ctx) 404
        return
    }
    $datos = $s[0]
    $u = @(Leer-Csv $UsersCsv | Where-Object { $_.Email -ieq $datos.EmailSolicitante } | Select-Object -First 1)
    $fila = [ordered]@{
        Folio              = $datos.Id
        Nombre             = if ($u.Count -eq 1) { $u[0].Nombre } else { $datos.NombreSolicitante }
        Correo             = $datos.EmailSolicitante
        Derecho            = $datos.Derecho
        Motivo             = $datos.Motivo
        EstadoResolucion   = $datos.Estado
        FechaSolicitud     = $datos.FechaSolicitud
        FechaResolucion    = $datos.FechaResolucion
        Resolutor          = $datos.Resolutor
        DetalleResolucion  = $datos.DetalleResolucion
        FechaNacimiento    = if ($u.Count -eq 1) { $u[0].FechaNacimiento } else { "" }
        Telefono           = if ($u.Count -eq 1) { $u[0].Telefono } else { "" }
        Jurisdiccion       = if ($u.Count -eq 1) { $u[0].Jurisdiccion } else { "" }
        AseguradoraPoliza  = if ($u.Count -eq 1) { $u[0].AseguradoraPoliza } else { "" }
        MotivoAlergias     = if ($u.Count -eq 1) { $u[0].MotivoAlergias } else { "" }
        Consentimiento     = if ($u.Count -eq 1) { $u[0].Consentimiento } else { "" }
        FechaConsentimiento = if ($u.Count -eq 1) { $u[0].FechaConsentimiento } else { "" }
        VersionAviso       = if ($u.Count -eq 1) { $u[0].VersionAviso } else { "" }
        FechaRegistro      = if ($u.Count -eq 1) { $u[0].FechaRegistro } else { "" }
    }
    $lineas = @(@([pscustomobject]$fila) | ConvertTo-Csv -NoTypeInformation)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($lineas -join "`r`n"))
    Registrar-Evento $ctx "ARCO_REPORTE_DESCARGADO" "/privacidad/reporte" $true
    Enviar-Archivo $ctx $bytes "reporte-arco-$id.csv"
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
$servidor.Prefixes.Add("https://$($Direccion):$Puerto/")
$servidor.Prefixes.Add("http://$($Direccion):$PuertoRedireccion/")
try {
    $servidor.Start()
} catch {
    Write-Host "No se pudo iniciar el servidor. Ejecuta Configurar-Red.ps1 como administrador." -ForegroundColor Red
    throw
}

$urlsLan = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -ne '127.0.0.1' -and
    $_.PrefixOrigin -ne 'WellKnown' -and
    $_.InterfaceAlias -notmatch 'Tailscale'
} | ForEach-Object { "https://$($_.IPAddress):$Puerto/" }

Write-Host "=== $CompanyName | $AppVersion ==="
Write-Host "Escuchando HTTPS en todas las interfaces en el puerto $Puerto (HTTP $($PuertoRedireccion) redirige a HTTPS)"
Write-Host "URL principal: https://kuxtal.com/"
foreach ($url in $urlsLan) { Write-Host "Acceso LAN: $url" -ForegroundColor Cyan }
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
                Redirigir $ctx "https://$hostHeader$ruta$($ctx.Request.Url.Query)" 301
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
