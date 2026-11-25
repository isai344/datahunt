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

$EncabezadoUsuarios = "Id,Nombre,Email,PasswordHash,FechaNacimiento,Telefono,Jurisdiccion,AseguradoraPoliza,MotivoAlergias,Consentimiento,FechaConsentimiento,VersionAviso,FechaRegistro"
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
    Set-ProteccionArchivo $UsersCsv
    Set-ProteccionArchivo $AccessLogCsv
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
    $html = "<table><thead><tr>"
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
    return "$html</tbody></table>"
}

$css = @'
<style>
:root{color-scheme:light}body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f7fa;color:#17324d}
header{background:#0b4f6c;color:#fff;padding:14px 22px}header h1{margin:0;font-size:20px}header small{opacity:.85}
nav{background:#e2edf3;padding:9px 22px}nav a,nav button{margin-right:14px;font-size:14px}
main{max-width:960px;margin:22px auto;background:#fff;padding:22px;border-radius:8px;box-shadow:0 1px 5px #ccd6df}
label{display:block;margin:11px 0;font-weight:600}input,select,textarea{display:block;width:100%;max-width:520px;padding:8px;border:1px solid #9fb3c2;border-radius:4px;font:inherit}
textarea{min-height:88px}button{padding:9px 15px;background:#0b4f6c;color:#fff;border:0;border-radius:4px;cursor:pointer}
.aviso{background:#eef6fa;border-left:4px solid #0b4f6c;padding:12px;margin:16px 0}
.ccpa{background:#fff6e5;border-left:4px solid #c47f00;padding:12px;margin:16px 0}
table{border-collapse:collapse;width:100%;font-size:13px;margin:12px 0}th,td{border:1px solid #c9d6de;padding:6px;text-align:left;vertical-align:top}th{background:#e8f0f5}
.err{color:#a11212;font-weight:600}.ok{color:#116b2a;font-weight:600}code{word-break:break-all}footer{color:#5a7184;font-size:12px;margin-top:24px}
</style>
'@

function Nueva-Pagina([string]$titulo, [string]$contenido, $ctx = $null) {
    $nonce = Nuevo-Nonce
    $nav = "<a href='/'>Inicio</a><a href='/registro'>Registro</a><a href='/login'>Iniciar sesión</a><a href='/privacy'>Aviso de privacidad</a>"
    $sesion = if ($ctx) { Get-SesionActual $ctx } else { $null }
    if ($sesion -and $sesion.Rol -in $RolesAdmin) { $nav += "<a href='/admin'>Administración</a>" }
    if ($sesion) {
        $nav += "<a href='/mi-cuenta'>Mi cuenta</a><a href='/arco'>Derechos ARCO</a><a href='/ajustes'>Ajustes</a>"
        $nav += "<form method='post' action='/logout' style='display:inline'><button type='submit' style='margin:0;padding:4px 9px'>Cerrar sesión ($(Escapar $sesion.Rol))</button></form>"
    }
    $nombre = Escapar $CompanyName
    $version = Escapar $AppVersion
    return @"
<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>$(Escapar $titulo) - $nombre</title>$css</head><body>
<header><h1>$nombre</h1><small>Data Hunt $version | DEP-01 Admisión y Atención al Paciente</small></header>
<nav>$nav</nav><main><h2>$(Escapar $titulo)</h2>$contenido
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

function Formulario-Ajustes([string]$mensaje = "", [bool]$esError = $true) {
    $clase = if ($esError) { "err" } else { "ok" }
    $alerta = if ($mensaje) { "<p class='$clase'>$(Escapar $mensaje)</p>" } else { "" }
    return @"
$alerta<form method='post' action='/ajustes'>
<label>Contraseña actual <input type='password' name='password_actual' required autocomplete='current-password' maxlength='128'></label>
<label>Nueva contraseña <input type='password' name='password_nueva' required autocomplete='new-password' minlength='8' maxlength='128'></label>
<label>Confirmar nueva contraseña <input type='password' name='password_confirmacion' required autocomplete='new-password' minlength='8' maxlength='128'></label>
<button type='submit'>Guardar contraseña</button></form>
<p>La nueva contraseña debe tener entre 8 y 128 caracteres y ser diferente de la actual. Al guardarla se cierran todas las sesiones de la cuenta.</p>
<p>Si tu cuenta aún no tiene contraseña, solicítala al administrador.</p>
"@
}

function Pagina-Privacidad {
    # CORRECCIÓN H-07: aviso integral simplificado, transparente y adaptado a las 3 jurisdicciones.
    $plantilla = @'
<h3>1. Identidad y domicilio del responsable</h3>
<p>{COMPANY}, DEP-01 (Admisión y Atención al Paciente), con domicilio para efectos de aviso en Hospital Integral Kuxtal, Mérida, Yucatán, México. Contacto de privacidad: <strong>{CONTACTO}</strong>.</p>
<h3>2. Datos que recabamos</h3>
<p>Nombre, correo, contraseña (almacenada solo como hash PBKDF2-SHA256 con sal), fecha de nacimiento, teléfono, jurisdicción de residencia, aseguradora/póliza, motivo de consulta y alergias (dato sensible de salud), fecha y versión del consentimiento. No solicitamos datos financieros.</p>
<h3>3. Finalidades</h3>
<p>Pre-registro y atención al paciente, identificación de la aseguradora, triaje clínico básico y seguridad de la cuenta. No vendemos ni compartimos datos con fines comerciales.</p>
<h3>4. Transferencias y encargados</h3>
<p>Solo se comparten cuando lo exige la ley o con proveedores de infraestructura bajo contrato que prohibe cualquier uso distinto. No se realizan transferencias internacionales distintas de las necesarias para la operación del servicio.</p>
<h3>5. Derechos ARCO y revocación</h3>
<p>Puedes acceder, rectificar, cancelar u oponerte al tratamiento, así como revocar tu consentimiento, desde <a href='/arco'>la solicitud ARCO</a> o escribiendo a {CONTACTO}. La respuesta se da en los plazos que marca la ley aplicable.</p>
<h3>6. GDPR (Unión Europea)</h3>
<p>Base jurídica: consentimiento explícito (art. 6.1.a) y, para datos de salud, consentimiento expreso (art. 9.2.a). Conservamos los datos solo mientras sea necesario para la atención. Tienes derecho a portabilidad, limitación y a presentar reclamación ante la autoridad de control.</p>
<h3>7. CCPA (California)</h3>
<p id='ccpa'>No vendemos información personal. Si elegiste residir en California puedes ejercer <strong>Do Not Sell My Personal Information</strong> y solicitar la eliminación de tus datos mediante <a href='/arco'>el formulario de eliminación</a>. No discriminaremos por ejercer estos derechos.</p>
<h3>8. Conservación y seguridad</h3>
<p>Los registros se conservan únicamente durante el periodo de atención y se eliminan al solicitarlo. Aplicamos PBKDF2 con sal, comparación en tiempo constante, sesiones HttpOnly/SameSite=Strict, ACL restrictiva en los archivos, anonimización de IP y registro de eventos sin datos personales.</p>
<h3>9. Cambios al aviso</h3>
<p>Cualquier cambio se publica en esta misma página y se actualiza la versión del aviso; el consentimiento se vuelve a solicitar cuando el cambio es sustantivo. Versión vigente: {VERSION}.</p>
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

$Rutas["/"] = {
    param($ctx)
    $contenido = "<p>Bienvenido a $(Escapar $CompanyName): $(Escapar $AppVersion).</p>"
    $contenido += "<p>Registro de pacientes del departamento $(Escapar $CompanyName) - DEP-01.</p>"
    $contenido += "<p><a href='/registro'>Ir al pre-registro</a> | <a href='/login'>Iniciar sesión</a></p>"
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
        $html += "<a href='/privacy' target='_blank'>Consultar el aviso de privacidad integral (versión $(Escapar $PrivacyPolicyVer))</a>.</div>"
        $html += "<label><input type='checkbox' id='consent' name='consent' value='True' required> "
        $html += "D-13: Leí y acepto el aviso de privacidad y el tratamiento de mis datos, incluidos los de salud.</label>"

        # CORRECCIÓN H-05: metadatos no esenciales solo si el usuario lo autoriza expresamente.
        $html += "<label><input type='checkbox' id='metadata' name='metadata' value='True'> "
        $html += "D-14 (opcional): Autorizo registrar una IP anonimizada para detectar accesos no autorizados. "
        $html += "Si no marcas esta casilla no se registrará IP ni navegador.</label>"
        $html += "<button type='submit'>Crear pre-registro</button></form>"

        # CORRECCIÓN H-07: CCPA visible solo cuando se selecciona California (Estados Unidos - California).
        $html += "<div id='ccpa' class='ccpa' style='display:none'><strong>CCPA - California.</strong> "
        $html += "<a href='/privacy#ccpa'>Do Not Sell My Personal Information</a> | "
        $html += "<a href='/arco'>Solicitar eliminación de mis datos personales</a></div>"
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
        $html += "<div class='ccpa'><a href='/privacy#ccpa'>Do Not Sell My Personal Information</a> | "
        $html += "<a href='/arco'>Solicitar eliminación de mis datos personales</a></div>"
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
    Nueva-Sesion $ctx $usuario[0].Email $rol $autoriza | Out-Null
    $destino = if ($rol -in $RolesAdmin) { "/admin" } else { "/mi-cuenta" }
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

    if ($ctx.Request.HttpMethod -eq "GET") {
        Registrar-Evento $ctx "AJUSTES_VIEW" "/ajustes" $true
        Enviar $ctx (Nueva-Pagina "Ajustes de la cuenta" (Formulario-Ajustes) $ctx)
        return
    }
    if ($ctx.Request.HttpMethod -ne "POST") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Usa GET o POST en esta ruta." $ctx) 405
        return
    }

    $form = Leer-Formulario $ctx
    foreach ($clave in @($form.Keys)) { $form[$clave] = (($form[$clave] -replace '[\r\n]+', ' ')).Trim() }

    $actual = if ($form.ContainsKey("password_actual")) { $form["password_actual"] } else { "" }
    $nueva = if ($form.ContainsKey("password_nueva")) { $form["password_nueva"] } else { "" }
    $confirmacion = if ($form.ContainsKey("password_confirmacion")) { $form["password_confirmacion"] } else { "" }

    $rechazar = {
        param([string]$mensaje)
        Registrar-Evento $ctx "PASSWORD_CAMBIO_RECHAZADO" "/ajustes" $false "WARN"
        Enviar $ctx (Nueva-Pagina "Ajustes de la cuenta" (Formulario-Ajustes $mensaje) $ctx) 400
    }

    if ($actual.Length -lt 1 -or $actual.Length -gt 128) { & $rechazar "La contraseña actual no es válida."; return }
    if ($nueva.Length -lt 8 -or $nueva.Length -gt 128) { & $rechazar "La nueva contraseña debe tener entre 8 y 128 caracteres."; return }
    if ($nueva -cne $confirmacion) { & $rechazar "La confirmación de la nueva contraseña no coincide."; return }

    $usuarios = @(Leer-Csv $UsersCsv)
    $usuario = @($usuarios | Where-Object { $_.Email -ieq $sesion.Email } | Select-Object -First 1)
    if ($usuario.Count -ne 1) { & $rechazar "No se encontró la cuenta autenticada."; return }

    if (-not (Probar-Contrasena $actual $usuario[0].PasswordHash)) { & $rechazar "La contraseña actual es incorrecta."; return }
    if (Probar-Contrasena $nueva $usuario[0].PasswordHash) { & $rechazar "La nueva contraseña debe ser diferente de la actual."; return }

    $usuario[0].PasswordHash = Nuevo-HashContrasena $nueva
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

$Rutas["/privacy"] = {
    param($ctx)
    Enviar $ctx (Nueva-Pagina "Aviso de privacidad integral" (Pagina-Privacidad) $ctx)
}

$Rutas["/aviso"] = $Rutas["/privacy"]

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
    $html += "<p><a href='/arco'>Ejercer derechos ARCO (rectificar o eliminar)</a> | <a href='/ajustes'>Cambiar contraseña</a></p>"
    Enviar $ctx (Nueva-Pagina "Mi cuenta" $html $ctx)
}

$Rutas["/arco"] = {
    param($ctx)

    # CORRECCIÓN H-07 / C-15: canal ARCO (Acceso, Rectificación, Cancelación y Oposición) con verificación de sesión.
    $sesion = Get-SesionActual $ctx
    if (-not $sesion) {
        if ($ctx.Request.HttpMethod -eq "GET") {
            Enviar $ctx (Pagina-Error "Autenticación requerida" "Inicia sesión para ejercer tus derechos ARCO. <a href='/login'>Ir a /login</a>" $ctx) 401
        } else {
            Enviar $ctx (Pagina-Error "Autenticación requerida" "Inicia sesión primero." $ctx) 403
        }
        return
    }

    $usuarios = @(Leer-Csv $UsersCsv)
    $usuario = @($usuarios | Where-Object { $_.Email -ieq $sesion.Email } | Select-Object -First 1)
    if ($usuario.Count -ne 1) {
        Enviar $ctx (Pagina-Error "Cuenta no encontrada" "No se encontró el registro de tu cuenta." $ctx) 404
        return
    }
    $u = $usuario[0]

    if ($ctx.Request.HttpMethod -eq "GET") {
        $html = "<p>Ejerce tus derechos <strong>ARCO</strong> (LFPDPPP 2025 / GDPR / CCPA) sobre tu cuenta autenticada. Para consultar tus datos completos ve a <a href='/mi-cuenta'>Mi cuenta</a>.</p>"
        $html += "<h3>Rectificación de datos</h3>"
        $html += "<form method='post' action='/arco'>"
        $html += "<input type='hidden' name='email' value='$(Escapar $sesion.Email)'>"
        $html += "<label>Nombre completo <input type='text' name='nombre' maxlength='120' value='$(Escapar $u.Nombre)' required></label>"
        $html += "<label>Teléfono <input type='tel' name='telefono' maxlength='20' value='$(Escapar $u.Telefono)' required></label>"
        $html += "<label>Aseguradora y póliza <input type='text' name='aseguradora_poliza' maxlength='200' value='$(Escapar $u.AseguradoraPoliza)' required></label>"
        $html += "<label>Motivo de consulta y alergias <textarea name='motivo_alergias' maxlength='1000' required>$(Escapar $u.MotivoAlergias)</textarea></label>"
        $html += "<button type='submit' name='accion' value='rectificar'>Guardar rectificación</button></form>"
        $html += "<h3>Cancelación u oposición</h3>"
        $html += "<p>Esta acción elimina tus datos de pre-registro de Data Hunt y cierra tu sesión.</p>"
        $html += "<form method='post' action='/arco'>"
        $html += "<label>Correo de la cuenta <input type='email' name='email' value='$(Escapar $sesion.Email)' readonly></label>"
        $html += "<button type='submit' name='accion' value='cancelar'>Cancelar / oponerme al tratamiento y eliminar mis datos</button></form>"
        Enviar $ctx (Nueva-Pagina "Derechos ARCO" $html $ctx)
        return
    }
    if ($ctx.Request.HttpMethod -ne "POST") {
        Enviar $ctx (Pagina-Error "Método no permitido" "Usa GET o POST en esta ruta." $ctx) 405
        return
    }

    $form = Leer-Formulario $ctx
    foreach ($clave in @($form.Keys)) { $form[$clave] = (($form[$clave] -replace '[\r\n]+', ' ')).Trim() }
    $email = if ($form.ContainsKey("email")) { $form["email"] } else { "" }
    if ($email -ine $sesion.Email) {
        Registrar-Evento $ctx "ARCO_RECHAZADO" "/arco" $false "WARN"
        Enviar $ctx (Pagina-Error "Solicitud rechazada" "Solo puedes ejercer derechos sobre tu propia cuenta." $ctx) 403
        return
    }

    $accion = if ($form.ContainsKey("accion")) { $form["accion"] } else { "cancelar" }
    if ($accion -eq "rectificar") {
        $nombre = if ($form.ContainsKey("nombre")) { $form["nombre"] } else { "" }
        $telefono = if ($form.ContainsKey("telefono")) { $form["telefono"] } else { "" }
        $poliza = if ($form.ContainsKey("aseguradora_poliza")) { $form["aseguradora_poliza"] } else { "" }
        $motivo = if ($form.ContainsKey("motivo_alergias")) { $form["motivo_alergias"] } else { "" }
        if ([string]::IsNullOrWhiteSpace($nombre) -or $nombre.Length -gt 120 -or
            $telefono -notmatch '^[0-9+\-() ]{7,20}$' -or
            [string]::IsNullOrWhiteSpace($poliza) -or $poliza.Length -gt 200 -or
            [string]::IsNullOrWhiteSpace($motivo) -or $motivo.Length -gt 1000) {
            Registrar-Evento $ctx "ARCO_RECTIFICACION_RECHAZADA" "/arco" $false "WARN"
            Enviar $ctx (Pagina-Error "Datos inválidos" "Revisa los campos de rectificación e inténtalo de nuevo." $ctx) 400
            return
        }
        $u.Nombre = $nombre
        $u.Telefono = $telefono
        $u.AseguradoraPoliza = $poliza
        $u.MotivoAlergias = $motivo
        Escribir-Csv $UsersCsv $EncabezadoUsuarios $usuarios
        Registrar-Evento $ctx "ARCO_RECTIFICACION_OK" "/arco" $true
        $html = "<p class='ok'>Tu solicitud de rectificación fue aplicada correctamente.</p>"
        $html += "<p><a href='/mi-cuenta'>Ver mis datos actualizados</a> | <a href='/'>Volver al inicio</a></p>"
        Enviar $ctx (Nueva-Pagina "Rectificación ARCO aplicada" $html $ctx)
        return
    }

    $resto = @($usuarios | Where-Object { $_.Email -ine $email })
    Escribir-Csv $UsersCsv $EncabezadoUsuarios $resto
    $MetadatosAutorizados.Remove($email.ToLowerInvariant()) | Out-Null
    Registrar-Evento $ctx "ARCO_CANCELACION_OK" "/arco" $true
    Cerrar-Sesion $ctx
    $html = "<p class='ok'>Tu solicitud de cancelación/oposición fue registrada, los datos fueron eliminados y tu sesión se cerró.</p>"
    $html += "<p><a href='/'>Volver al inicio</a></p>"
    Enviar $ctx (Nueva-Pagina "Solicitud ARCO atendida" $html $ctx)
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
