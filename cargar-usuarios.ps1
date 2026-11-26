param(
    [string]$Archivo = (Join-Path $PSScriptRoot "usuarios_a_cargar_v2.csv"),
    [string]$DataPath = "C:\DataHunt",
    [switch]$LimpiarPasswords
)

$ErrorActionPreference = "Stop"

$UsersCsv = Join-Path $DataPath "users.csv"
$AccessLogCsv = Join-Path $DataPath "access_log.csv"
$EncabezadoUsuarios = "Id,Nombre,Email,PasswordHash,FechaNacimiento,Telefono,Jurisdiccion,AseguradoraPoliza,MotivoAlergias,Consentimiento,FechaConsentimiento,VersionAviso,FechaRegistro"
$EncabezadoAccesos = "Fecha,Evento,Ruta,Exito,Nivel,IPAnonimizada"
$PrivacyPolicyVer = "v2.1 (2026-11-26)"
$IteracionesPbkdf2 = 600000

function Ahora { (Get-Date -Format 'o') }

function New-RandomBytes([int]$cantidad) {
    $bytes = [byte[]]::new($cantidad)
    $generador = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generador.GetBytes($bytes) } finally { $generador.Dispose() }
    return $bytes
}

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

function Test-HashValido([string]$guardado) {
    if ([string]::IsNullOrWhiteSpace($guardado)) { return $false }
    $partes = $guardado -split ':', 2
    if ($partes.Count -ne 2) { return $false }
    try {
        $sal = [Convert]::FromBase64String($partes[0])
        $hash = [Convert]::FromBase64String($partes[1])
        return ($sal.Length -eq 16 -and $hash.Length -eq 32)
    } catch { return $false }
}

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
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
    if (-not (Test-Path -LiteralPath $UsersCsv)) {
        Set-Content -LiteralPath $UsersCsv -Value $EncabezadoUsuarios -Encoding utf8
    }
    if (-not (Test-Path -LiteralPath $AccessLogCsv)) {
        Set-Content -LiteralPath $AccessLogCsv -Value $EncabezadoAccesos -Encoding utf8
    }
    Set-ProteccionArchivo $UsersCsv
    Set-ProteccionArchivo $AccessLogCsv
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

function Registrar-Evento([bool]$exito) {
    $registro = [ordered]@{
        Fecha         = Ahora
        Evento        = if ($exito) { "CARGA_MASIVA_OK" } else { "CARGA_MASIVA_FALLIDA" }
        Ruta          = "cargar-usuarios.ps1"
        Exito         = [int]$exito
        Nivel         = if ($exito) { "INFO" } else { "WARN" }
        IPAnonimizada = "NO_REGISTRADA"
    }
    [pscustomobject]$registro | Export-Csv -LiteralPath $AccessLogCsv -Append -NoTypeInformation -Encoding utf8
    Set-ProteccionArchivo $AccessLogCsv
}

function Obtener-Valor($fila, [string]$nombre, [string]$valorPorDefecto) {
    $propiedad = $fila.PSObject.Properties[$nombre]
    if ($null -eq $propiedad -or [string]::IsNullOrWhiteSpace([string]$propiedad.Value)) { return $valorPorDefecto }
    return ([string]$propiedad.Value).Trim()
}

if (-not (Test-Path -LiteralPath $Archivo)) { throw "No existe el archivo de carga: $Archivo" }

Inicializar-Csv

$entrada = @(Import-Csv -LiteralPath $Archivo -Encoding utf8)
$existentes = @(Import-Csv -LiteralPath $UsersCsv -Encoding utf8)
$porEmail = @{}
foreach ($u in $existentes) {
    if (-not [string]::IsNullOrWhiteSpace([string]$u.Email)) {
        $porEmail[([string]$u.Email).ToLowerInvariant()] = $true
    }
}

$nuevos = @()
$errores = @()
$filaNumero = 0

foreach ($fila in $entrada) {
    $filaNumero++

    $email = (Obtener-Valor $fila "Email" "").ToLowerInvariant()
    if (-not $email) {
        $errores += "Fila ${filaNumero}: Email vacio"
        continue
    }
    if ($porEmail.ContainsKey($email)) {
        $errores += "Fila ${filaNumero}: Email duplicado: $email"
        continue
    }
    if ($email -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]{2,}$') {
        $errores += "Fila ${filaNumero}: Email invalido: $email"
        continue
    }

    $password = Obtener-Valor $fila "Password" ""
    $passwordHash = Obtener-Valor $fila "PasswordHash" ""
    if ($password) {
        $passwordHash = Nuevo-HashContrasena $password
    }
    if (-not (Test-HashValido $passwordHash)) {
        $errores += "Fila ${filaNumero}: falta Password valido o PasswordHash en formato salt:hash"
        continue
    }

    $nombre = Obtener-Valor $fila "Nombre" ($email.Split('@')[0])
    $fechaNacimiento = Obtener-Valor $fila "FechaNacimiento" "1900-01-01"
    $telefono = Obtener-Valor $fila "Telefono" "0000000000"
    $jurisdiccion = Obtener-Valor $fila "Jurisdiccion" "Otro"
    $aseguradora = Obtener-Valor $fila "AseguradoraPoliza" "NO_APLICA"
    $motivo = Obtener-Valor $fila "MotivoAlergias" "Carga masiva"
    $fecha = Ahora

    $nuevos += [pscustomobject][ordered]@{
        Id                  = [guid]::NewGuid().ToString()
        Nombre              = $nombre
        Email               = $email
        PasswordHash        = $passwordHash
        FechaNacimiento     = $fechaNacimiento
        Telefono            = $telefono
        Jurisdiccion        = $jurisdiccion
        AseguradoraPoliza   = $aseguradora
        MotivoAlergias      = $motivo
        Consentimiento      = "True"
        FechaConsentimiento = $fecha
        VersionAviso        = $PrivacyPolicyVer
        FechaRegistro       = $fecha
    }

    $porEmail[$email] = $true
}

if ($errores.Count -gt 0) {
    Registrar-Evento $false
    throw "Carga cancelada. Errores:`n$($errores -join "`n")"
}

if ($nuevos.Count -eq 0) {
    Registrar-Evento $false
    throw "No hay usuarios nuevos para cargar en $Archivo"
}

Escribir-Csv $UsersCsv $EncabezadoUsuarios @($existentes + $nuevos)
Registrar-Evento $true

if ($LimpiarPasswords) {
    $limpios = @(foreach ($fila in $entrada) {
        if ($fila.PSObject.Properties['Password']) { $fila.Password = "" }
        $fila
    })
    Escribir-Csv $Archivo "Nombre,Email,Password,PasswordHash,FechaNacimiento,Telefono,Jurisdiccion,AseguradoraPoliza,MotivoAlergias" $limpios
}

Write-Host "Cargados $($nuevos.Count) usuarios. Total en users.csv: $($existentes.Count + $nuevos.Count)."
