param(
    [string]$Archivo = (Join-Path $PSScriptRoot "usuarios_a_cargar_v2.csv"),
    [string]$DataPath = "C:\DataHunt",
    [switch]$LimpiarPasswords
)

$ErrorActionPreference = "Stop"

$UsersCsv = Join-Path $DataPath "users.csv"
$AccessLogCsv = Join-Path $DataPath "access_log.csv"
$EncabezadoUsuarios = "Id,Nombre,Email,PasswordHash,FechaNacimiento,Telefono,Jurisdiccion,AseguradoraPoliza,MotivoAlergias,Consentimiento,FechaConsentimiento,VersionAviso,FechaRegistro,TotpSecret,TotpActivado"
$EncabezadoAccesos = "Fecha,Evento,Ruta,Exito,Nivel,IPAnonimizada"
$EncabezadoEntrada = "Nombre,Email,Password,PasswordHash,FechaNacimiento,Telefono,Jurisdiccion,AseguradoraPoliza,MotivoAlergias"
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
        Evento        = if ($exito) { "CONTRASENAS_ACTUALIZADAS" } else { "CONTRASENAS_RECHAZADAS" }
        Ruta          = "establecer-contrasenas.ps1"
        Exito         = [int]$exito
        Nivel         = if ($exito) { "INFO" } else { "WARN" }
        IPAnonimizada = "NO_REGISTRADA"
    }
    [pscustomobject]$registro | Export-Csv -LiteralPath $AccessLogCsv -Append -NoTypeInformation -Encoding utf8
    Set-ProteccionArchivo $AccessLogCsv
}

function Obtener-Valor($fila, [string]$nombre) {
    $propiedad = $fila.PSObject.Properties[$nombre]
    if ($null -eq $propiedad) { return "" }
    return ([string]$propiedad.Value).Trim()
}

if (-not (Test-Path -LiteralPath $Archivo)) { throw "No existe el archivo de carga: $Archivo" }

Inicializar-Csv

$entrada = @(Import-Csv -LiteralPath $Archivo -Encoding utf8)
$usuarios = @(Import-Csv -LiteralPath $UsersCsv -Encoding utf8)
$porEmail = @{}
foreach ($u in $usuarios) {
    if (-not [string]::IsNullOrWhiteSpace([string]$u.Email)) {
        $porEmail[([string]$u.Email).ToLowerInvariant()] = $u
    }
}

$actualizados = 0
$errores = @()
$filaNumero = 0

foreach ($fila in $entrada) {
    $filaNumero++

    $email = (Obtener-Valor $fila "Email").ToLowerInvariant()
    $password = Obtener-Valor $fila "Password"
    if (-not $email -or -not $password) { continue }

    if (-not $porEmail.ContainsKey($email)) {
        $errores += "Fila ${filaNumero}: usuario no existe: $email"
        continue
    }
    if ($password.Length -lt 8 -or $password.Length -gt 128) {
        $errores += "Fila ${filaNumero}: Password debe tener entre 8 y 128 caracteres"
        continue
    }

    $porEmail[$email].PasswordHash = Nuevo-HashContrasena $password
    $actualizados++
}

if ($errores.Count -gt 0) {
    Registrar-Evento $false
    throw "Carga cancelada. Errores:`n$($errores -join "`n")"
}

if ($actualizados -eq 0) {
    Registrar-Evento $false
    throw "No hay contrasenas para crear en $Archivo. Escribe una contrasena en la columna Password."
}

Escribir-Csv $UsersCsv $EncabezadoUsuarios $usuarios
Registrar-Evento $true

if ($LimpiarPasswords) {
    $limpios = @(foreach ($fila in $entrada) {
        if ($fila.PSObject.Properties['Password']) { $fila.Password = "" }
        $fila
    })
    Escribir-Csv $Archivo $EncabezadoEntrada $limpios
}

Write-Host "Contrasenas creadas/actualizadas: $actualizados."
