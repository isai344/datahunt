# Restaura users.csv a partir de las fuentes originales SIN cambiar ninguna clave.
# - Cuentas privilegiadas: usuarios_a_cargar.csv (PasswordHash original, sin regenerar).
# - Empleados y pacientes: usuarios_a_cargar_empleados_pacientes.csv (PasswordHash original).
# NO imprime ni modifica PasswordHash, TotpSecret ni TotpActivado.
# Uso: pwsh -NoProfile -ExecutionPolicy Bypass -File C:\DataHunt\Restaurar-Usuarios.ps1
# AVISO: si users.csv ya tiene secretos TOTP, el script se niega a sobrescribirlos.
#        Solo con -Forzar y respaldo previo se puede continuar.
param(
    [string]$DataPath = 'C:\DataHunt',
    [switch]$OmitirVerificacion,
    [switch]$Forzar
)

$ErrorActionPreference = 'Stop'
$UsersCsv   = Join-Path $DataPath 'users.csv'
$AccessLog  = Join-Path $DataPath 'access_log.csv'
$PrivCsv    = Join-Path $DataPath 'usuarios_a_cargar.csv'
$EmpleadosCsv = Join-Path $DataPath 'usuarios_a_cargar_empleados_pacientes.csv'
$Encabezado = 'Id,Nombre,Email,PasswordHash,FechaNacimiento,Telefono,Jurisdiccion,AseguradoraPoliza,MotivoAlergias,Consentimiento,FechaConsentimiento,VersionAviso,FechaRegistro,TotpSecret,TotpActivado'
$VersionAviso = 'v2.1 (2026-11-26)'
$Iteraciones  = 600000

function Ahora { (Get-Date -Format 'o') }

function Test-Hash([string]$clave, [string]$guardado) {
    if ([string]::IsNullOrWhiteSpace($clave) -or [string]::IsNullOrWhiteSpace($guardado)) { return $false }
    $partes = $guardado -split ':', 2
    if ($partes.Count -ne 2) { return $false }
    try {
        $sal = [Convert]::FromBase64String($partes[0])
        $esperado = [Convert]::FromBase64String($partes[1])
        if ($sal.Length -ne 16 -or $esperado.Length -ne 32) { return $false }
        $claveBytes = [Text.Encoding]::UTF8.GetBytes($clave)
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $derive = [Security.Cryptography.Rfc2898DeriveBytes]::new(
                $claveBytes, $sal, $Iteraciones, [Security.Cryptography.HashAlgorithmName]::SHA256)
        } else {
            $derive = [Security.Cryptography.Rfc2898DeriveBytes]::new(
                $claveBytes, $sal, $Iteraciones, [Security.Cryptography.HashAlgorithm]::SHA256)
        }
        try { $calculado = $derive.GetBytes(32) } finally { $derive.Dispose() }
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            return [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($calculado, $esperado)
        }
        $diferencia = 0
        for ($i = 0; $i -lt 32; $i++) { $diferencia = $diferencia -bor ($calculado[$i] -bxor $esperado[$i]) }
        return ($diferencia -eq 0)
    } catch { throw "Error al verificar hash: $($_.Exception.Message)" }
}

function Obtener($fila, [string]$nombre, [string]$porDefecto) {
    $p = $fila.PSObject.Properties[$nombre]
    if ($null -eq $p -or [string]::IsNullOrWhiteSpace([string]$p.Value)) { return $porDefecto }
    return ([string]$p.Value).Trim()
}

function Proteger([string]$ruta) {
    try {
        $acl = Get-Acl -LiteralPath $ruta
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($regla in @($acl.Access)) { $acl.RemoveAccessRule($regla) | Out-Null }
        foreach ($id in @(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
            [Security.Principal.WindowsIdentity]::GetCurrent().User
        )) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($id, 'FullControl', 'Allow'))
        }
        Set-Acl -LiteralPath $ruta -AclObject $acl
    } catch { }
}

function Registrar([string]$evento, [bool]$exito) {
    $fila = [ordered]@{
        Fecha = Ahora
        Evento = $evento
        Ruta = 'Restaurar-Usuarios.ps1'
        Exito = [int]$exito
        Nivel = if ($exito) { 'INFO' } else { 'WARN' }
        IPAnonimizada = 'NO_REGISTRADA'
    }
    [pscustomobject]$fila | Export-Csv -LiteralPath $AccessLog -Append -NoTypeInformation -Encoding utf8
}

foreach ($ruta in @($PrivCsv,$EmpleadosCsv)) {
    if (-not (Test-Path -LiteralPath $ruta)) { throw "Falta archivo fuente: $ruta" }
}

# No destruir secretos TOTP generados por la app en sesiones posteriores.
$actuales = @(Import-Csv -LiteralPath $UsersCsv -Encoding utf8 -ErrorAction SilentlyContinue)
$conTotp = @($actuales | Where-Object { -not [string]::IsNullOrWhiteSpace($_.TotpSecret) }).Count
if ($conTotp -gt 0 -and -not $Forzar) {
    throw "users.csv contiene $conTotp secretos TOTP. Abortado para no borrarlos. Usa -Forzar solo con respaldo."
}

# Copia de seguridad del estado actual (aunque este vacio).
$backup = Join-Path $DataPath ("users_antes_restaurar_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
Copy-Item -LiteralPath $UsersCsv -Destination $backup -Force
Write-Host "[OK] Respaldo: $backup"

$ahora = Ahora
$registros = @()
$porEmail = @{}

# 1) Cuentas privilegiadas: se conserva el PasswordHash tal cual y los campos TOTP de la fuente.
foreach ($f in @(Import-Csv -LiteralPath $PrivCsv -Encoding utf8)) {
    $email = (Obtener $f 'Email' '').ToLowerInvariant()
    if (-not $email) { continue }
    if ($porEmail.ContainsKey($email)) { continue }
    if (-not $OmitirVerificacion -and -not (Test-Hash '12345678' (Obtener $f 'PasswordHash' ''))) {
        throw "Hash privilegiado no coincide con la clave documentada para $email. Abortado."
    }
    $porEmail[$email] = $true
    $registros += [pscustomobject][ordered]@{
        Id = [guid]::NewGuid().ToString()
        Nombre = Obtener $f 'Nombre' $email
        Email = $email
        PasswordHash = (Obtener $f 'PasswordHash' '')
        FechaNacimiento = Obtener $f 'FechaNacimiento' '1900-01-01'
        Telefono = Obtener $f 'Telefono' '0000000000'
        Jurisdiccion = Obtener $f 'Jurisdiccion' 'Otro'
        AseguradoraPoliza = Obtener $f 'AseguradoraPoliza' 'NO_APLICA'
        MotivoAlergias = Obtener $f 'MotivoAlergias' 'Carga masiva'
        Consentimiento = 'True'
        FechaConsentimiento = $ahora
        VersionAviso = $VersionAviso
        FechaRegistro = $ahora
        TotpSecret = Obtener $f 'TotpSecret' ''
        TotpActivado = Obtener $f 'TotpActivado' 'False'
    }
}
$privCount = $registros.Count

# 2) Empleados y pacientes: se conserva el PasswordHash original (no se regenera).
$omitidos = 0
foreach ($f in @(Import-Csv -LiteralPath $EmpleadosCsv -Encoding utf8)) {
    $email = (Obtener $f 'Email' '').ToLowerInvariant()
    if (-not $email) { $omitidos++; continue }
    if ($porEmail.ContainsKey($email)) { $omitidos++; continue }
    $hash = Obtener $f 'PasswordHash' ''
    $clave = Obtener $f 'Password' ''
    if (-not $OmitirVerificacion -and -not (Test-Hash $clave $hash)) {
        throw "Hash no coincide con la clave de $email. Abortado."
    }
    $porEmail[$email] = $true
    $registros += [pscustomobject][ordered]@{
        Id = [guid]::NewGuid().ToString()
        Nombre = Obtener $f 'Nombre' $email
        Email = $email
        PasswordHash = $hash
        FechaNacimiento = Obtener $f 'FechaNacimiento' '1900-01-01'
        Telefono = Obtener $f 'Telefono' '0000000000'
        Jurisdiccion = Obtener $f 'Jurisdiccion' 'Otro'
        AseguradoraPoliza = Obtener $f 'AseguradoraPoliza' 'NO_APLICA'
        MotivoAlergias = Obtener $f 'MotivoAlergias' 'Carga masiva'
        Consentimiento = 'True'
        FechaConsentimiento = $ahora
        VersionAviso = $VersionAviso
        FechaRegistro = $ahora
        TotpSecret = Obtener $f 'TotpSecret' ''
        TotpActivado = Obtener $f 'TotpActivado' 'False'
    }
}

if ($registros.Count -lt 80) { throw "Numero de usuarios inesperado: $($registros.Count). Abortado." }

$lineas = @($Encabezado) + @($registros | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1)
Set-Content -LiteralPath $UsersCsv -Value $lineas -Encoding utf8
Proteger $UsersCsv
Registrar 'USUARIOS_RESTAURADOS' $true

Write-Host "[OK] Restaurados $($registros.Count) usuarios (privilegiados: $privCount, empleados/pacientes: $($registros.Count - $privCount))."
Write-Host "[OK] Duplicados omitidos: $omitidos"
Write-Host "[OK] PasswordHash copiados sin modificacion. TotpSecret/TotpActivado copiados de la fuente."
Write-Host "[OK] users.csv protegido (SYSTEM, Administradores, usuario actual)."
