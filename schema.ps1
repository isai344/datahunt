# =====================================================================
# schema.ps1 - Extracción de esquema: lista las columnas de cada CSV
# Uso:  .\schema.ps1
#       .\schema.ps1 -Carpeta C:\DataHunt
# Resultado: diccionario-borrador.csv (una fila por columna encontrada)
# =====================================================================
param(
    [string]$Carpeta = $(if (Test-Path "C:\DataHunt") { "C:\DataHunt" } else { $PSScriptRoot }),
    [string]$Salida  = (Join-Path $PSScriptRoot "diccionario-borrador.csv")
)

$ErrorActionPreference = "Stop"
$Carpeta = (Resolve-Path $Carpeta).Path
$SalidaDir = Split-Path $Salida -Parent
if (-not (Test-Path -LiteralPath $SalidaDir)) {
    New-Item -ItemType Directory -Path $SalidaDir -Force | Out-Null
}

$filas = @()
$numero = 1
$archivos = Get-ChildItem -Path $Carpeta -Filter *.csv -File | Where-Object { $_.FullName -ne $Salida }

foreach ($archivo in $archivos) {
    $registros = @(Import-Csv -Path $archivo.FullName -Encoding UTF8)
    # Los nombres de las columnas salen de la primera línea del archivo
    $primeraLinea = Get-Content -Path $archivo.FullName -TotalCount 1 -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($primeraLinea)) { continue }
    $columnas = ($primeraLinea -replace '"', '') -split ","

    Write-Host ""
    Write-Host "$($archivo.Name)  ($($registros.Count) registros)" -ForegroundColor Cyan

    foreach ($columna in $columnas) {
        $columna = $columna.Trim()
        if (-not $columna) { continue }
        # Cuántos registros tienen un valor en esta columna (sin mostrar el valor)
        $conValor = @($registros | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.$columna) }).Count
        Write-Host ("  {0,-25} {1} con valor" -f $columna, $conValor)

        $filas += [PSCustomObject][ordered]@{
            id            = "D-{0:D2}" -f $numero
            archivo       = $archivo.Name
            columna       = $columna
            con_valor     = $conValor
            descripcion   = ""
            origen        = ""
            tipo_dato     = ""
            clasificacion = ""
            finalidad     = ""
            base_legal    = ""
            conservacion  = ""
            dueno         = ""
        }
        $numero++
    }
}

$filas | Export-Csv -Path $Salida -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "Borrador guardado en $Salida ($($filas.Count) columnas)" -ForegroundColor Green
