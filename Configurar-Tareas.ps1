# Tareas programadas para kuxtal.com / Data Hunt v2.
# Ejecutar con Windows PowerShell como administrador.
$ErrorActionPreference = 'Stop'

$ps51  = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$pwsh7 = 'C:\Program Files\PowerShell\7\pwsh.exe'
if (-not (Test-Path $pwsh7)) { $pwsh7 = 'powershell.exe' }

# 1) DNS: cada 5 minutos, corrige la IP si cambia Wi-Fi / Ethernet / DHCP.
$accionDns = New-ScheduledTaskAction -Execute $ps51 `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\DataHunt\Actualizar-DnsKuxtal.ps1"'
$triggerCiclo = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
Register-ScheduledTask -TaskName 'Kuxtal-DNS-Actualizar' -Action $accionDns `
    -Trigger $triggerCiclo -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Write-Host '[OK] Tarea Kuxtal-DNS-Actualizar (cada 5 min)'

# 2) DNS: al arrancar el servidor.
$triggerBoot = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName 'Kuxtal-DNS-Actualizar-Boot' -Action $accionDns `
    -Trigger $triggerBoot -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Write-Host '[OK] Tarea Kuxtal-DNS-Actualizar-Boot (al arrancar)'

# 3) App: al arrancar, 1 minuto despues (espera a red y DNS).
$accionApp = New-ScheduledTaskAction -Execute $pwsh7 `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\DataHunt\Iniciar-DataHunt.ps1"'
$triggerApp = New-ScheduledTaskTrigger -AtStartup
try { $triggerApp.Delay = 'PT1M' } catch { Write-Warning 'No se pudo aplicar retardo de 1 min al arranque' }
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'Kuxtal-DataHunt-Auto' -Action $accionApp `
    -Trigger $triggerApp -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Write-Host '[OK] Tarea Kuxtal-DataHunt-Auto (al arrancar, +1 min, reintenta 3 veces)'

Get-ScheduledTask -TaskName 'Kuxtal-*' | Select-Object TaskName, State | Format-Table -AutoSize
