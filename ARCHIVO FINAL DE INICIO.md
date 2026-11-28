# ARCHIVO FINAL DE INICIO

**Data Hunt v2 — Hospital Integral Kuxtal**
Servidor: `SRV-HOSP-01` (dominio `KUXTAL.local`) · Fecha de cierre: **27/11/2026**

URL única para usuarios: **`https://kuxtal.com/`**
Alias equivalente: `https://hospitalkuxtal.com/`

> No se escribe IP ni puerto. El servidor escucha HTTPS en `443`; el puerto `80`
> solo redirige a HTTPS. El puerto `5990` pertenece a `MSStrgSvc` y **no se toca**.

---

## 1. Estado final de referencia

| Concepto | Valor |
|---|---|
| Certificado | `A5505BF4269ABD7D387B80E8B3D0ADC9C737BE9F` (vigente, también en Trusted Root local) |
| Enlace TLS | `0.0.0.0:443` y `[::]:443` con `AppId {B1E4A0F2-3C5D-4E67-9A80-1D2F3C4B5E6A}` |
| DNS | Zonas primarias `kuxtal.com` y `hospitalkuxtal.com`, registro A `@` y CNAME `www` |
| Redirección | `http://hospitalkuxtal.com/` → `301` → `https://hospitalkuxtal.com/` |
| Cuentas | `users.csv`: 82 filas, sin duplicados, 3 secretos TOTP preservados |
| SHA-256 `users.csv` | `009E62215FD47AA53FB6EC9C7C477616E80C41F6C97DEA0965E35CF10026997A` |
| `5990` | IPv4 `594BB96ECE5C0CDEA58BFA54A67C033E2B3D4C1B`, IPv6 `C0E0F9863A8A479508617C7C98050C0B6670C859` (sin cambios) |
| Tareas | `Kuxtal-DataHunt-Auto`, `Kuxtal-DNS-Actualizar`, `Kuxtal-DNS-Actualizar-Boot` activas; `Kuxtal-DataHunt` desactivada |
| Verificación maestra | **19/19 OK, `EXIT=0`** el 27/11/2026 16:42 |

---

## 2. En el servidor: una sola orden para iniciar todo

Abrir **PowerShell como administrador** en `SRV-HOSP-01`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\DataHunt\Inicializador-Maestro.ps1
```

O simplemente doble clic en:

```
C:\DataHunt\Inicializar-Sistema.cmd
```

El maestro es **idempotente**: se puede ejecutar las veces que haga falta. Primero
respalda en `C:\DataHunt\Backups-Maestro\<fecha>` y luego repara/verifica:

- certificado y enlace TLS en `443` (IPv4 e IPv6);
- URL ACL de `https://+:443/` y `http://+:80/`;
- reglas de firewall `DataHunt 443 TLS` y `DataHunt 80 TLS` (`Profile=Any`);
- DNS local y `hosts` del servidor para ambos dominios;
- `users.csv` (no reescribe cuentas ni secretos TOTP existentes);
- tareas programadas y arranque de la app si no está escuchando;
- regeneración de `Paquete-Cliente-Kuxtal.zip` y `Kit-Exposicion.zip`;
- comprobación final de 19 puntos, incluido **`5990` sin cambios**.

Al terminar debe aparecer:

```
SISTEMA LISTO. No hace falta IP ni puerto: abre kuxtal.com.
EXIT=0
```

### Opciones del maestro

```powershell
... -SoloVerificar            # diagnóstico sin cambiar nada (seguro para auditores)
... -ForzarIp 10.0.0.5        # fuerza la IP de los registros A y del hosts
... -Preferir 'Wi-Fi'         # elige interfaz; por defecto Ethernet > Wi-Fi
... -ModoExposicion           # modo escuela + genera el paquete del amigo
... -OmitirPaquetes           # no regenera los ZIP
... -OmitirTareas             # no re-registra tareas programadas
```

Atajos listos para usar:

- `C:\DataHunt\Inicializar-Sistema.cmd` → estado final normal.
- `C:\DataHunt\Verificar-Sistema.cmd` → solo lectura.
- `C:\DataHunt\Inicializar-Sistema-Expo.cmd` → modo escuela.

### Arranque automático

No hay que iniciar nada a mano después de un reinicio: la tarea
`Kuxtal-DataHunt-Auto` levanta la app y `Kuxtal-DNS-Actualizar` corrige la IP
cada 5 minutos (más `Kuxtal-DNS-Actualizar-Boot` al arrancar).

Si se detuviera la app manualmente:

```powershell
pwsh -File C:\DataHunt\Iniciar-DataHunt.ps1
```

---

## 3. Desde otra PC de la misma red (hospital)

Una sola vez por dispositivo:

1. Copiar y descomprimir `C:\DataHunt\Paquete-Cliente-Kuxtal.zip`
   (también en `C:\Hospital\TI\Paquete-Cliente-Kuxtal.zip`).
2. Ejecutar **`Configurar-Cliente-Kuxtal.ps1` como administrador** y aceptar UAC.
   Eso agrega el `hosts` e importa el certificado: desaparece el aviso
   “No es seguro”.
3. Abrir en el navegador: **`kuxtal.com`**. Sin `www`, sin IP y sin `:443`.

Comprobación en el cliente:

```powershell
Test-NetConnection 192.168.100.50 -Port 443
nslookup kuxtal.com
Invoke-WebRequest https://hospitalkuxtal.com/ -UseBasicParsing
```

Esperado: `TcpTestSucceeded : True`, IP `192.168.100.50` y `StatusCode 200`.

---

## 4. Modo escuela (servidor y amigo en el mismo Wi-Fi)

En el servidor, con el Wi-Fi de la escuela conectado:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\DataHunt\Inicializador-Maestro.ps1 -ModoExposicion -Preferir 'Wi-Fi'
```

O doble clic en `Inicializar-Sistema-Expo.cmd`. Si el script elige la IP equivocada:

```powershell
... -ModoExposicion -ForzarIp 192.168.15.23
```

Eso actualiza DNS/`hosts` a la IP de la escuela y genera:

```
C:\DataHunt\Expo\Paquete-Amigo-Expo.zip
```

Entregar ese ZIP al amigo. En su PC, ejecutar **`Configurar-Amigo.cmd` como
administrador** y abrir **`kuxtal.com`**. El paquete ya trae la IP nueva pegada;
no hace falta escribirla. Detalles en
`C:\DataHunt\Expo\INSTRUCCIONES-EXPO.txt`.

Si `Test-NetConnection <IP> -Port 443` da `False`, el Wi-Fi tiene aislamiento de
clientes: usar `Configurar-Amigo-Tailscale.cmd` (incluido) o un hotspot/router
compartido.

Al volver al hospital: ejecutar el maestro normal (sin `-ModoExposicion`) y que
el amigo vuelva a ejecutar `Configurar-Cliente-Kuxtal.ps1` con
`-ServidorIp 192.168.100.50`.

---

## 5. Pruebas funcionales ejecutadas (27/11/2026)

### 5.1 Inicio de sesión — cuentas no privilegiadas

Se usaron `PAC-001` y `EMP-0002` desde `credenciales_generadas.csv`.
**No se probó ninguna cuenta privilegiada** (`admin`, `dpo`, `admision`,
`privacidad`, etc.).

| Prueba | Resultado |
|---|---|
| `GET /login` | 200 |
| `POST /login` con credenciales correctas | 200 → sesión autenticada |
| `GET /mi-cuenta` con esa sesión | 200 y el correo de la cuenta aparece en la página |
| Evento en `access_log.csv` | `LOGIN_OK`, `Exito=1`, `Nivel=INFO` |
| Contraseña incorrecta | mensaje genérico “Correo o contraseña incorrectos.” y `LOGIN_OK`, `Exito=0` |

Repetible sin poner contraseñas en la consola:

```powershell
$base = 'https://hospitalkuxtal.com'
$cred = @(Import-Csv C:\DataHunt\credenciales_generadas.csv -Encoding utf8 |
          Where-Object { $_.ID -in @('PAC-001','EMP-0002') })
foreach ($c in $cred) {
    $s = $null
    Invoke-WebRequest "$base/login" -UseBasicParsing -SessionVariable s | Out-Null
    $r  = Invoke-WebRequest "$base/login" -UseBasicParsing -WebSession $s -Method Post `
          -Body @{ email = $c.Correo; password = $c.Contrasena }
    $mc = Invoke-WebRequest "$base/mi-cuenta" -UseBasicParsing -WebSession $s
    "{0}: login={1} mi-cuenta={2} emailVisible={3}" -f $c.ID, [int]$r.StatusCode, `
        [int]$mc.StatusCode, ($mc.Content -match [regex]::Escape($c.Correo))
}
```

### 5.2 Registro de una cuenta nueva

| Prueba | Resultado |
|---|---|
| `GET /registro` | 200 |
| `POST /registro` con consentimiento | 200, “Pre-registro creado correctamente.” |
| Usuarios | 82 → 83 |
| `PasswordHash` guardado | formato PBKDF2 `salt:hash`, **sin texto plano** |
| Secretos TOTP | 3 antes, 3 después (ninguno se regeneró) |
| Evento en bitácora | `REGISTRO_OK` |
| Login con la cuenta recién creada | 200 → `/mi-cuenta` 200 con el correo visible |

La cuenta de prueba se **eliminó** restaurando `users.csv` desde el respaldo:
volvió a 82 filas y al SHA-256
`009E62215FD47AA53FB6EC9C7C477616E80C41F6C97DEA0965E35CF10026997A`.
La bitácora `access_log.csv` conserva los eventos `LOGIN_OK`/`REGISTRO_OK` como
rastro de auditoría; no contiene correos, contraseñas ni datos de salud.

Plantilla controlada para repetir la prueba (genera un correo único y revierte
automáticamente solo `users.csv`):

```powershell
$ErrorActionPreference = 'Stop'
$base = 'https://hospitalkuxtal.com'
$resp = 'C:\DataHunt\Backups-Maestro\PruebasFinales_20261127\usersantes.csv'
New-Item -ItemType Directory -Path (Split-Path $resp) -Force | Out-Null
Copy-Item C:\DataHunt\users.csv $resp -Force
try {
    $g  = [guid]::NewGuid().ToString('N').Substring(0,10)
    $body = @{
        nombre='Prueba temporal'; email="verificacion.$g@kuxtal.test"
        password="Prueba-$g-A1!"; fecha_nacimiento='1990-01-15'
        telefono='+52 999 123 4567'; jurisdiccion='Estados Unidos - California'
        aseguradora_poliza='PRUEBA-123'; motivo_alergias='Prueba funcional'
        consent='True'
    }
    $s = $null
    Invoke-WebRequest "$base/registro" -UseBasicParsing -SessionVariable s | Out-Null
    $r = Invoke-WebRequest "$base/registro" -UseBasicParsing -WebSession $s -Method Post -Body $body
    "Alta=$([int]$r.StatusCode) Usuarios=$((@(Import-Csv C:\DataHunt\users.csv -Encoding utf8)).Count)"
} finally {
    Copy-Item $resp C:\DataHunt\users.csv -Force
    "Revertido=$((@(Import-Csv C:\DataHunt\users.csv -Encoding utf8)).Count) filas"
}
```

---

## 6. Verificación rápida en cualquier momento

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\DataHunt\Inicializador-Maestro.ps1 -SoloVerificar
```

O doble clic en `C:\DataHunt\Verificar-Sistema.cmd`. Deben salir los 19 puntos en
`OK` y `SISTEMA LISTO`.

Comandos puntuales:

```powershell
Resolve-DnsName kuxtal.com -Type A
Resolve-DnsName hospitalkuxtal.com -Type A
netsh http show sslcert
Get-NetTCPConnection -LocalPort 443,80 -State Listen
curl.exe -m 10 -s -o NUL -w '%{http_code} %{redirect_url}' http://hospitalkuxtal.com/
Get-FileHash C:\DataHunt\users.csv -Algorithm SHA256
Get-ScheduledTask -TaskName 'Kuxtal-*' | Select-Object TaskName,State
```

Bitácora del maestro: `C:\DataHunt\inicializador_maestro.log`.

---

## 7. Reglas que no se deben romper

1. **Nunca modificar ni reenlazar el puerto `5990`**; pertenece a `MSStrgSvc`.
2. **No cambiar contraseñas, `PasswordHash` ni secretos TOTP** de cuentas
   privilegiadas; no usar esas cuentas para pruebas.
3. No ejecutar `Restaurar-Usuarios.ps1` sin respaldo y sin `-Forzar`: la guardia
   anti-sobrescritura detiene la operación si detecta secretos TOTP.
4. El acceso preparado es **solo LAN**. HTTPS público requiere aprobación para
   túnel/redirección de puerto y certificado de CA pública.
5. Si `users.csv` llega a tener más de 82 filas por una prueba, restaurar desde
   `C:\DataHunt\Backups-Maestro\<fecha>\users.csv` y verificar el SHA-256.

---

## 8. Hashes de referencia

| Archivo | SHA-256 |
|---|---|
| `Inicializador-Maestro.ps1` | `B66153CD8FCCFD1F01FF9B46B6E280C49A8186F1C6BDB4B0685DDA219525F7E1` |
| `Paquete-Cliente-Kuxtal.zip` | `1C0CB46FC19426F6D566188077C9E8975C081BF33E94C987CD0F7912F22C13BC` |
| `Kit-Exposicion.zip` | `F5328B7820C8C1C71D58796DD8FDEF6DFCE76B5D8CBF320FFBFA50791545DE85` |
| `users.csv` (estado final) | `009E62215FD47AA53FB6EC9C7C477616E80C41F6C97DEA0965E35CF10026997A` |

Documentación adicional: `C:\DataHunt\adrian-emi.md` y
`C:\DataHunt\informe_para_emilio_20261127.txt`.
Reversión detallada: `C:\DataHunt\backup_kuxtalcom_20261127.txt`.
