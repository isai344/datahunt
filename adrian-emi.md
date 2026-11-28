# Data Hunt v2 — Adrian / Emilio

Documento de entrega: **cambios realizados y estado actual de Data Hunt v2**
en `SRV-HOSP-01` (dominio `kuxtal.local`). Fecha de cierre: **27/11/2026**.

URL principal: **https://hospitalkuxtal.com/** · Alias: **https://kuxtal.com/**

---

## 0. Inicializador maestro (una sola orden)

Guía operativa completa: **`C:\DataHunt\ARCHIVO FINAL DE INICIO.md`**.

Para dejar —o volver a dejar— **todo el sistema** en el estado acordado,
ejecuta como administrador en `SRV-HOSP-01`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\DataHunt\Inicializador-Maestro.ps1
```

También puedes hacer doble clic en **`C:\DataHunt\Inicializar-Sistema.cmd`**.

El maestro es **idempotente**: respalda en `C:\DataHunt\Backups-Maestro\<fecha>`,
repara certificado, URL ACL, firewall, DNS/hosts, tareas, app y paquetes, y
después verifica 19 puntos. Entre ellos, confirma que `5990` conserva sus dos
certificados originales y que `users.csv` mantiene sus 3 secretos TOTP. **No
prueba cuentas privilegiadas.**

Opciones:

```powershell
... -SoloVerificar              # diagnóstico sin cambiar nada
... -ForzarIp 10.0.0.5          # fuerza la IP de DNS y hosts
... -Preferir 'Wi-Fi'           # elige interfaz (defecto: Ethernet > Wi-Fi)
... -ModoExposicion             # modo escuela + paquete del amigo
... -OmitirPaquetes / -OmitirTareas
```

Atajos: `Verificar-Sistema.cmd` y `Inicializar-Sistema-Expo.cmd`.

Ejecución de referencia **27/11/2026 16:36 → 19/19 OK, `EXIT=0`**. La tarea
antigua `Kuxtal-DataHunt` (con `svc_datahunt$` inexistente) quedó desactivada
y `Kuxtal-DataHunt-Auto` sigue activa. Bitácora:
`C:\DataHunt\inicializador_maestro.log`.

SHA-256 de referencia:

| Archivo | SHA-256 |
|---|---|
| `Inicializador-Maestro.ps1` | `B66153CD8FCCFD1F01FF9B46B6E280C49A8186F1C6BDB4B0685DDA219525F7E1` |
| `Paquete-Cliente-Kuxtal.zip` | `1C0CB46FC19426F6D566188077C9E8975C081BF33E94C987CD0F7912F22C13BC` |
| `Kit-Exposicion.zip` | `F5328B7820C8C1C71D58796DD8FDEF6DFCE76B5D8CBF320FFBFA50791545DE85` |

---

## Cómo iniciar el servicio y acceder

### En el servidor (local)

La app **arranca sola al reiniciar** mediante la tarea `Kuxtal-DataHunt-Auto`.
Si la detuviste manualmente, levántala con:

```powershell
pwsh -File C:\DataHunt\Iniciar-DataHunt.ps1
```

El lanzador valida certificado, ACL, firewall y puerto, y confirma HTTP 200.
Para entrar, abre en el navegador del servidor: **https://hospitalkuxtal.com/**
(`http://hospitalkuxtal.com/` redirige a HTTPS; `https://kuxtal.com/` también funciona).

### Desde otra computadora de la misma red (LAN)

1. El servicio debe estar levantado en el servidor (paso anterior).
2. Copia a la PC cliente el paquete (contiene el script, el certificado de
   respaldo y `INSTRUCCIONES.txt`). Está en dos lugares:

   - En el servidor: `C:\DataHunt\Paquete-Cliente-Kuxtal.zip`
   - Accesible por red desde tu PC:
     `\\SRV-HOSP-01\TI\Paquete-Cliente-Kuxtal.zip` (recurso `TI`, permiso de
     lectura para `KUXTAL\GG_TI` y Administradores).

   Descomprímelo en la otra PC y, **como administrador**, ejecuta **una sola
   vez** en esa carpeta:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configurar-Cliente-Kuxtal.ps1
```

   Si ya tienes acceso a `C:\DataHunt` en esa PC, también puedes usar la ruta
   completa `C:\DataHunt\Configurar-Cliente-Kuxtal.ps1`.

Ese script hace dos cosas: agrega los dominios al `hosts` **e importa el
certificado como Autoridad de Certificación Raíz de confianza**. Por eso
desaparece el aviso *"No es seguro"*.

3. Abre **https://hospitalkuxtal.com/** (o `https://kuxtal.com/`). Ya no hace
   falta escribir IP ni puerto. Tampoco sale el aviso si entras por
   `https://192.168.100.50/`, porque la IP está incluida en el certificado.

- Si el dispositivo entra por Tailscale en vez de la LAN:
  `powershell.exe -ExecutionPolicy Bypass -File C:\DataHunt\Configurar-Cliente-Kuxtal.ps1 -ServidorIp 100.109.230.106`
- Prueba rápida: `Test-NetConnection 192.168.100.50 -Port 443` → `TcpTestSucceeded : True`.
- **El puerto 5000 ya no se usa.** Usa siempre el dominio (o HTTPS en 443).
- Si la IP del servidor cambia (Wi‑Fi/DHCP), vuelve a ejecutar el paso 2 en la PC cliente.

> ¿Por qué salía el aviso antes? Por dos razones: entrabas por **IP** (el
> certificado era solo para `kuxtal.com`) y la laptop **no confiaba** en el
> certificado autofirmado. Ya están corregidas ambas.

Opcional: iniciar el servicio de forma remota desde otra PC con WinRM:

```powershell
Invoke-Command -ComputerName SRV-HOSP-01 -ScriptBlock { pwsh -File C:\DataHunt\Iniciar-DataHunt.ps1 }
```

---

## 1. Estado actual (al cierre)

| Concepto | Estado |
|---|---|
| URL de acceso | `https://hospitalkuxtal.com/` → **HTTP 200**, título *Inicio - Hospital Integral Kuxtal* |
| Redirección | `http://hospitalkuxtal.com/` → **301** a `https://hospitalkuxtal.com/` |
| Alternativas | `https://kuxtal.com/`, `https://www.hospitalkuxtal.com/`, `https://www.kuxtal.com/`, `https://srv-hosp-01/`, `https://192.168.100.50/` (sin aviso si se ejecutó el script de cliente) |
| Proceso de la app | `pwsh.exe` PID **3028** (verificar con `Get-CimInstance Win32_Process \| Where CommandLine -match 'app\.ps1'`) |
| Puertos en escucha | **443** (HTTPS) y **80** (solo redirección). El **5000 ya no escucha** |
| Certificado | `CN=hospitalkuxtal.com`, thumbprint `A5505BF4269ABD7D387B80E8B3D0ADC9C737BE9F`, SAN `hospitalkuxtal.com` / `www.hospitalkuxtal.com` / `kuxtal.com` / `www.kuxtal.com` / `srv-hosp-01` **+ IP 192.168.100.50, 192.168.100.61 y 100.109.230.106**, SHA-256, RSA 2048, EKU Server Authentication, vigencia 2 años |
| TLS | Enlazado en `0.0.0.0:443` y `[::]:443`, AppID `{B1E4A0F2-3C5D-4E67-9A80-1D2F3C4B5E6A}` |
| Confianza | Certificado en `Cert:\LocalMachine\Root` del servidor, publicado en Trusted Root de AD y **embebido en `Configurar-Cliente-Kuxtal.ps1`** para importarlo en cada laptop |
| DNS | Zonas primarias `hospitalkuxtal.com` y `kuxtal.com` en este DC; registro A `@` → `192.168.100.50`; CNAME `www` en ambas |
| Resolución local | Entrada en `hosts`: `192.168.100.50 kuxtal.com www.kuxtal.com hospitalkuxtal.com www.hospitalkuxtal.com` |
| URL ACL | `https://+:443/` y `http://+:80/` para `SYSTEM` y `KUXTAL\adm.isai` |
| Firewall | Reglas entrantes `DataHunt 443 TLS` y `DataHunt 80 TLS`, TCP, `Remote=Any`, perfil Any |
| Puerto 5990 | **Intacto**, pertenece a `MSStrgSvc` (Windows Standards-Based Storage Management). No tocar |
| Certificados viejos | `CN=localhost` y `CN=msstrgsvc` intactos en `Cert:\LocalMachine\My` |
| Arranque automático | Tarea `Kuxtal-DataHunt-Auto` (SYSTEM, al arrancar +1 min, 3 reintentos) |
| DNS dinámico | Tareas `Kuxtal-DNS-Actualizar` (cada 5 min) y `Kuxtal-DNS-Actualizar-Boot` (al arrancar). Log: `C:\DataHunt\dns_update.log` |
| Bitácora | `C:\DataHunt\access_log.csv` con intentos de login fallidos (`Exito=0`, `Nivel=WARN`) |
| Usuarios | `users.csv`: **82 cuentas** (4 privilegiadas, 58 empleados, 20 pacientes), hashes originales sin cambios. SHA-256 vigente: `009E6221…26997A` (cambió por enrolamientos MFA posteriores, ver fase 5) |
| Restaurador | `Restaurar-Usuarios.ps1` (idempotente, valida los 82 hashes antes de escribir y respalda el archivo anterior) |

---

## 2. Cambios realizados (cronología)

### Fase 1 — Diagnóstico y reversión del error TLS
1. Diagnóstico de solo lectura: `netsh http show sslcert`, inspección de certificados,
   `netsh http show servicestate`, revisión de `app.ps1`, tarea programada y ACL.
2. Respaldo `C:\DataHunt\ssl_5990_backup_20261127.txt` con thumbprints, AppIDs y
   comandos de reversión. Aviso previo al canal técnico.
3. Reenlace autorizado de `[::]:5990` al certificado `CN=localhost`; al detectar que
   el puerto pertenece a `MSStrgSvc`, **se revirtió de inmediato** a su estado original
   (`c0e0f986…0c859`, AppID `{468e21d1-…2086f}`). Los certificados no se borraron.

### Fase 2 — Arranque HTTP y validación funcional
4. App levantada en `http://localhost:5000/` y accesible por todas las IPs locales
   (`192.168.100.50`, `192.168.100.61`, Tailscale y nombre del servidor) → HTTP 200.
5. 4 intentos fallidos de login → 4 filas nuevas en `access_log.csv`
   (`Evento=LOGIN_OK`, `Ruta=/login`, `Exito=0`, `Nivel=WARN`).
6. URL ACL de `http://+:5000/` ampliada para incluir a `KUXTAL\adm.isai`,
   conservando a `KUXTAL\adm.adrian`. Sin esto la app solo arrancaba elevada.
7. Creado `Iniciar-DataHunt.ps1`: valida PowerShell 7, archivos, ACL, firewall y
   puerto, arranca `app.ps1` y confirma HTTP 200.

### Fase 3 — Publicación con dominio y TLS
8. Creado certificado autofirmado `CN=kuxtal.com` con SAN, EKU Server Authentication,
   KeyUsage DigitalSignature+KeyEncipherment, SHA-256/2048, vigencia 2 años.
   Exportado a `C:\DataHunt\kuxtal.com.cer`, importado en Root local y publicado en AD.
9. TLS enlazado en 443 (IPv4 e IPv6), URL ACL y firewall para 443 y 80.
10. Creada zona DNS `kuxtal.com`. No se pudo integrar en AD
    (`DNS_ERROR_DP_DOES_NOT_EXIST`, código 9901), por lo que se creó como
    **primaria local (archivo)**; con un solo DC es equivalente en la práctica.
11. `app.ps1` modificado:
    - `$Puerto = 443`, `$PuertoRedireccion = 80`, `$ExigirHttps = $true`.
    - Prefijos `https://+:443/` y `http://+:80/`.
    - Redirección 301 que conserva la querystring.
    - `Escribir-Cuerpo()` para que las peticiones HEAD no envíen cuerpo
      (evitaba que `curl -I` se colgara esperando `Content-Length`).
12. Creadas tareas programadas: arranque automático de la app, actualización de DNS
    cada 5 minutos y al arrancar.
13. Creado `Actualizar-DnsKuxtal.ps1`: elige Ethernet > Wi-Fi > otra IP LAN, ignora
    Tailscale y APIPA, y actualiza el registro A **y el `hosts` del servidor**.
14. Creado `Configurar-Cliente-Kuxtal.ps1` para las PCs (opción `-SetDns`).
15. Documentación: `adrian-emi.md` (este archivo), `informe_para_emilio_20261127.txt`
    y `backup_kuxtalcom_20261127.txt`.

### Fase 4 — Nombre `hospitalkuxtal.com` y fin del aviso "No es seguro"
16. Creado certificado nuevo `CN=hospitalkuxtal.com`, thumbprint
    `A5505BF4269ABD7D387B80E8B3D0ADC9C737BE9F`, con SAN que incluye ambos
    dominios, sus `www`, `srv-hosp-01` **y las IP** `192.168.100.50`,
    `192.168.100.61` y `100.109.230.106`. SHA-256/2048, EKU Server
    Authentication, vigencia 2 años. Exportado a
    `C:\DataHunt\hospitalkuxtal.com.cer`, importado en Root local y publicado
    en Trusted Root de AD. Certificado anterior conservado, no borrado.
17. Reenlazado TLS en `0.0.0.0:443` y `[::]:443` al certificado nuevo, con el
    mismo AppID. `kuxtal.com` sigue funcionando porque está en el SAN.
18. Creada zona DNS `hospitalkuxtal.com` con A `@` → `192.168.100.50` y
    CNAME `www`. `Actualizar-DnsKuxtal.ps1` ahora mantiene **ambas zonas** y
    la entrada del `hosts` del servidor con los cuatro nombres.
19. `Configurar-Cliente-Kuxtal.ps1` reescrito: agrega los dominios al `hosts`
    del cliente **e importa el certificado en Trusted Root**, con lo que
    desaparece el aviso del navegador. Sin `-SetDns` no se toca el DNS del
    cliente; con `-SetDns` se añade al servidor como DNS primario.
20. Actualizados `Configurar-KuxtalCom.ps1` (idempotente, ya no revierte el
    certificado nuevo), `Iniciar-DataHunt.ps1` (verifica ambos dominios) y
    este documento.

### Fase 5 — Restauración de cuentas (rechazo de login)
21. Diagnóstico: `users.csv` tenía **solo el encabezado** (190 bytes), por eso
    se rechazaban todas las credenciales de pacientes y empleados.
22. Verificación previa: los 79 hashes de
    `usuarios_a_cargar_empleados_pacientes.csv` coinciden con las contraseñas
    de `credenciales_generadas.csv`, y los 4 hashes de
    `usuarios_a_cargar.csv` coinciden con `12345678`. No se regeneró ninguno.
23. Creado `Restaurar-Usuarios.ps1`: copia los `PasswordHash` **tal cual**,
    respalda el archivo anterior, valida los hashes, detecta duplicados y
    protege el CSV con ACL. Se ejecutó con PowerShell 7.
24. Resultado: 82 cuentas (4 privilegiadas + 58 empleados + 20 pacientes).
    Se omitió 1 duplicado (`privacidad@kuxtal.test`, que aparece en ambas
    fuentes con la misma clave); se conservó la versión privilegiada.
25. **Cuentas privilegiadas**: el restaurador conservó sus `PasswordHash` y
    copió los campos TOTP vacíos de la fuente; este procedimiento no probó
    esas cuentas. **Actualización 16:23:** con posterioridad se registraron
    accesos desde la app entre las 15:45 y las 15:52 (`MFA_ACTIVADA` en tres
    ocasiones). Quedaron con un secreto TOTP generado por el propio formulario
    `dpo@kuxtal.test`, `admision@kuxtal.test` y `privacidad@kuxtal.test`;
    `admin@kuxtal.test` sigue sin secreto. No se imprimió ni cambió ningún
    `PasswordHash`. `users.csv` pasó a 31 567 bytes y su SHA-256 vigente es
    `009E62215FD47AA53FB6EC9C7C477616E80C41F6C97DEA0965E35CF10026997A`.
    El propio `Restaurar-Usuarios.ps1` ahora se niega a sobrescribir si detecta
    secretos TOTP (solo continúa con `-Forzar` y respaldo previo).

### Fase 6 — Kit para exposición en otra red
26. `Actualizar-DnsKuxtal.ps1` acepta `-ForzarIp` y `-Preferir` (por defecto
    sigue igual: Ethernet > Wi-Fi), para poder apuntar los dominios a la IP
    del Wi-Fi de la escuela sin tocar la programación automática.
27. Creado `C:\DataHunt\Expo\Preparar-Exposicion.ps1` y
    `C:\DataHunt\Kit-Exposicion.zip`. El script detecta la IP, actualiza DNS y
    `hosts`, verifica 443/firewall y genera `Paquete-Amigo-Expo.zip` con un
    `Configurar-Amigo.cmd` que ya incluye la IP nueva y una alternativa
    Tailscale.
28. `Configurar-Cliente-Kuxtal.ps1` dejó de probar `https://<IP>/` (una IP
    ajena no está en el SAN) y ahora comprueba `Test-NetConnection <IP> -Port
    443`. Las reglas de firewall 443/80 tienen `Profile=Any`.

### Fase 7 — Inicializador maestro
29. Creado `Inicializador-Maestro.ps1` y los atajos `Inicializar-Sistema.cmd`,
    `Verificar-Sistema.cmd` y `Inicializar-Sistema-Expo.cmd`. Unifica en una
    sola orden idempotente todas las fases anteriores, respalda en
    `Backups-Maestro`, verifica 19 puntos y falla explícitamente si el `5990`
    cambia o si faltan cuentas/TOTP. Ejecutado el 27/11/2026: **19/19 OK**.

---

## 3. Por qué fallaba en otros dispositivos y cómo quedó

Dos causas independientes:

1. **Nombre:** el DHCP lo entrega el router `192.168.100.1`, **no este
   servidor**. Un dispositivo que pregunte por `kuxtal.com` recibe la IP
   pública `44.221.248.111` en vez de `192.168.100.50`. En el servidor
   funcionaba gracias a la entrada del `hosts`.
2. **Certificado:** entrar por IP (`https://192.168.100.50/`) hacía que el
   navegador viera un nombre que no estaba en el certificado; además, el
   certificado autofirmado no era confiable en la laptop. De ahí el aviso
   *"No es seguro"*.

**Solución en cada PC que deba entrar, como administrador:**

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\DataHunt\Configurar-Cliente-Kuxtal.ps1
```

Luego abre **https://hospitalkuxtal.com/** (o `https://kuxtal.com/`). Ya no
hace falta IP ni puerto, y no aparece el aviso de seguridad. Si se entra por
IP, tampoco aparece porque la IP está incluida en el SAN del certificado.

Si el dispositivo entra por Tailscale:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\DataHunt\Configurar-Cliente-Kuxtal.ps1 -ServidorIp 100.109.230.106
```

Si la PC está en el dominio `kuxtal.local`, también basta con
`gpupdate /force` tras la publicación en AD. El script del cliente es la vía
universal (funciona aunque la PC no esté en el dominio).

Verificación desde el cliente:

```powershell
Test-NetConnection 192.168.100.50 -Port 443
Invoke-WebRequest https://hospitalkuxtal.com/ -UseBasicParsing
Invoke-WebRequest https://kuxtal.com/ -UseBasicParsing
```

> El puerto **5000 ya no está en uso**. Para compatibilidad con enlaces
> viejos se podría volver a añadir como redirección a HTTPS; hoy no responde.

---

## 4. Cambio de IP (Wi-Fi, DHCP o reinicio)

`Actualizar-DnsKuxtal.ps1` se ejecuta al arrancar y cada 5 minutos. Si la IP cambia:

- reescribe el registro A de **`kuxtal.com` y `hospitalkuxtal.com`** en el DNS,
- reescribe la entrada del `hosts` del servidor con ambos dominios,
- guarda el evento en `C:\DataHunt\dns_update.log`.

En los clientes hay que volver a ejecutar `Configurar-Cliente-Kuxtal.ps1` con la
IP nueva (el certificado incluye solo las IP conocidas; si aparece una IP
distinta, el navegador avisará al entrar por IP, pero no al usar el dominio).
La app no necesita reiniciarse: escucha en todas las interfaces.

---

## 4b. Modo exposición: servidor en otra red (Wi-Fi de una escuela)

Kit listo: **`C:\DataHunt\Kit-Exposicion.zip`** (contiene
`Preparar-Exposicion.ps1`, `INSTRUCCIONES-EXPO.txt` y el
`Paquete-Cliente-Kuxtal.zip`). Procedimiento:

1. En la escuela, conectar el servidor al Wi-Fi y anotar su IPv4 (`ipconfig`).
2. En el servidor, como administrador:

   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File C:\DataHunt\Expo\Preparar-Exposicion.ps1
   ```

   Detecta la IP del Wi-Fi, actualiza los registros A y el `hosts`, verifica
   el puerto 443 y el firewall, prueba ambos dominios y genera
   `C:\DataHunt\Expo\Paquete-Amigo-Expo.zip` con un `Configurar-Amigo.cmd`
   que ya lleva la IP nueva. Opciones: `-SoloVerificar` (no cambia nada) y
   `-ForzarIp <ip>`.
3. Entregar ese ZIP al amigo (USB, correo o OneDrive) y ejecutar
   `Configurar-Amigo.cmd` **como administrador** en su PC.
4. En el navegador del amigo: **`kuxtal.com`**, sin IP y sin puerto.

El configurador del cliente ya no prueba `https://<IP>/` porque una IP de otra
red no está en el SAN; en su lugar comprueba `Test-NetConnection <IP> -Port
443`. Las reglas de firewall `DataHunt 443 TLS` y `DataHunt 80 TLS` tienen
`Profile=Any`, así que funcionan aunque Windows marque la red como `Public`.

Si el Wi-Fi de la escuela aísla a los clientes (`Test-NetConnection` da
`False`), usar el `Configurar-Amigo-Tailscale.cmd` incluido — Tailscale ya está
instalado en el servidor — o un hotspot/router compartido. Esto **no publica**
la página en Internet: para eso harían falta un túnel o redirección de puerto
y un certificado público, con aprobación previa.

Al volver al hospital: ejecutar `Actualizar-DnsKuxtal.ps1` (o esperar 5
minutos) y volver a ejecutar el configurador del cliente con
`-ServidorIp 192.168.100.50`. Detalle completo en
`C:\DataHunt\Expo\INSTRUCCIONES-EXPO.txt`.

---

## 5. Arranque / paro / verificación

Arrancar (si se detuvo manualmente; normalmente ya arranca solo):

```powershell
pwsh -File C:\DataHunt\Iniciar-DataHunt.ps1
```

Detener:

```powershell
Stop-Process -Id 3028
```

Verificar:

```powershell
Resolve-DnsName hospitalkuxtal.com -Type A
Resolve-DnsName kuxtal.com -Type A
nslookup hospitalkuxtal.com 127.0.0.1
netsh http show sslcert
Get-NetTCPConnection -LocalPort 443,80 -State Listen
Invoke-WebRequest https://hospitalkuxtal.com/ -UseBasicParsing
Invoke-WebRequest https://kuxtal.com/ -UseBasicParsing
Get-ScheduledTask -TaskName 'Kuxtal-*' | Select-Object TaskName, State
Import-Csv C:\DataHunt\access_log.csv | Where-Object { $_.Exito -eq '0' }
```

Verificar confianza del certificado en un cliente:

```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq 'A5505BF4269ABD7D387B80E8B3D0ADC9C737BE9F'
```

Verificar cuentas y login:

```powershell
$u = Import-Csv C:\DataHunt\users.csv -Encoding utf8
"Usuarios: $($u.Count)"
$u | Group-Object { if ($_.Email -match '@kuxtal\.test$') { 'privilegiadas' } elseif ($_.Email -match '@kuxtal\.example$') { 'empleados' } else { 'pacientes' } } | Select Name,Count
Get-FileHash C:\DataHunt\users.csv -Algorithm SHA256
Import-Csv C:\DataHunt\access_log.csv | Where-Object { $_.Exito -eq '1' } | Select-Object -Last 5 Fecha,Evento,Exito
```

Probado con éxito el 27/11/2026: paciente `PAC-001` y empleado `EMP-0002`
→ HTTP 200 en `/login`, cookie de sesión emitida y `/mi-cuenta` → 200.
Los intentos fallidos anteriores quedaron registrados con `Exito=0`.

### Registro de usuarios nuevos
Sí: el formulario `https://hospitalkuxtal.com/registro` escribe directamente
en `users.csv` mediante `Agregar-Csv`. La contraseña se guarda **solo como
hash PBKDF2** (`salt:hash`, 600000 iteraciones, SHA-256), nunca en texto
plano; se registran consentimiento, versión del aviso y fecha. La app valida
campos obligatorios, formato de correo, fecha, teléfono y duplicados, y
rechaza correos predefinidos de roles. Cada alta exitosa deja un evento
`REGISTRO_OK` en `access_log.csv`.

Comprobado con un alta de prueba el 27/11/2026: 82 → 83 usuarios, fila con
hash válido, sin contraseña en claro. La cuenta de prueba se eliminó
restaurando el archivo; quedó en **82 usuarios**. El SHA-256 de ese momento
era `3DCBE0F7…D54315`; el vigente es `009E6221…26997A` por los enrolamientos
MFA registrados después (ver fase 5).

---

## 6. Pendientes

1. Ejecutar `Configurar-Cliente-Kuxtal.ps1` en cada dispositivo externo.
2. Confirmar si `Exito=0` es aceptable o se quiere como texto `False`.
3. ~~Desactivar la tarea antigua `Kuxtal-DataHunt`~~ **Hecho** por el maestro
   el 27/11/2026 (usuario `svc_datahunt$` inexistente).
4. Si se quiere HTTPS público (no solo LAN), hace falta certificado de una CA
   pública y publicar el registro DNS correspondiente fuera de la red.
5. Si se requiere que un empleado distinto de los tres listados en
   `$RolesPorEmail` tenga rol de admisión/médico/facturación, agregar su correo
   a esa tabla en `app.ps1` (hoy quedan como R-01).
6. Las contraseñas de las cuentas privilegiadas no se cambiaron. Tres de ellas
   (`dpo`, `admision`, `privacidad`) ya tienen un secreto TOTP generado por la
   app el 27/11; `admin` no. Si se van a migrar a otros teléfonos, exporta los
   secretos desde `users.csv` antes de cualquier restauración; no regeneres
   los `PasswordHash`.

---

## 7. Reversión

- Fase kuxtal.com / hospitalkuxtal.com:
  `C:\DataHunt\backup_kuxtalcom_20261127.txt` (ADDENDA con comandos exactos de
  certificado, TLS, ACL, firewall, DNS, hosts y tareas). Para volver al
  certificado anterior, enlazar de nuevo el thumbprint
  `FEDE8804439B0EB6F6AC45B6AD5C79FBA0313175` en `0.0.0.0:443` y `[::]:443`.
- En clientes: quitar la línea marcada del `hosts` y ejecutar
  `Remove-Item Cert:\LocalMachine\Root\A5505BF4269ABD7D387B80E8B3D0ADC9C737BE9F`.
- Fase 5990: `C:\DataHunt\ssl_5990_backup_20261127.txt` (incluye la addenda de la ACL).
- Cuentas: `C:\DataHunt\users_antes_restaurar_20261127_153812.csv` (estado vacío
  previo). Para recuperar las fuentes, `usuarios_a_cargar.csv` y
  `usuarios_a_cargar_empleados_pacientes.csv` están intactas.
- Informe para Emilio: `C:\DataHunt\informe_para_emilio_20261127.txt`.
