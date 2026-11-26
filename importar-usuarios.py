import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

base = Path(r"C:\Users\ccuen\Desktop\proyectos-datahunt-v2")
users = Path(r"C:\DataHunt\users.csv")
log = Path(r"C:\DataHunt\access_log.csv")

entrada = list(csv.DictReader((base / "usuarios_a_cargar_empleados_pacientes.csv").open(encoding="utf-8-sig", newline="")))
existentes = list(csv.DictReader(users.open(encoding="utf-8-sig", newline="")))
por_correo = {fila["Email"].lower() for fila in existentes}

ahora = datetime.now(timezone.utc).isoformat()
version = "v2.1 (2026-11-26)"
nuevos = []
for fila in entrada:
    correo = fila["Email"].lower()
    if correo in por_correo:
        continue
    por_correo.add(correo)
    import uuid
    nuevos.append({
        "Id": str(uuid.uuid4()),
        "Nombre": fila["Nombre"],
        "Email": correo,
        "PasswordHash": fila["PasswordHash"],
        "FechaNacimiento": fila["FechaNacimiento"],
        "Telefono": fila["Telefono"],
        "Jurisdiccion": fila["Jurisdiccion"],
        "AseguradoraPoliza": fila["AseguradoraPoliza"],
        "MotivoAlergias": fila["MotivoAlergias"],
        "Consentimiento": "True",
        "FechaConsentimiento": ahora,
        "VersionAviso": version,
        "FechaRegistro": ahora,
    })

encabezado = ["Id", "Nombre", "Email", "PasswordHash", "FechaNacimiento", "Telefono", "Jurisdiccion", "AseguradoraPoliza", "MotivoAlergias", "Consentimiento", "FechaConsentimiento", "VersionAviso", "FechaRegistro"]
with users.open("w", encoding="utf-8", newline="") as f:
    escritor = csv.DictWriter(f, fieldnames=encabezado)
    escritor.writeheader()
    escritor.writerows(existentes + nuevos)

with log.open("a", encoding="utf-8", newline="") as f:
    csv.writer(f).writerow([ahora, "CARGA_MASIVA_OK", "empleados-pacientes", 1, "INFO", "NO_REGISTRADA"])

print("cargados", len(nuevos), "total", len(existentes) + len(nuevos))
