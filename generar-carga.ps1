import csv
import hashlib
import secrets
import string
from pathlib import Path

import openpyxl

base = Path(r"C:\Users\ccuen\Desktop\proyectos-datahunt-v2")
excel = Path(r"C:\Users\ccuen\Desktop\2 · Jefes de área\02 · Base de datos ficticia (empleados y pacientes de prueba).xlsx")
wb = openpyxl.load_workbook(excel, data_only=True)


def fecha(valor):
    if valor is None:
        return "1900-01-01"
    return valor.strftime("%Y-%m-%d")


def texto(valor, por_defecto=""):
    if valor is None:
        return por_defecto
    return str(valor).strip()


def contrasena():
    alfabeto = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        valor = "".join(secrets.choice(alfabeto) for _ in range(16))
        if (any(c.islower() for c in valor) and any(c.isupper() for c in valor)
                and any(c.isdigit() for c in valor) and any(c in "!@#$%^&*" for c in valor)):
            return valor


def hash_pbkdf2(clave):
    sal = secrets.token_bytes(16)
    hash_valor = hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"), sal, 600000, dklen=32)
    import base64
    return base64.b64encode(sal).decode() + ":" + base64.b64encode(hash_valor).decode()


filas = []
credenciales = []


ws = wb["Empleados"]
for fila in ws.iter_rows(min_row=2, values_only=True):
    if not texto(fila[0]).startswith("EMP-"):
        continue
    if texto(fila[16]) != "Activo":
        continue
    nombre = texto(fila[1])
    apellidos = (texto(fila[2]) + " " + texto(fila[3])).strip()
    correo = texto(fila[10]).lower()
    clave = contrasena()
    filas.append({
        "Nombre": (nombre + " " + apellidos).strip(),
        "Email": correo,
        "Password": clave,
        "PasswordHash": hash_pbkdf2(clave),
        "FechaNacimiento": "1900-01-01",
        "Telefono": texto(fila[11], "0000000000"),
        "Jurisdiccion": "México",
        "AseguradoraPoliza": texto(fila[9]),
        "MotivoAlergias": "Empleado " + texto(fila[0]) + " - " + texto(fila[6]) + " - " + texto(fila[5]),
    })
    credenciales.append(("EMPLEADO", texto(fila[0]), filas[-1]["Nombre"], correo, clave))

ws = wb["Pacientes de prueba"]
for fila in ws.iter_rows(min_row=2, values_only=True):
    if not texto(fila[0]).startswith("PAC-"):
        continue
    correo = texto(fila[2]).lower()
    clave = contrasena()
    pais = texto(fila[5])
    estado = texto(fila[6])
    if pais == "Estados Unidos":
        jurisdiccion = "Estados Unidos - California"
    elif pais == "México":
        jurisdiccion = "México"
    elif pais in ("España", "Alemania", "Francia", "Italia", "Portugal"):
        jurisdiccion = "Unión Europea (España, Alemania, etc.)"
    else:
        jurisdiccion = "Otro"
    aseguradora = texto(fila[8])
    poliza = texto(fila[9])
    filas.append({
        "Nombre": texto(fila[1]),
        "Email": correo,
        "Password": clave,
        "PasswordHash": hash_pbkdf2(clave),
        "FechaNacimiento": fecha(fila[3]),
        "Telefono": texto(fila[4]),
        "Jurisdiccion": jurisdiccion,
        "AseguradoraPoliza": (aseguradora + (" " + poliza if poliza else "")).strip(),
        "MotivoAlergias": (texto(fila[10]) + " | Alergias: " + texto(fila[11])).strip(),
    })
    credenciales.append(("PACIENTE", texto(fila[0]), filas[-1]["Nombre"], correo, clave))

encabezado = ["Nombre", "Email", "Password", "PasswordHash", "FechaNacimiento", "Telefono", "Jurisdiccion", "AseguradoraPoliza", "MotivoAlergias"]
with (base / "usuarios_a_cargar_empleados_pacientes.csv").open("w", encoding="utf-8", newline="") as f:
    escritor = csv.DictWriter(f, fieldnames=encabezado)
    escritor.writeheader()
    escritor.writerows(filas)

with (base / "credenciales_generadas.csv").open("w", encoding="utf-8", newline="") as f:
    escritor = csv.writer(f)
    escritor.writerow(["Tipo", "ID", "Nombre", "Correo", "Contrasena"])
    escritor.writerows(credenciales)

print("filas", len(filas), "empleados", sum(1 for c in credenciales if c[0] == "EMPLEADO"), "pacientes", sum(1 for c in credenciales if c[0] == "PACIENTE"))
