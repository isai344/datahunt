import csv
from pathlib import Path

base = Path(r"C:\Users\ccuen\Desktop\proyectos-datahunt-v2")
credenciales = list(csv.DictReader((base / "credenciales_generadas.csv").open(encoding="utf-8-sig", newline="")))
lineas = [
    "ADMINISTRADOR", "Cuenta predefinida", "Admin", "admin@kuxtal.test", "12345678",
    "DPO", "Cuenta predefinida", "DPO", "dpo@kuxtal.test", "12345678",
    "ADMISION", "Cuenta predefinida", "Admisión", "admision@kuxtal.test", "12345678",
]
for fila in credenciales:
    lineas.append(fila["Tipo"])
    lineas.append(fila["ID"])
    lineas.append(fila["Nombre"])
    lineas.append(fila["Correo"])
    lineas.append(fila["Contrasena"])
(base / "cont.txt").write_text("\n".join(lineas) + "\n", encoding="utf-8")
print("credenciales", len(credenciales))
