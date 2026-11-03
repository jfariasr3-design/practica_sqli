"""
seguridad_bd.py
Modulo de seguridad en bases de datos (hardening) sobre SQLite.
  - Audita la BD vulnerable: detecta claves en texto plano y permisos del archivo.
  - Con --aplicar genera usuarios_endurecida.db con claves protegidas por hash.

Uso:
    python seguridad_bd.py            # solo auditoria
    python seguridad_bd.py --aplicar  # auditoria + crear BD endurecida
"""
import argparse
import os
import sqlite3
import stat
from werkzeug.security import generate_password_hash

ORIGEN = "usuarios_vulnerable.db"
DESTINO = "usuarios_endurecida.db"


def auditar():
    if not os.path.exists(ORIGEN):
        raise SystemExit(f"No existe {ORIGEN}. Ejecuta primero app_vulnerable.py una vez.")
    print(f"== Auditoria de {ORIGEN} ==")
    modo = stat.filemode(os.stat(ORIGEN).st_mode)
    print(f"Permisos del archivo: {modo}  (recomendado: solo el propietario)")
    con = sqlite3.connect(ORIGEN)
    filas = con.execute("SELECT usuario, clave FROM usuarios").fetchall()
    con.close()
    planas = 0
    for u, c in filas:
        es_hash = c.startswith(("scrypt:", "pbkdf2:"))
        estado = "OK (hash)" if es_hash else "RIESGO: clave en texto plano"
        planas += 0 if es_hash else 1
        print(f"  usuario={u:8} -> {estado}")
    print(f"\nHallazgos: {planas} clave(s) en texto plano de {len(filas)} usuarios.")
    print("\nBuenas practicas recomendadas:")
    for t in [
        "Usar consultas parametrizadas (nunca concatenar entrada del usuario).",
        "Guardar claves con hash y sal (scrypt/bcrypt), jamas en texto plano.",
        "Principio de minimo privilegio para la cuenta de la aplicacion.",
        "Validar y limitar la entrada; no mostrar errores SQL al usuario.",
        "Respaldos periodicos y cifrado del archivo/disco de la base de datos.",
        "Restringir permisos del archivo de BD y registrar accesos (logs).",
    ]:
        print("  -", t)
    return filas


def aplicar(filas):
    con = sqlite3.connect(DESTINO)
    con.execute("DROP TABLE IF EXISTS usuarios")
    con.execute("CREATE TABLE usuarios (usuario TEXT UNIQUE, clave_hash TEXT)")
    for u, c in filas:
        h = c if c.startswith(("scrypt:", "pbkdf2:")) else generate_password_hash(c)
        con.execute("INSERT INTO usuarios VALUES (?,?)", (u, h))
    con.commit()
    con.close()
    try:
        os.chmod(DESTINO, 0o600)
    except OSError:
        pass
    print(f"\nBD endurecida creada: {DESTINO} (claves con hash).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--aplicar", action="store_true")
    a = ap.parse_args()
    datos = auditar()
    if a.aplicar:
        aplicar(datos)
