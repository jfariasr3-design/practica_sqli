"""
escaneo_red.py
Escaner basico de puertos TCP (connect scan) con hilos.
Por seguridad, solo escanea equipos locales o de red privada.

Uso:
    python escaneo_red.py                       # 127.0.0.1, puertos 1-1024 + 5000,5001
    python escaneo_red.py --host 127.0.0.1 --ports 1-200
"""
import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor


def rango(texto):
    puertos = set()
    for parte in texto.split(","):
        if "-" in parte:
            a, b = parte.split("-")
            puertos.update(range(int(a), int(b) + 1))
        else:
            puertos.add(int(parte))
    return sorted(p for p in puertos if 1 <= p <= 65535)


def escanear(host, puerto):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        if s.connect_ex((host, puerto)) == 0:
            try:
                servicio = socket.getservbyport(puerto, "tcp")
            except OSError:
                servicio = "desconocido"
            return puerto, servicio
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--ports", default="1-1024,5000,5001")
    a = ap.parse_args()
    ip = socket.gethostbyname(a.host)
    dir_ip = ipaddress.ip_address(ip)
    if not (dir_ip.is_loopback or dir_ip.is_private):
        sys.exit("Por seguridad solo se permiten equipos locales o de red privada.")
    puertos = rango(a.ports)
    print(f"Escaneando {a.host} ({ip}) - {len(puertos)} puertos...\n")
    with ThreadPoolExecutor(max_workers=100) as ex:
        resultados = [r for r in ex.map(lambda p: escanear(ip, p), puertos) if r]
    print(f"{'PUERTO':8} {'ESTADO':8} SERVICIO")
    print("-" * 32)
    for p, s in resultados:
        print(f"{p:<8} {'abierto':8} {s}")
    if not resultados:
        print("No se encontraron puertos abiertos.")
    print(f"\nTotal de puertos abiertos: {len(resultados)}")


if __name__ == "__main__":
    main()
