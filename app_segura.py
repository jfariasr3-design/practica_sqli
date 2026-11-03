"""
app_segura.py
Version MITIGADA de la aplicacion: usa consultas parametrizadas (sentencias
preparadas) y guarda las claves con hash. Neutraliza la inyeccion SQL.
Se ejecuta en el puerto 5001 para comparar con app_vulnerable.py (5000).
"""
import sqlite3
from html import escape
from flask import Flask, request
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DB = "usuarios_seguro.db"
PUERTO = 5001


def crear_bd():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS usuarios")
    cur.execute(
        "CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT UNIQUE, "
        "clave_hash TEXT, rol TEXT)"
    )
    datos = [
        ("admin", "Admin#2026", "administrador"),
        ("maria", "maria123", "usuario"),
        ("juan", "juan456", "usuario"),
    ]
    for u, c, r in datos:
        cur.execute(
            "INSERT INTO usuarios (usuario, clave_hash, rol) VALUES (?,?,?)",
            (u, generate_password_hash(c), r),
        )
    con.commit()
    con.close()


FORM_LOGIN = """
<h2>Login (SEGURO)</h2>
<form method="POST">
  Usuario: <input name="usuario"><br><br>
  Clave: <input name="clave" type="password"><br><br>
  <button type="submit">Entrar</button>
</form>
<p><a href="/buscar">Ir al buscador</a></p>
"""


@app.route("/")
def inicio():
    return '<h3>App segura (practica SQLi)</h3><a href="/login">Login</a> | <a href="/buscar">Buscador</a>'


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return FORM_LOGIN
    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")
    con = sqlite3.connect(DB)
    try:
        # SEGURO: consulta parametrizada, la entrada nunca se interpreta como SQL
        fila = con.execute(
            "SELECT id, usuario, clave_hash, rol FROM usuarios WHERE usuario = ?",
            (usuario,),
        ).fetchone()
    finally:
        con.close()
    if fila and check_password_hash(fila[2], clave):
        return f"Bienvenido {escape(fila[1])} (rol: {escape(fila[3])})"
    return "Credenciales incorrectas", 401


@app.route("/buscar")
def buscar():
    q = request.args.get("q", "")
    con = sqlite3.connect(DB)
    try:
        filas = con.execute(
            "SELECT id, usuario, rol FROM usuarios WHERE usuario LIKE ?",
            ("%" + q + "%",),
        ).fetchall()
    finally:
        con.close()
    html = (
        '<h2>Buscador de usuarios (SEGURO)</h2>'
        '<form method="GET">Buscar: <input name="q" value="">'
        '<button>Buscar</button></form><ul>'
    )
    for f in filas:
        html += f"<li>{escape(str(f[0]))} - {escape(str(f[1]))} - {escape(str(f[2]))}</li>"
    return html + "</ul>"


if __name__ == "__main__":
    crear_bd()
    app.run(host="127.0.0.1", port=PUERTO, debug=False)
