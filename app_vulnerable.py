"""
app_vulnerable.py
Aplicacion web VULNERABLE A PROPOSITO (Flask + SQLite) para la practica de
Seguridad Informatica - SQL Injection.

!! Solo para uso academico en tu propio equipo (127.0.0.1). NO publicar. !!

La vulnerabilidad: las consultas SQL se arman CONCATENANDO texto del usuario.
"""
import sqlite3
from html import escape
from flask import Flask, request

app = Flask(__name__)
DB = "usuarios_vulnerable.db"
PUERTO = 5000


def crear_bd():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS usuarios")
    cur.execute(
        "CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT, "
        "clave TEXT, rol TEXT)"
    )
    cur.executemany(
        "INSERT INTO usuarios (usuario, clave, rol) VALUES (?,?,?)",
        [
            ("admin", "Admin#2026", "administrador"),
            ("maria", "maria123", "usuario"),
            ("juan", "juan456", "usuario"),
        ],
    )
    con.commit()
    con.close()


FORM_LOGIN = """
<h2>Login (VULNERABLE)</h2>
<form method="POST">
  Usuario: <input name="usuario"><br><br>
  Clave: <input name="clave" type="password"><br><br>
  <button type="submit">Entrar</button>
</form>
<p><a href="/buscar">Ir al buscador</a></p>
"""


@app.route("/")
def inicio():
    return '<h3>App vulnerable (practica SQLi)</h3><a href="/login">Login</a> | <a href="/buscar">Buscador</a>'


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return FORM_LOGIN
    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")
    # VULNERABLE: concatenacion directa de la entrada del usuario
    consulta = (
        "SELECT * FROM usuarios WHERE usuario='" + usuario
        + "' AND clave='" + clave + "'"
    )
    con = sqlite3.connect(DB)
    try:
        fila = con.execute(consulta).fetchone()
    except Exception as e:
        return f"Error SQL: {escape(str(e))}<br>Consulta: {escape(consulta)}", 500
    finally:
        con.close()
    if fila:
        return f"Bienvenido {escape(fila[1])} (rol: {escape(fila[3])})"
    return "Credenciales incorrectas", 401


@app.route("/buscar")
def buscar():
    q = request.args.get("q", "")
    # VULNERABLE: concatenacion directa de la entrada del usuario
    consulta = "SELECT id, usuario, rol FROM usuarios WHERE usuario LIKE '%" + q + "%'"
    con = sqlite3.connect(DB)
    try:
        filas = con.execute(consulta).fetchall()
    except Exception as e:
        return f"Error SQL: {escape(str(e))}", 500
    finally:
        con.close()
    html = (
        '<h2>Buscador de usuarios (VULNERABLE)</h2>'
        '<form method="GET">Buscar: <input name="q" value="">'
        '<button>Buscar</button></form><ul>'
    )
    for f in filas:
        html += f"<li>{escape(str(f[0]))} - {escape(str(f[1]))} - {escape(str(f[2]))}</li>"
    return html + "</ul>"


if __name__ == "__main__":
    crear_bd()
    # Solo escucha en localhost y sin modo debug
    app.run(host="127.0.0.1", port=PUERTO, debug=False)
