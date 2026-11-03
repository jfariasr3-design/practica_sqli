# Manual de uso y pruebas

## 1. Requisitos
- Python 3.10 o superior, Visual Studio Code y Git.
- Todo se ejecuta en la misma computadora (127.0.0.1).

## 2. Instalación
```bash
git clone https://github.com/USUARIO/practica_sqli.git
cd practica_sqli
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac / Linux
pip install -r requirements.txt
```
(También funciona instalando a mano: `pip install flask requests`).

## 3. Ejecutar los servidores
Abre **dos terminales** de VS Code con el entorno virtual activo:

```bash
# Terminal 1 - aplicación VULNERABLE (puerto 5000)
python app_vulnerable.py

# Terminal 2 - aplicación SEGURA (puerto 5001)
python app_segura.py
```

Cada servidor crea su base de datos de prueba al iniciar.

## 4. Pruebas ANTES de la mitigación (app vulnerable)

### 4.1 Funcionamiento normal
1. Abre `http://127.0.0.1:5000/login`.
2. Entra con `maria` / `maria123` → debe decir **Bienvenido maria**.
3. Entra con una clave incorrecta → **Credenciales incorrectas**.

### 4.2 Ataque manual al login (bypass de autenticación)
En el campo **Usuario** escribe `' OR '1'='1' --` y cualquier clave.
Resultado esperado: acceso concedido sin credenciales válidas.
Otra prueba: usuario `admin' --`.

### 4.3 Ataque manual al buscador (extracción de registros)
En `http://127.0.0.1:5000/buscar` escribe:
```
' UNION SELECT id, usuario, clave FROM usuarios --
```
Resultado esperado: el buscador muestra las claves de todos los usuarios.

### 4.4 Ataque con el script
```bash
python ataque_sql_i.py --url http://127.0.0.1:5000
```
Imprime una tabla con cada prueba y guarda `resultados_5000.csv`.

## 5. Pruebas DESPUÉS de la mitigación (app segura)
Repite los mismos ataques manuales en `http://127.0.0.1:5001/login` y `/buscar`, y ejecuta:
```bash
python ataque_sql_i.py --url http://127.0.0.1:5001
```
Resultado esperado: todos los payloads aparecen como **BLOQUEADO** y se guarda `resultados_5001.csv`.

**Qué cambió en el código:**
```python
# ANTES (vulnerable): concatenación de texto
consulta = "SELECT * FROM usuarios WHERE usuario='" + usuario + "' AND clave='" + clave + "'"

# DESPUÉS (seguro): consulta parametrizada + hash de clave
fila = con.execute("SELECT ... FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
check_password_hash(fila[2], clave)
```

## 6. Módulos complementarios

### Escaneo de red (puertos/servicios)
```bash
python escaneo_red.py
python escaneo_red.py --host 127.0.0.1 --ports 1-200,5000,5001
```
Con los servidores encendidos deben aparecer abiertos los puertos 5000 y 5001.

### Seguridad en bases de datos (hardening)
```bash
python seguridad_bd.py            # auditoría de la BD vulnerable
python seguridad_bd.py --aplicar  # además crea usuarios_endurecida.db con hash
```

## 7. Tabla resumen de resultados comparativos

| Prueba | App vulnerable (5000) | App segura (5001) |
|---|---|---|
| Login normal | Acceso legítimo | Acceso legítimo |
| `' OR '1'='1' --` | Acceso sin credenciales | Bloqueado |
| `admin' --` | Acceso sin credenciales | Bloqueado |
| Comilla simple `'` | Error SQL expuesto | Sin error, rechazado |
| Buscador `' OR '1'='1` | Lista todos los usuarios | Sin filtración |
| Buscador `UNION SELECT ...` | Claves filtradas | Sin filtración |

## 8. Evidencias
Guarda las capturas de pantalla en la carpeta `evidencias/` (ver `evidencias/LEEME.txt`).
