# Práctica 4 - SQL Injection con Flask y SQLite

**Universidad Estatal de Milagro (UNEMI)** · Seguridad Informática · 2026

Proyecto académico que simula una aplicación web **vulnerable a propósito** a SQL Injection,
un script de ataque controlado, la mitigación con consultas parametrizadas y módulos
complementarios de escaneo de red y seguridad en bases de datos.

> ⚠️ **Uso exclusivamente educativo y local (127.0.0.1).** No publicar la app vulnerable en internet
> ni usar estos scripts contra sistemas ajenos.

## Contenido

| Archivo | Descripción |
|---|---|
| `app_vulnerable.py` | Servidor Flask con login y buscador vulnerables (puerto 5000) |
| `app_segura.py` | Versión mitigada: consultas parametrizadas + hash de claves (puerto 5001) |
| `ataque_sql_i.py` | Script de pruebas de inyección SQL (solo permite objetivos locales) |
| `escaneo_red.py` | Escáner básico de puertos TCP (solo equipos locales/red privada) |
| `seguridad_bd.py` | Auditoría y endurecimiento (hardening) de la base de datos |
| `MANUAL_USO.md` | Guía paso a paso de instalación, ejecución y pruebas |
| `evidencias/` | Carpeta para las capturas de pantalla del informe |

## Integrantes

- Diego Armando Ayala Armijos
- Lizbeth Verónica Casco Bastidas
- Marcello Radamés Cordero Torrealba
- Jennifer Ariana Farias Rojas
- Juan Carlos Pillasagua Alcívar
- Wilson Javier Quishpe Toaquiza
- Griselda Coraima Rúa Bailón 

## Herramientas

Python 3, Flask, SQLite, Visual Studio Code, Git/GitHub.

## Inicio rápido

```bash
python -m venv venv
venv\Scripts\activate        # Windows  (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
python app_vulnerable.py
```

Consulta `MANUAL_USO.md` para el procedimiento completo.
