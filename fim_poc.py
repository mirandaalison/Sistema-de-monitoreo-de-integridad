#!/usr/bin/env python3
"""
PoC: Sistema de Monitoreo de Integridad de Archivos (FIM)

Requisitos cumplidos:
- Único archivo Python, usando solo librerías estándar: tkinter, sqlite3,
  hashlib, os, time, datetime, threading.
- Base de datos SQLite `integridad_monitores.db` con tablas `inventario` y `alertas`.
- Monitoreo de la carpeta `./archivos_criticos` con archivo de prueba `config.cfg`.
- Línea base, escaneo en hilo secundario, medición de tiempo con time.perf_counter().
- GUI con Tkinter (tema oscuro), indicador de estado, Treeview con historial,
  botones: Establecer Línea Base, Escanear Ahora, Simular Modificación, Limpiar Alertas.
- Consultas parametrizadas y manejo de excepciones de archivos.

Ejecutar: `python3 fim_poc.py` (recomendado en Ubuntu Desktop)
"""

import os
import sqlite3
import hashlib
import time
import datetime
import threading
import subprocess
import platform
import html
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    GUI_AVAILABLE = True
except Exception:
    # Entorno sin tkinter (modo headless posible)
    GUI_AVAILABLE = False
    tk = None
    ttk = None
    messagebox = None

# --- Configuración global ---
BASE_DIR = os.path.expanduser("~/.fim_poc")
DB_FILENAME = os.path.join(BASE_DIR, "integridad_monitores.db")
WATCH_DIR = os.path.join(BASE_DIR, "archivos_criticos")
TEST_FILENAME = os.path.join(WATCH_DIR, "config.cfg")

# Sincronización remota desde Metasploitable2 hacia Ubuntu Desktop
# Ubuntu Desktop (monitora): 10.0.2.3
# Metasploitable2 (objetivo monitoreado): 10.0.2.4
# Kali Linux (atacante): 10.0.2.15
REMOTE_SYNC_ENABLED = True
REMOTE_USER = "msfadmin"
REMOTE_HOST = "10.0.2.4"
REMOTE_SOURCE_DIR = "/home/msfadmin/carpeta_critica"
REMOTE_SSH_PORT = 22
REMOTE_SSH_OPTIONS = [
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "ConnectTimeout=15",
    "-o",
    "HostKeyAlgorithms=+ssh-rsa",
    "-o",
    "PubkeyAcceptedAlgorithms=+ssh-rsa",
]
REMOTE_TARGET_DIR = WATCH_DIR


def get_db_connection():
    """Crear y devolver una conexión SQLite.

    Cada hilo debe crear su propia conexión para evitar conflictos con
    `check_same_thread`.
    """
    conn = sqlite3.connect(DB_FILENAME, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def normalize_path(path):
    """Normalizar rutas para comparación y almacenamiento.

    Esto evita falsos negativos cuando el mismo archivo se escribe con
    separadores o referencias redundantes diferentes.
    """
    return os.path.normpath(path)


def init_db():
    """Crear la base de datos y las tablas si no existen."""
    os.makedirs(os.path.dirname(DB_FILENAME), exist_ok=True)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS inventario (
            ruta_archivo TEXT PRIMARY KEY,
            hash_seguro TEXT,
            ultima_verificacion TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ruta_archivo TEXT,
            fecha_hora TEXT,
            usuario TEXT,
            hash_anterior TEXT,
            hash_nuevo TEXT,
            tiempo_deteccion_ms REAL
        )
        """
    )
    conn.commit()
    conn.close()


def ensure_watch_dir():
    """Crear carpeta de archivos críticos y archivo de prueba si no existen."""
    os.makedirs(WATCH_DIR, exist_ok=True)
    if not os.path.exists(TEST_FILENAME):
        try:
            with open(TEST_FILENAME, "w", encoding="utf-8") as f:
                f.write("# Archivo de configuración de prueba\nparam=valor\n")
        except Exception:
            # No romper si no se puede crear el archivo; se registrará si es necesario
            pass


def sha256_of_file(path):
    """Calcular hash SHA-256 de un archivo. Maneja excepciones de lectura.

    Devuelve la hex digest o lanza la excepción para que el llamador lo maneje.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sincronizar_remoto(progress_callback=None):
    """Sincroniza una carpeta remota desde Metasploitable2 hacia la carpeta local."""
    if not REMOTE_SYNC_ENABLED:
        if progress_callback:
            progress_callback("", "REMOTO_DESACTIVADO")
        return False
    ensure_watch_dir()
    remote_spec = f"{REMOTE_USER}@{REMOTE_HOST}:{REMOTE_SOURCE_DIR}"
    local_path = REMOTE_TARGET_DIR
    os.makedirs(local_path, exist_ok=True)
    remote_contents_spec = remote_spec.rstrip("/") + "/."
    cmd = ["scp", "-r", "-P", str(REMOTE_SSH_PORT)] + REMOTE_SSH_OPTIONS + [remote_contents_spec, local_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if proc.returncode != 0:
            message = proc.stderr.strip() or proc.stdout.strip() or "scp falló"
            if progress_callback:
                progress_callback(remote_spec, f"SCP_ERROR: {message}")
            return False
        else:
            if progress_callback:
                progress_callback(remote_spec, "REMOTO_SINCRONIZADO")
            return True
    except FileNotFoundError:
        if progress_callback:
            progress_callback(remote_spec, "SCP_NO_INSTALADO")
        return False
    except subprocess.TimeoutExpired:
        if progress_callback:
            progress_callback(remote_spec, "SCP_TIMEOUT")
        return False
    except Exception as e:
        if progress_callback:
            progress_callback(remote_spec, f"SCP_EXCEPTION: {e}")
        return False


def establecer_linea_base(progress_callback=None):
    """Escanea la carpeta y guarda/actualiza la línea base en `inventario`.

    Si `progress_callback` es una función, se la llama con (ruta, estado).
    """
    ensure_watch_dir()
    sincronizar_remoto(progress_callback=progress_callback)
    archivos = []
    for root, _, files in os.walk(WATCH_DIR):
        for fn in files:
            archivos.append(normalize_path(os.path.join(root, fn)))

    conn = get_db_connection()
    cur = conn.cursor()

    timestamp = datetime.datetime.utcnow().isoformat()

    for path in archivos:
        try:
            h = sha256_of_file(path)
        except Exception as e:
            # Registrar fallo en inventario dejando hash_seguro como NULL
            cur.execute(
                "INSERT OR REPLACE INTO inventario (ruta_archivo, hash_seguro, ultima_verificacion) VALUES (?, ?, ?)",
                (path, None, timestamp),
            )
            if progress_callback:
                progress_callback(path, f"ERROR: {e}")
            continue

        cur.execute(
            "INSERT OR REPLACE INTO inventario (ruta_archivo, hash_seguro, ultima_verificacion) VALUES (?, ?, ?)",
            (path, h, timestamp),
        )
        if progress_callback:
            progress_callback(path, "OK")

    conn.commit()
    conn.close()


def insertar_alerta(ruta, usuario, hash_anterior, hash_nuevo, tiempo_ms):
    """Insertar una fila en la tabla `alertas` con parámetros seguros."""
    conn = get_db_connection()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO alertas (ruta_archivo, fecha_hora, usuario, hash_anterior, hash_nuevo, tiempo_deteccion_ms) VALUES (?, ?, ?, ?, ?, ?)",
        (ruta, now, usuario, hash_anterior, hash_nuevo, tiempo_ms),
    )
    conn.commit()
    conn.close()


def obtener_alertas(limit=100):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT ruta_archivo, fecha_hora, usuario, tiempo_deteccion_ms, hash_anterior, hash_nuevo FROM alertas ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def limpiar_alertas():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM alertas")
    conn.commit()
    conn.close()


def contar_alertas():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alertas")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else 0


def obtener_ultimo_evento():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT fecha_hora FROM alertas ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else "N/A"


def contar_archivos_observados():
    total = 0
    for root, _, files in os.walk(WATCH_DIR):
        total += len(files)
    return total


def obtener_inventario():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT ruta_archivo, hash_seguro FROM inventario")
    rows = cur.fetchall()
    conn.close()
    return {normalize_path(r): h for r, h in rows}


def actualizar_ultima_verificacion(path, timestamp=None):
    path = normalize_path(path)
    if timestamp is None:
        timestamp = datetime.datetime.utcnow().isoformat()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE inventario SET ultima_verificacion = ? WHERE ruta_archivo = ?",
        (timestamp, path),
    )
    conn.commit()
    conn.close()


def actualizar_inventario(path, hash_seguro, timestamp=None):
    path = normalize_path(path)
    if timestamp is None:
        timestamp = datetime.datetime.utcnow().isoformat()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO inventario (ruta_archivo, hash_seguro, ultima_verificacion) VALUES (?, ?, ?)",
        (path, hash_seguro, timestamp),
    )
    conn.commit()
    conn.close()


def eliminar_de_inventario(path):
    path = normalize_path(path)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM inventario WHERE ruta_archivo = ?", (path,))
    conn.commit()
    conn.close()


def verificar_integridad(progress_callback=None, completion_callback=None):
    """Verifica integridad comparando con la línea base y registra alertas.

    Esta función se puede ejecutar en un hilo secundario. Llama a
    `progress_callback(ruta, estado)` para informar de estados intermedios y
    `completion_callback()` al finalizar.
    """
    start = time.perf_counter()

    # Tomar snapshot de inventario (baseline)
    baseline = obtener_inventario()

    # Si no hay línea base previa, crearla y no generar alertas falsas.
    if not baseline:
        if progress_callback:
            progress_callback("", "LÍNEA BASE AUTOMÁTICA")
        establecer_linea_base(progress_callback=progress_callback)
        if completion_callback:
            completion_callback()
        return

    # Sincronizar el contenido remoto antes de verificar
    remote_ok = sincronizar_remoto(progress_callback=progress_callback)
    if not remote_ok:
        if progress_callback:
            progress_callback("", "SINCRONIZACION_REMOTA_FALLO")
        if completion_callback:
            completion_callback()
        return

    # Escanear archivos actuales
    actuales = []
    for root, _, files in os.walk(WATCH_DIR):
        for fn in files:
            actuales.append(normalize_path(os.path.join(root, fn)))

    # Mapear para detección de eliminaciones
    baseline_paths = set(normalize_path(p) for p in baseline.keys())
    actuales_paths = set(actuales)
    usuario = obtener_usuario()

    # Detectar archivos modificados o nuevos
    for path in actuales:
        try:
            h = sha256_of_file(path)
        except Exception as e:
            # Registrar fallo de lectura como alerta
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            hash_prev = baseline.get(path, "DESCONOCIDO")
            insertar_alerta(path, usuario, hash_prev, "ERROR_LECTURA", elapsed_ms)
            if progress_callback:
                progress_callback(path, f"ERROR_LECTURA: {e}")
            # actualizar última verificación para este archivo en inventario (si existe)
            if path in baseline:
                actualizar_ultima_verificacion(path)
            continue

        if path in baseline:
            baseline_hash = baseline[path]
            if baseline_hash is None:
                # Línea base existente pero hash nulo (error previo)
                if progress_callback:
                    progress_callback(path, "HASH_BASE_VACIO")
                # Si ahora podemos leer el archivo, actualizamos la línea base y no generamos alerta repetida.
                actualizar_inventario(path, h)
            else:
                if h != baseline_hash:
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    insertar_alerta(path, usuario, baseline_hash, h, elapsed_ms)
                    actualizar_inventario(path, h)
                else:
                    actualizar_ultima_verificacion(path)
        else:
            # Archivo nuevo (no estaba en la línea base)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            insertar_alerta(path, usuario, "NUEVO", h, elapsed_ms)
            actualizar_inventario(path, h)

        if progress_callback:
            progress_callback(path, "VERIFICADO")

    # Detectar eliminaciones
    eliminados = baseline_paths - actuales_paths
    for path in eliminados:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        insertar_alerta(path, usuario, baseline.get(path, "DESCONOCIDO"), "ELIMINADO", elapsed_ms)
        eliminar_de_inventario(path)
        if progress_callback:
            progress_callback(path, "ELIMINADO")

    # Fin
    if completion_callback:
        completion_callback()


def monitor_continuo(poll_interval=1.0, stop_event=None, progress_callback=None, completion_callback=None):
    """Ejecuta verificaciones periódicas hasta que `stop_event` esté seteado.

    `poll_interval` en segundos. Diseñado para uso en modo headless o en hilo.
    """
    if stop_event is None:
        # crear objeto simple con atributo is_set si no se provee
        class E:
            def __init__(self):
                self._v = False
            def is_set(self):
                return self._v
        stop_event = E()

    while not stop_event.is_set():
        try:
            verificar_integridad(progress_callback=progress_callback, completion_callback=completion_callback)
        except Exception:
            # no romper el loop por error puntual
            pass
        time.sleep(poll_interval)


def obtener_usuario():
    """Obtener nombre de usuario del sistema de forma robusta sin libs extra."""
    try:
        return os.getlogin()
    except Exception:
        # Fallback a variables de entorno comunes
        for k in ("USER", "USERNAME", "LOGNAME"):
            v = os.environ.get(k)
            if v:
                return v
    return "desconocido"


# ----------------- Interfaz Web en localhost -----------------

def get_dashboard_data():
    rows = obtener_alertas(limit=100)
    return {
        "files": contar_archivos_observados(),
        "alerts": contar_alertas(),
        "last_event": obtener_ultimo_evento(),
        "rows": rows,
    }


def build_dashboard_html(message=None):
    data = get_dashboard_data()
    rows_html = ""
    for ruta, fecha, usuario, tiempo_ms, hash_ant, hash_nuevo in data["rows"]:
        evento = "Modificado"
        if hash_nuevo == "ELIMINADO":
            evento = "Eliminado"
        elif hash_nuevo == "ERROR_LECTURA":
            evento = "Error lectura"
        elif hash_ant in (None, "NUEVO", "HASH_BASE_VACIO"):
            evento = "Nuevo"
        elif hash_ant == hash_nuevo:
            evento = "Sin cambio"
        tiempo_str = f"{tiempo_ms:.2f}" if isinstance(tiempo_ms, (int, float)) else str(tiempo_ms)
        rows_html += (
            "<tr>"
            f"<td>{html.escape(ruta)}</td>"
            f"<td>{html.escape(fecha)}</td>"
            f"<td>{html.escape(usuario or '')}</td>"
            f"<td>{html.escape(evento)}</td>"
            f"<td>{html.escape(tiempo_str)}</td>"
            f"<td>{html.escape(hash_ant or '')}</td>"
            f"<td>{html.escape(hash_nuevo or '')}</td>"
            "</tr>"
        )
    if not rows_html:
        rows_html = "<tr><td colspan='7'>Sin alertas todavía</td></tr>"

    message_html = ""
    if message:
        message_html = f"<div class='message'>{html.escape(message)}</div>"

    return f"""<!doctype html>
<html lang='es'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>FIM Dashboard</title>
  <style>
    :root {{
      --bg: #07111f;
      --panel: #0f172a;
      --panel-2: #111c32;
      --border: #243244;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --accent-2: #22c55e;
      --danger: #ef4444;
      --warning: #f59e0b;
    }}
    * {{ box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: linear-gradient(135deg, var(--bg), #111827 70%); color: var(--text); }}
    .container {{ max-width: 1320px; margin: 0 auto; padding: 28px; }}
    .hero {{ background: linear-gradient(135deg, rgba(56,189,248,0.2), rgba(34,197,94,0.12)); border: 1px solid var(--border); border-radius: 20px; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.25); }}
    .header {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; }}
    .title {{ font-size: 30px; margin: 0; font-weight: 700; }}
    .subtitle {{ color: var(--muted); margin-top: 6px; }}
    .pill {{ display: inline-block; padding: 7px 12px; background: rgba(56,189,248,0.16); border: 1px solid rgba(56,189,248,0.35); border-radius: 999px; color: #bae6fd; font-size: 13px; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-top: 18px; }}
    .stat {{ background: rgba(255,255,255,0.04); border: 1px solid var(--border); border-radius: 14px; padding: 16px; }}
    .stat .label {{ color: var(--muted); font-size: 13px; text-transform: uppercase; letter-spacing: .08em; }}
    .stat .value {{ font-size: 24px; font-weight: 700; margin-top: 6px; }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 16px; padding: 18px; margin-top: 18px; box-shadow: 0 8px 24px rgba(0,0,0,0.18); }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 10px; }}
    button {{ background: linear-gradient(135deg, var(--accent), #2563eb); color: white; border: none; border-radius: 10px; padding: 10px 14px; cursor: pointer; font-weight: 600; box-shadow: 0 6px 16px rgba(56,189,248,0.18); }}
    button.danger {{ background: linear-gradient(135deg, var(--danger), #b91c1c); }}
    button:hover {{ transform: translateY(-1px); }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ border-bottom: 1px solid var(--border); padding: 10px 8px; text-align: left; }}
    th {{ background: rgba(255,255,255,0.04); color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
    tr:hover {{ background: rgba(255,255,255,0.03); }}
    .message {{ padding: 12px 14px; border-radius: 10px; background: rgba(34,197,94,0.16); border: 1px solid rgba(34,197,94,0.3); color: #bbf7d0; margin-top: 14px; }}
    .badge {{ display: inline-block; padding: 6px 10px; border-radius: 999px; background: rgba(245,158,11,0.16); color: #fde68a; font-size: 12px; }}
  </style>
</head>
<body>
  <div class='container'>
    <div class='hero'>
      <div class='header'>
        <div>
          <h1 class='title'>🛡️ FIM Dashboard</h1>
          <div class='subtitle'>Monitoreo de integridad de archivos · Ubuntu + Metasploitable2</div>
        </div>
        <div class='pill'>localhost:8000</div>
      </div>
      {message_html}
      <div class='stats'>
        <div class='stat'><div class='label'>Archivos observados</div><div class='value'>{data['files']}</div></div>
        <div class='stat'><div class='label'>Alertas registradas</div><div class='value'>{data['alerts']}</div></div>
        <div class='stat'><div class='label'>Último evento</div><div class='value'>{html.escape(data['last_event'])}</div></div>
      </div>
    </div>
    <div class='card'>
      <div class='actions'>
        <form method='post' action='/action'><input type='hidden' name='action' value='baseline'><button>Establecer Línea Base</button></form>
        <form method='post' action='/action'><input type='hidden' name='action' value='scan'><button>Escanear Ahora</button></form>
        <form method='post' action='/action'><input type='hidden' name='action' value='sync'><button>Sincronizar Remoto</button></form>
        <form method='post' action='/action'><input type='hidden' name='action' value='clear'><button class='danger'>Limpiar Alertas</button></form>
      </div>
    </div>
    <div class='card'>
      <div class='badge'>Historial de alertas</div>
      <table>
        <thead><tr><th>Ruta</th><th>Fecha/Hora</th><th>Usuario</th><th>Evento</th><th>Tiempo (ms)</th><th>Hash anterior</th><th>Hash nuevo</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </div>
</body>
</html>"""


class FIMWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(build_dashboard_html(message=self._get_query_message(parsed.query)).encode("utf-8"))
            return
        self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/action":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        form = urllib.parse.parse_qs(body)
        action = form.get("action", [""])[0]

        message = "Acción ejecutada"
        if action == "baseline":
            establecer_linea_base()
            message = "Línea base establecida"
        elif action == "scan":
            verificar_integridad()
            message = "Escaneo completado"
        elif action == "sync":
            ok = sincronizar_remoto()
            message = "Sincronización remota completada" if ok else "Sincronización remota fallida"
        elif action == "clear":
            limpiar_alertas()
            message = "Alertas limpiadas"
        else:
            message = "Acción no reconocida"

        self.send_response(303)
        self.send_header("Location", f"/?message={urllib.parse.quote(message)}")
        self.end_headers()

    def _get_query_message(self, query):
        params = urllib.parse.parse_qs(query)
        return params.get("message", [None])[0]


def start_web_server(host="127.0.0.1", port=8000):
    server = ThreadingHTTPServer((host, port), FIMWebHandler)
    print(f"SERVIDOR_WEB_ACTIVO http://{host}:{port}")
    server.serve_forever()


# ----------------- Interfaz Gráfica (Tkinter) -----------------


class FIMApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🛡️ SISTEMA DE MONITOREO DE INTEGRIDAD (FIM)")
        self.geometry("980x660")
        self.resizable(False, False)

        # Tema oscuro básico
        self.style = ttk.Style(self)
        self._setup_style()

        self.summary_files_var = tk.StringVar(value="Archivos: 0")
        self.summary_alerts_var = tk.StringVar(value="Alertas: 0")
        self.summary_scan_var = tk.StringVar(value="Último evento: N/A")
        self.summary_monitor_var = tk.StringVar(value="Monitoreo: OFF")

        # Widgets
        self._create_header()
        self._create_controls()
        self._create_treeview()

        # Estado de parpadeo
        self._blink_job = None
        self._blink_state = False
        self._monitoring = False
        self._monitor_stop = None

        # Cargar alertas iniciales
        self.refresh_alerts()

    def _setup_style(self):
        # Colores base
        bg = "#1e1e2e"
        panel = "#313244"
        fg = "#cdd6f4"
        success = "#a6e3a1"
        danger = "#f38ba8"

        self.configure(bg=bg)
        self.style.theme_use("clam")
        self.style.configure("TFrame", background=panel)
        self.style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), background=bg, foreground=fg)
        self.style.configure("Card.TFrame", background=panel, relief="flat")
        self.style.configure("TButton", background="#2b2b3a", foreground=fg)

        # Treeview style
        self.style.configure("Treeview", background=panel, fieldbackground=panel, foreground=fg)
        self.style.configure("Treeview.Heading", background="#252534", foreground=fg)
        self.style.map("TButton", background=[("active", "#3a3a4a")])

        # Guardar colores para uso posterior
        self._colors = {"bg": bg, "panel": panel, "fg": fg, "success": success, "danger": danger}

    def _create_header(self):
        header = ttk.Frame(self, style="Card.TFrame")
        header.place(x=12, y=12, width=956, height=100)

        title = ttk.Label(header, text="🛡️ SISTEMA DE MONITOREO DE INTEGRIDAD (FIM)", style="Header.TLabel")
        title.place(x=20, y=10)

        self.status_label = ttk.Label(header, text="🟢 SISTEMA SEGURO", font=("Segoe UI", 12, "bold"))
        self.status_label.place(x=20, y=50)

        # Panel de resumen rápido
        ttk.Label(header, textvariable=self.summary_files_var, font=("Segoe UI", 10, "bold"), foreground=self._colors["success"]).place(x=520, y=15)
        ttk.Label(header, textvariable=self.summary_alerts_var, font=("Segoe UI", 10, "bold"), foreground=self._colors["danger"]).place(x=520, y=35)
        ttk.Label(header, textvariable=self.summary_monitor_var, font=("Segoe UI", 10, "bold"), foreground=self._colors["fg"]).place(x=520, y=55)
        ttk.Label(header, textvariable=self.summary_scan_var, font=("Segoe UI", 9), foreground=self._colors["fg"]).place(x=520, y=75)

    def _create_controls(self):
        panel = ttk.Frame(self, style="Card.TFrame")
        panel.place(x=12, y=120, width=956, height=108)

        btn_base = ttk.Button(panel, text="Establecer Línea Base", command=self.on_baseline)
        btn_base.place(x=12, y=12, width=180, height=36)

        btn_scan = ttk.Button(panel, text="Escanear Ahora", command=self.on_scan)
        btn_scan.place(x=210, y=12, width=160, height=36)

        self.btn_monitor = ttk.Button(panel, text="Monitor Continuo: OFF", command=self._toggle_monitor)
        self.btn_monitor.place(x=390, y=12, width=180, height=36)

        btn_clear = ttk.Button(panel, text="Limpiar Alertas", command=self.on_clear_alerts)
        btn_clear.place(x=580, y=12, width=140, height=36)

        btn_sync = ttk.Button(panel, text="Sincronizar Remoto", command=self.on_remote_sync)
        btn_sync.place(x=730, y=12, width=140, height=36)

        # Descripción de funciones
        descripcion = (
            "Ubuntu solo observa. Los cambios deben venir desde Metasploitable2 y se detectan al sincronizar la carpeta remota."
        )
        lbl_desc = ttk.Label(panel, text=descripcion, wraplength=900, font=("Segoe UI", 9), foreground=self._colors["fg"])
        lbl_desc.place(x=12, y=58, width=900, height=28)

        # Indicador de progreso/estado
        self.progress_var = tk.StringVar(value="Listo")
        lbl_prog = ttk.Label(panel, textvariable=self.progress_var)
        lbl_prog.place(x=20, y=88)

        self.monitor_indicator = ttk.Label(panel, textvariable=self.summary_monitor_var, font=("Segoe UI", 9, "italic"), foreground=self._colors["fg"])
        self.monitor_indicator.place(x=210, y=58)

    def _create_treeview(self):
        frame = ttk.Frame(self, style="Card.TFrame")
        frame.place(x=12, y=230, width=956, height=408)
        cols = ("ruta", "fecha", "usuario", "evento", "tiempo_ms", "hash_ant", "hash_new")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=18)
        self.tree.heading("ruta", text="Ruta")
        self.tree.heading("fecha", text="Fecha/Hora (UTC)")
        self.tree.heading("usuario", text="Usuario")
        self.tree.heading("evento", text="Evento")
        self.tree.heading("tiempo_ms", text="Tiempo Detección (ms)")
        self.tree.heading("hash_ant", text="Hash Anterior")
        self.tree.heading("hash_new", text="Hash Nuevo")
        self.tree.column("ruta", width=260)
        self.tree.column("fecha", width=140)
        self.tree.column("usuario", width=100)
        self.tree.column("evento", width=100)
        self.tree.column("tiempo_ms", width=120, anchor="e")
        self.tree.column("hash_ant", width=220)
        self.tree.column("hash_new", width=220)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.place(x=12, y=12, width=908, height=360)
        vsb.place(x=924, y=12, height=360)
        hsb.place(x=12, y=376, width=908)

    # ----------------- Acciones de botones -----------------
    def on_baseline(self):
        def progress(path, estado):
            self.progress_var.set(f"Línea base: {os.path.basename(path)} -> {estado}")

        def run():
            try:
                establecer_linea_base(progress_callback=progress)
                self.after(100, lambda: self.progress_var.set("Línea base establecida."))
                self.after(200, self.refresh_alerts)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", f"Error al establecer línea base: {e}"))

        threading.Thread(target=run, daemon=True).start()

    def on_scan(self):
        # Evitar múltiples escaneos simultáneos
        if getattr(self, "_scanning", False):
            return
        self._scanning = True
        self.progress_var.set("Escaneando...")
        self.btn_monitor.config(state="disabled")

        def progress(path, estado):
            # Actualizar UI desde hilo principal
            self.after(0, lambda: self.progress_var.set(f"{os.path.basename(path)} -> {estado}"))

        def completion():
            self._scanning = False
            self.btn_monitor.config(state="normal")
            self.after(0, lambda: self.progress_var.set("Escaneo finalizado."))
            self.after(100, self.refresh_alerts)
            self.after(0, lambda: self.summary_monitor_var.set("Monitoreo: OFF" if not self._monitoring else "Monitoreo: ON"))

        threading.Thread(target=lambda: verificar_integridad(progress_callback=progress, completion_callback=completion), daemon=True).start()

    def _toggle_monitor(self):
        if self._monitoring:
            self._stop_monitor()
        else:
            self._start_monitor()

    def _start_monitor(self, interval=1.0):
        if self._monitoring:
            return
        self._monitoring = True
        self._monitor_stop = threading.Event()
        self.btn_monitor.config(text=f"Monitor Continuo: ON")

        def progress(path, estado):
            self.after(0, lambda: self.progress_var.set(f"Monitoreo: {os.path.basename(path)} -> {estado}"))

        def completion():
            self.after(0, self.refresh_alerts)

        def loop():
            monitor_continuo(poll_interval=interval, stop_event=self._monitor_stop, progress_callback=progress, completion_callback=completion)

        threading.Thread(target=loop, daemon=True).start()

    def _stop_monitor(self):
        if not self._monitoring:
            return
        self._monitoring = False
        if self._monitor_stop:
            self._monitor_stop.set()
        self.btn_monitor.config(text=f"Monitor Continuo: OFF")
        self.summary_monitor_var.set("Monitoreo: OFF")

    def on_remote_sync(self):
        self.progress_var.set("Sincronizando remoto...")
        def progress(path, estado):
            self.after(0, lambda: self.progress_var.set(f"{os.path.basename(path)} -> {estado}"))

        def worker():
            sincronizar_remoto(progress_callback=progress)
            self.after(0, lambda: self.progress_var.set("Sincronización remota completada."))
            self.after(100, self.refresh_alerts)

        threading.Thread(target=worker, daemon=True).start()

    def _calcular_evento(self, hash_ant, hash_nuevo):
        if hash_nuevo == "ELIMINADO":
            return "Eliminado"
        if hash_nuevo == "ERROR_LECTURA":
            return "Error lectura"
        if hash_ant in (None, "NUEVO", "HASH_BASE_VACIO"):
            return "Nuevo"
        if hash_ant == hash_nuevo:
            return "Sin cambio"
        return "Modificado"

    def on_clear_alerts(self):
        if not messagebox.askyesno("Confirmar", "¿Limpiar todas las alertas?"):
            return
        try:
            limpiar_alertas()
            self.refresh_alerts()
            self.progress_var.set("Alertas limpiadas.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudieron limpiar las alertas: {e}")

    # ----------------- Actualización UI -----------------
    def refresh_alerts(self):
        # Actualizar Treeview con alertas
        for r in self.tree.get_children():
            self.tree.delete(r)

        rows = obtener_alertas(limit=500)
        compromised = False
        for ruta, fecha, usuario, tiempo_ms, hash_ant, hash_nuevo in rows:
            tiempo_str = f"{tiempo_ms:.2f}" if isinstance(tiempo_ms, (int, float)) else str(tiempo_ms)
            evento = self._calcular_evento(hash_ant, hash_nuevo)
            self.tree.insert("", "end", values=(ruta, fecha, usuario, evento, tiempo_str, hash_ant or "", hash_nuevo or ""))
            compromised = True

        self.summary_files_var.set(f"Archivos: {contar_archivos_observados()}")
        self.summary_alerts_var.set(f"Alertas: {contar_alertas()}")
        self.summary_scan_var.set(f"Último evento: {obtener_ultimo_evento()}")
        self.summary_monitor_var.set("Monitoreo: ON" if self._monitoring else "Monitoreo: OFF")

        # Actualizar indicador
        if compromised:
            self._set_compromised(True)
        else:
            self._set_compromised(False)

    def _set_compromised(self, compromised: bool):
        if compromised:
            # Texto y parpadeo en rojo
            self.status_label.config(text="⚠️ ¡SISTEMA COMPROMETIDO!")
            if self._blink_job is None:
                self._blink()
        else:
            # Texto verde y detener parpadeo
            self.status_label.config(text="🟢 SISTEMA SEGURO", foreground=self._colors["success"])
            if self._blink_job is not None:
                self.after_cancel(self._blink_job)
                self._blink_job = None
            # asegurar color normal
            self.status_label.config(foreground=self._colors["success"])

    def _blink(self):
        # Cambia color entre rojo y fondo para llamar la atención
        fg = self._colors["danger"] if self._blink_state else self._colors["bg"]
        self.status_label.config(foreground=fg)
        self._blink_state = not self._blink_state
        self._blink_job = self.after(600, self._blink)


def main():
    # Evitar ejecución en Windows para que no monitoree rutas locales de Windows.
    if platform.system().lower().startswith("win"):
        print("ERROR: Este script debe ejecutarse en Ubuntu Desktop, no en Windows.")
        return

    # Inicialización
    init_db()
    ensure_watch_dir()

    # CLI: modo headless para entornos sin tkinter
    import argparse
    parser = argparse.ArgumentParser(description="PoC FIM - modo CLI/GUI/web")
    parser.add_argument("--headless", action="store_true", help="Ejecutar en modo sin GUI (CLI)")
    parser.add_argument("--action", choices=["baseline","scan","monitor","clear","sync"], help="Acción a ejecutar en modo headless")
    parser.add_argument("--monitor-interval", type=float, default=1.0, help="Intervalo (s) para monitor continuo en modo headless")
    parser.add_argument("--web", action="store_true", help="Iniciar una interfaz web en localhost:8000")
    parser.add_argument("--tk", action="store_true", help="Abrir la interfaz Tkinter clásica")
    args = parser.parse_args()

    if args.headless:
        # Ejecutar acción solicitada y salir (o monitor continuo)
        if args.action == "baseline":
            establecer_linea_base()
            print("LINEA_BASE_OK")
        elif args.action == "scan":
            verificar_integridad()
            print("ESCANEO_OK")
        elif args.action == "clear":
            limpiar_alertas()
            print("ALERTAS_LIMPIADAS")
        elif args.action == "sync":
            success = sincronizar_remoto()
            if success:
                print("SINCRONIZACION_REMOTA_OK")
            else:
                print("SINCRONIZACION_REMOTA_FALLO")
        elif args.action == "monitor":
            print(f"INICIANDO_MONITOR_CONTINUO intervalo={args.monitor_interval}s (CTRL-C para parar)")
            try:
                stop = threading.Event()
                monitor_continuo(poll_interval=args.monitor_interval, stop_event=stop)
            except KeyboardInterrupt:
                print("MONITOR_DETENIDO")
        else:
            print("Modo headless: especifique --action baseline|scan|monitor|simulate|clear")
        return

    if args.web:
        start_web_server()
        return

    # Si no hay tkinter disponible, informar y salir
    if not GUI_AVAILABLE:
        print("tkinter no disponible en este entorno. Use --web o --headless para ejecutar en modo web/CLI.")
        return

    if args.tk:
        app = FIMApp()
        app.mainloop()
        return

    # Por defecto, abrir la interfaz web para que sea más usable.
    start_web_server()


if __name__ == "__main__":
    main()
