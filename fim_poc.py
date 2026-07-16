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
DB_FILENAME = "integridad_monitores.db"
WATCH_DIR = os.path.join(os.getcwd(), "archivos_criticos")
TEST_FILENAME = os.path.join(WATCH_DIR, "config.cfg")


def get_db_connection():
    """Crear y devolver una conexión SQLite.

    Cada hilo debe crear su propia conexión para evitar conflictos con
    `check_same_thread`.
    """
    conn = sqlite3.connect(DB_FILENAME, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Crear la base de datos y las tablas si no existen."""
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


def establecer_linea_base(progress_callback=None):
    """Escanea la carpeta y guarda/actualiza la línea base en `inventario`.

    Si `progress_callback` es una función, se la llama con (ruta, estado).
    """
    ensure_watch_dir()
    archivos = []
    for root, _, files in os.walk(WATCH_DIR):
        for fn in files:
            archivos.append(os.path.join(root, fn))

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
    return {r: h for r, h in rows}


def actualizar_ultima_verificacion(path, timestamp=None):
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


def verificar_integridad(progress_callback=None, completion_callback=None):
    """Verifica integridad comparando con la línea base y registra alertas.

    Esta función se puede ejecutar en un hilo secundario. Llama a
    `progress_callback(ruta, estado)` para informar de estados intermedios y
    `completion_callback()` al finalizar.
    """
    start = time.perf_counter()

    # Tomar snapshot de inventario (baseline)
    baseline = obtener_inventario()

    # Escanear archivos actuales
    actuales = []
    for root, _, files in os.walk(WATCH_DIR):
        for fn in files:
            actuales.append(os.path.join(root, fn))

    # Mapear para detección de eliminaciones
    baseline_paths = set(baseline.keys())
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
            # actualizar ultima_verificacion para este archivo en inventario (si existe)
            actualizar_ultima_verificacion(path)
            continue

        if path in baseline:
            if baseline[path] is None:
                # Línea base existente pero hash nulo (error previo)
                if progress_callback:
                    progress_callback(path, "HASH_BASE_VACIO")
                # comparar: si ahora tenemos hash, considerar como cambio
                if h is not None:
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    insertar_alerta(path, usuario, "HASH_BASE_VACIO", h, elapsed_ms)
            else:
                if h != baseline[path]:
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    insertar_alerta(path, usuario, baseline[path], h, elapsed_ms)
        else:
            # Archivo nuevo (no estaba en la línea base)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            insertar_alerta(path, usuario, "NUEVO", h, elapsed_ms)

        # actualizar última verificación
        actualizar_ultima_verificacion(path)
        if progress_callback:
            progress_callback(path, "VERIFICADO")

    # Detectar eliminaciones
    eliminados = baseline_paths - actuales_paths
    for path in eliminados:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        insertar_alerta(path, usuario, baseline.get(path, "DESCONOCIDO"), "ELIMINADO", elapsed_ms)
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

        btn_sim = ttk.Button(panel, text="Simular Modificación", command=self.on_simulate)
        btn_sim.place(x=730, y=12, width=200, height=36)

        # Indicador de progreso/estado
        self.progress_var = tk.StringVar(value="Listo")
        lbl_prog = ttk.Label(panel, textvariable=self.progress_var)
        lbl_prog.place(x=20, y=58)

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

    def on_simulate(self):
        # Modificar ligeramente el archivo de prueba para simular ataque
        try:
            ensure_watch_dir()
            if not os.path.exists(TEST_FILENAME):
                with open(TEST_FILENAME, "w", encoding="utf-8") as f:
                    f.write("# config inicial\n")
            # Añadir una línea con timestamp
            with open(TEST_FILENAME, "a", encoding="utf-8") as f:
                f.write(f"# modificación simulada {datetime.datetime.utcnow().isoformat()}\n")
            self.progress_var.set("Archivo modificado (simulación).")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo simular la modificación: {e}")

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

    def _calcular_evento(self, hash_ant, hash_nuevo):
        if hash_nuevo == "ELIMINADO":
            return "Eliminado"
        if hash_ant in (None, "NUEVO", "HASH_BASE_VACIO"):
            return "Nuevo"
        if hash_nuevo == "ERROR_LECTURA":
            return "Error lectura"
        if hash_ant == hash_nuevo:
            return "Sin cambio"
        return "Modificado"

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
    # Inicialización
    init_db()
    ensure_watch_dir()

    # CLI: modo headless para entornos sin tkinter
    import argparse
    parser = argparse.ArgumentParser(description="PoC FIM - modo CLI/GUI")
    parser.add_argument("--headless", action="store_true", help="Ejecutar en modo sin GUI (CLI)")
    parser.add_argument("--action", choices=["baseline","scan","monitor","simulate","clear"], help="Acción a ejecutar en modo headless")
    parser.add_argument("--monitor-interval", type=float, default=1.0, help="Intervalo (s) para monitor continuo en modo headless")
    args = parser.parse_args()

    if args.headless:
        # Ejecutar acción solicitada y salir (o monitor continuo)
        if args.action == "baseline":
            establecer_linea_base()
            print("LINEA_BASE_OK")
        elif args.action == "scan":
            verificar_integridad()
            print("ESCANEO_OK")
        elif args.action == "simulate":
            ensure_watch_dir()
            with open(TEST_FILENAME, "a", encoding="utf-8") as f:
                f.write(f"# simulacion {datetime.datetime.utcnow().isoformat()}\n")
            print("SIMULACION_OK")
        elif args.action == "clear":
            limpiar_alertas()
            print("ALERTAS_LIMPIADAS")
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

    # Si no hay tkinter disponible, informar y salir
    if not GUI_AVAILABLE:
        print("tkinter no disponible en este entorno. Use --headless para ejecutar en modo CLI.")
        return

    app = FIMApp()
    app.mainloop()


if __name__ == "__main__":
    main()
