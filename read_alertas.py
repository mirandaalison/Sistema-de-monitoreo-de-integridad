import sqlite3, json

DB = 'integridad_monitores.db'

conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT ruta_archivo, fecha_hora, usuario, tiempo_deteccion_ms, hash_anterior, hash_nuevo FROM alertas ORDER BY id DESC LIMIT 10")
rows = cur.fetchall()
conn.close()

print('ALERTAS_ENCONTRADAS:', len(rows))
print(json.dumps(rows, default=str, ensure_ascii=False, indent=2))
