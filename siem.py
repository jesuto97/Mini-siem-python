import sqlite3
import re

# Conectar a base de datos
conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Crear tabla de logs
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    status TEXT,
    raw TEXT
)
""")

# Crear tabla de alertas
cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    type TEXT
)
""")

# Función detección amenazas
def detect_threats(line, ip):
    alerts = []

    if "401" in line:
        alerts.append("Failed Login")

    if re.search(r"('|--|OR 1=1)", line, re.IGNORECASE):
        alerts.append("SQL Injection")

    return alerts

print("🔍 Iniciando mini SIEM...\n")

# Leer logs
with open("logs.txt", "r") as file:
    for line in file:
        ip = line.split(" ")[0]
        status = "401" if "401" in line else "200"

        # Guardar log
        cursor.execute(
            "INSERT INTO logs (ip, status, raw) VALUES (?, ?, ?)",
            (ip, status, line)
        )

        # Detectar amenazas
        threats = detect_threats(line, ip)

        for threat in threats:
            print(f"[ALERTA] {threat} detectado desde {ip}")

            cursor.execute(
                "INSERT INTO alerts (ip, type) VALUES (?, ?)",
                (ip, threat)
            )

conn.commit()

# CONSULTAS SOC
print("\n📊 IPs sospechosas (fuerza bruta):")
cursor.execute("""
SELECT ip, COUNT(*) 
FROM logs 
WHERE status='401'
GROUP BY ip
HAVING COUNT(*) > 3
""")

for row in cursor.fetchall():
    print(row)

print("\n🚨 Alertas registradas:")
cursor.execute("SELECT * FROM alerts")

for row in cursor.fetchall():
    print(row)

conn.close()
