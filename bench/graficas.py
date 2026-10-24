"""PAI-2 persona B (RS3): gráficas del benchmark TLS frente a plano para la memoria.

Uso (desde la raíz del proyecto, después de ejecutar LoadTestClient en los dos modos):
    python bench/graficas.py
Lee bench/resultados.csv (se queda con la última ejecución de cada modo) y logs/recursos-servidor-*.csv,
y guarda los PNG en bench/graficas/. Requiere pandas y matplotlib.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

SALIDA = Path("bench/graficas")
SALIDA.mkdir(parents=True, exist_ok=True)
COLORES = {"tls": "#2a6fb0", "plano": "#c8783a"}

res = pd.read_csv("bench/resultados.csv")
ultima = res[res["fecha"] == res.groupby("modo")["fecha"].transform("max")]  # última ejecución por modo
fases = list(dict.fromkeys(ultima["fase"]))
modos = [m for m in ("plano", "tls") if m in set(ultima["modo"])]


def barras(columna, titulo, eje_y, fichero):
    fig, ax = plt.subplots(figsize=(8, 4))
    ancho = 0.8 / len(modos)
    for i, modo in enumerate(modos):
        datos = ultima[ultima["modo"] == modo].set_index("fase").reindex(fases)
        ax.bar([x + i * ancho for x in range(len(fases))], datos[columna], ancho,
               label=modo.upper(), color=COLORES[modo])
    ax.set_xticks([x + ancho * (len(modos) - 1) / 2 for x in range(len(fases))], fases)
    ax.set_title(titulo)
    ax.set_ylabel(eje_y)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(SALIDA / fichero, dpi=150)
    plt.close(fig)


barras("throughput_ops_s", "Throughput por fase (300 dispositivos)", "operaciones/s", "throughput.png")
barras("lat_media_ms", "Latencia media por fase", "ms", "latencia_media.png")
barras("lat_p95_ms", "Latencia p95 por fase", "ms", "latencia_p95.png")

# Sobrecoste de TLS respecto al tráfico sin cifrar, fase a fase
if len(modos) == 2:
    t = ultima[ultima["modo"] == "tls"].set_index("fase")
    p = ultima[ultima["modo"] == "plano"].set_index("fase")
    overhead = ((t["lat_media_ms"] / p["lat_media_ms"] - 1) * 100).reindex(fases)
    overhead.round(1).to_csv(SALIDA / "overhead_latencia_pct.csv", header=["overhead_pct"])
    print("Sobrecoste de latencia media de TLS frente a plano (%):")
    print(overhead.round(1).to_string())

# CPU y RAM del servidor a lo largo de la prueba
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 6), sharex=False)
for modo in modos:
    f = Path(f"logs/recursos-servidor-{modo}.csv")
    if not f.exists():
        continue
    r = pd.read_csv(f)
    segundos = range(len(r))
    ax1.plot(segundos, r["cpu_proceso_pct"], label=modo.upper(), color=COLORES[modo])
    ax2.plot(segundos, r["heap_usado_mb"], label=modo.upper(), color=COLORES[modo])
ax1.set_title("CPU del servidor")
ax1.set_ylabel("% CPU")
ax2.set_title("Heap del servidor")
ax2.set_ylabel("MB")
ax2.set_xlabel("segundos desde el arranque")
for ax in (ax1, ax2):
    ax.legend()
    ax.grid(alpha=0.3)
fig.tight_layout()
fig.savefig(SALIDA / "recursos_servidor.png", dpi=150)
print(f"Gráficas guardadas en {SALIDA}/")
