package org.example.bench;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Locale;

/**
 * PAI-2 persona B (RS3): imprime el resumen del benchmark y lo guarda para la memoria:
 *   bench/resultados.csv          una fila por fase y ejecución (se acumulan para comparar TLS y plano)
 *   bench/latencias-<modo>.csv    todas las latencias individuales de la última ejecución (para histogramas)
 */
final class Informe {

    private static final Path DIR = Path.of("bench");

    private Informe() {}

    static void imprimirYGuardar(String modo, int usuarios, int transferencias, Metricas m, long[] inicioFase,
                                 LoadTestClient.MuestreoRecursos recursos) throws IOException {
        Files.createDirectories(DIR);
        Path resultados = DIR.resolve("resultados.csv");
        if (!Files.exists(resultados)) {
            Files.writeString(resultados, "fecha,modo,usuarios,transferencias,fase,ops,ok,errores,duracion_s,"
                    + "throughput_ops_s,lat_media_ms,lat_p50_ms,lat_p95_ms,lat_p99_ms,lat_max_ms\n");
        }
        String fecha = Instant.now().toString();

        System.out.printf("%n%-14s %5s %5s %5s %9s %11s %9s %9s %9s %9s %9s%n",
                "FASE", "ops", "ok", "err", "dur(s)", "ops/s", "media", "p50", "p95", "p99", "max(ms)");
        StringBuilder csv = new StringBuilder();
        for (int i = 0; i < LoadTestClient.FASES.length; i++) {
            String fase = LoadTestClient.FASES[i];
            Metricas.Resumen r = m.resumen(fase);
            // La duración de la fase va de la barrera de entrada a la de salida (todos los dispositivos terminados)
            double dur = inicioFase[i + 1] > 0 ? (inicioFase[i + 1] - inicioFase[i]) / 1e9 : 0;
            double thr = dur > 0 ? r.ok() / dur : 0;
            System.out.printf(Locale.ROOT, "%-14s %5d %5d %5d %9.3f %11.1f %9.2f %9.2f %9.2f %9.2f %9.2f%n",
                    fase, r.total(), r.ok(), r.errores(), dur, thr, r.media(), r.p50(), r.p95(), r.p99(), r.max());
            csv.append(String.format(Locale.ROOT, "%s,%s,%d,%d,%s,%d,%d,%d,%.3f,%.1f,%.2f,%.2f,%.2f,%.2f,%.2f%n",
                    fecha, modo, usuarios, transferencias, fase, r.total(), r.ok(), r.errores(), dur, thr,
                    r.media(), r.p50(), r.p95(), r.p99(), r.max()));
        }
        Files.writeString(resultados, csv, StandardOpenOption.APPEND);

        StringBuilder lat = new StringBuilder("modo,fase,usuario,latencia_ms,ok\n");
        for (String fase : LoadTestClient.FASES) {
            for (Metricas.Muestra s : m.muestras(fase)) {
                lat.append(String.format(Locale.ROOT, "%s,%s,%s,%.3f,%b%n", modo, fase, s.usuario(), s.ms(), s.ok()));
            }
        }
        Files.writeString(DIR.resolve("latencias-" + modo + ".csv"), lat);

        double[] cpu = recursos.mediaYMaximo(0);
        double[] ram = recursos.mediaYMaximo(1);
        double total = (inicioFase[LoadTestClient.FASES.length] - inicioFase[0]) / 1e9;
        System.out.printf(Locale.ROOT, "%nTiempo total: %.2f s. Cliente: CPU media %.1f%% (máx %.1f%%), heap medio %.0f MB (máx %.0f MB)%n",
                total, cpu[0], cpu[1], ram[0], ram[1]);
        System.out.println("CPU/RAM del servidor: logs/recursos-servidor-" + modo + ".csv (en la máquina del servidor)");
        System.out.println("Resultados añadidos a " + resultados + " y latencias en " + DIR.resolve("latencias-" + modo + ".csv"));
        if (!m.primerosErrores().isEmpty()) {
            System.out.println("\nPrimeros errores:");
            m.primerosErrores().forEach(e -> System.out.println("  " + e));
        }
    }
}
