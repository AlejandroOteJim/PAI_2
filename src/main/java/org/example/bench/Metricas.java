package org.example.bench;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * PAI-2 persona B (RS3): recoge la latencia de cada operación del benchmark, separada por fase.
 * La usan a la vez los 300 hilos del cliente de carga, por eso todos los métodos están sincronizados.
 */
final class Metricas {

    record Muestra(String usuario, double ms, boolean ok) {}

    record Resumen(int total, int ok, int errores, double media, double p50, double p95, double p99, double max) {}

    private final Map<String, List<Muestra>> porFase = new LinkedHashMap<>();
    private final List<String> primerosErrores = new ArrayList<>();

    synchronized void ok(String fase, String usuario, long nanos) {
        porFase.computeIfAbsent(fase, f -> new ArrayList<>()).add(new Muestra(usuario, nanos / 1e6, true));
    }

    // Respuesta HTTP con un código no esperado
    synchronized void fallo(String fase, String usuario, long nanos, String detalle) {
        porFase.computeIfAbsent(fase, f -> new ArrayList<>()).add(new Muestra(usuario, nanos / 1e6, false));
        anotar(fase + " " + usuario + ": " + detalle);
    }

    // Excepción (conexión rechazada, handshake fallido, timeout...)
    synchronized void error(String fase, String usuario, Exception e) {
        porFase.computeIfAbsent(fase, f -> new ArrayList<>()).add(new Muestra(usuario, 0, false));
        anotar(fase + " " + usuario + ": " + e.getClass().getSimpleName() + " " + e.getMessage());
    }

    private void anotar(String msg) {
        if (primerosErrores.size() < 10) primerosErrores.add(msg); // Solo los primeros, para no inundar la consola
    }

    synchronized List<Muestra> muestras(String fase) {
        return new ArrayList<>(porFase.getOrDefault(fase, List.of()));
    }

    synchronized List<String> primerosErrores() {
        return new ArrayList<>(primerosErrores);
    }

    // Media y percentiles calculados solo sobre las operaciones correctas
    synchronized Resumen resumen(String fase) {
        List<Muestra> todas = porFase.getOrDefault(fase, List.of());
        List<Double> lat = new ArrayList<>();
        for (Muestra m : todas) if (m.ok()) lat.add(m.ms());
        Collections.sort(lat);
        double media = lat.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        return new Resumen(todas.size(), lat.size(), todas.size() - lat.size(), media,
                percentil(lat, 50), percentil(lat, 95), percentil(lat, 99), lat.isEmpty() ? 0 : lat.get(lat.size() - 1));
    }

    // Percentil por el método del rango más cercano sobre una lista ya ordenada
    static double percentil(List<Double> ordenada, double p) {
        if (ordenada.isEmpty()) return 0;
        int idx = (int) Math.ceil(p / 100.0 * ordenada.size()) - 1;
        return ordenada.get(Math.max(0, Math.min(idx, ordenada.size() - 1)));
    }
}
