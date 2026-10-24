package org.example.server;

import io.vertx.core.Vertx;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.ThreadMXBean;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

/**
 * PAI-2 persona B (RS3): cada segundo apunta el consumo de CPU y RAM del proceso servidor en
 * logs/recursos-servidor-<modo>.csv, para comparar después la carga con TLS y sin TLS.
 */
public final class ResourceMonitor {

    private ResourceMonitor() {}

    public static void start(Vertx vertx, String modo) {
        Path out = Path.of("logs", "recursos-servidor-" + modo + ".csv");
        com.sun.management.OperatingSystemMXBean os =
                (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        MemoryMXBean mem = ManagementFactory.getMemoryMXBean();
        ThreadMXBean threads = ManagementFactory.getThreadMXBean();
        try {
            Files.createDirectories(out.getParent());
            if (!Files.exists(out)) Files.writeString(out, "timestamp,cpu_proceso_pct,heap_usado_mb,rss_aprox_mb,hilos\n");
        } catch (IOException e) {
            System.err.println("ResourceMonitor desactivado: " + e.getMessage());
            return;
        }

        vertx.setPeriodic(1000, id -> {
            double cpu = Math.max(0, os.getProcessCpuLoad()) * 100; // % del total de núcleos de la máquina
            long heap = mem.getHeapMemoryUsage().getUsed() / (1024 * 1024);
            long noHeap = mem.getNonHeapMemoryUsage().getUsed() / (1024 * 1024);
            String line = String.format(java.util.Locale.ROOT, "%s,%.1f,%d,%d,%d%n",
                    Instant.now(), cpu, heap, heap + noHeap, threads.getThreadCount());
            // La escritura es pequeña, pero se hace fuera del event loop por si el disco va lento
            vertx.executeBlocking(() -> Files.writeString(out, line, StandardOpenOption.APPEND), false);
        });
    }
}
