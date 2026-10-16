package org.example.client;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

/** Escribe cada linea en consola y en logs/<nombre>.log (evidencia para la memoria). */
public final class EvidenceLog {
    private final Path file;

    public EvidenceLog(String name) {
        try {
            Files.createDirectories(Path.of("logs"));
            file = Path.of("logs", name + ".log");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void log(String msg) {
        String line = Instant.now() + "  " + msg;
        System.out.println(line);
        try {
            Files.writeString(file, line + System.lineSeparator(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}