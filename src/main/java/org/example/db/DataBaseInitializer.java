package org.example.db;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.mysqlclient.MySQLBuilder;
import io.vertx.mysqlclient.MySQLConnectOptions;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.PoolOptions;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DataBaseInitializer {
    private static final String SCRIPT = "/db/schema.sql";

    public static Future<Void> init(Vertx vertx) {
        List<String> statements;
        try {
            statements = loadStatements();
        } catch (IOException e) {
            return Future.failedFuture(e);
        }

        // Sin .setDatabase(): la base "secbank" puede no existir todavía.
        MySQLConnectOptions options = new MySQLConnectOptions()
                .setHost("localhost")
                .setPort(3306)
                .setUser("root")
                .setPassword("root");

        Pool pool = MySQLBuilder.pool()
                .with(new PoolOptions().setMaxSize(1))
                .connectingTo(options)
                .using(vertx)
                .build();

        // withConnection garantiza que todas las sentencias (incluido USE secbank)
        // se ejecutan sobre la misma conexión.
        Future<Void> result = pool.withConnection(conn -> {
            Future<Void> chain = Future.succeededFuture();
            for (String sql : statements) {
                chain = chain.compose(v -> conn.query(sql).execute().mapEmpty());
            }
            return chain;
        });

        // Cerramos el pool pase lo que pase y devolvemos el resultado original
        Promise<Void> done = Promise.promise();
        result.onComplete(ar -> pool.close().onComplete(closed -> done.handle(ar)));
        return done.future();
    }

    private static List<String> loadStatements() throws IOException {
        try (InputStream in = DataBaseInitializer.class.getResourceAsStream(SCRIPT)) {
            if (in == null) {
                throw new IOException("No se encuentra " + SCRIPT + " en el classpath");
            }
            String script = new String(in.readAllBytes(), StandardCharsets.UTF_8);

            // Quitar comentarios de línea (-- ...) y trocear por ';'
            StringBuilder sinComentarios = new StringBuilder();
            for (String line : script.split("\\R")) {
                if (!line.trim().startsWith("--")) {
                    sinComentarios.append(line).append('\n');
                }
            }
            List<String> statements = new ArrayList<>();
            for (String s : sinComentarios.toString().split(";")) {
                if (!s.isBlank()) {
                    statements.add(s.trim());
                }
            }
            return statements;
        }
    }
}
