package org.example.crypto;

import io.vertx.core.Future;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.Tuple;

import java.time.Instant;

// RS3. Protección contra Ataques de Replay (Reintervención)
public class NonceStore {

    // Ventana de tiempo máxima aceptada (5 minutos = 300 segundos)
    private static final long TIME_WINDOW_SECONDS = 300;

    public static boolean isTimestampValid(long requestTimestamp) {
        long currentTimestamp = Instant.now().getEpochSecond();
        long difference = Math.abs(currentTimestamp - requestTimestamp);
        return difference <= TIME_WINDOW_SECONDS;
    }

    /**
     * Intenta registrar el nonce en la BD. Devuelve (de forma asíncrona) true si era
     * nuevo (se pudo insertar), o false si ya existía (Replay detectado).
     */
    public static Future<Boolean> registerAndCheckNonce(Pool client, String nonce, long timestamp) {
        return client.preparedQuery("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)")
                .execute(Tuple.of(nonce, timestamp))
                .map(rows -> true) // el INSERT tuvo éxito -> el nonce era nuevo
                .recover(err -> {
                    // Si salta por violar la PRIMARY KEY, el nonce ya existía -> Replay
                    if (err.getMessage() != null && err.getMessage().contains("Duplicate entry")) {
                        return Future.succeededFuture(false);
                    }

                    return Future.failedFuture(err);
                });
    }
}