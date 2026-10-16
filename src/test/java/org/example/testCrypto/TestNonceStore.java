package org.example.testCrypto;

import org.example.crypto.NonceStore;
import org.testng.annotations.Test;

import io.vertx.core.Vertx;
import io.vertx.mysqlclient.MySQLBuilder;
import io.vertx.mysqlclient.MySQLConnectOptions;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.PoolOptions;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class TestNonceStore {

    // NUEVO: necesario porque registerAndCheckNonce ahora consulta la BD, no memoria
    private static Pool crearPoolDePrueba() {
        Vertx vertx = Vertx.vertx();
        MySQLConnectOptions connectOptions = new MySQLConnectOptions()
                .setPort(3306).setHost("localhost").setDatabase("secbank")
                .setUser("root").setPassword("root");
        return MySQLBuilder.pool()
                .with(new PoolOptions().setMaxSize(2))
                .connectingTo(connectOptions)
                .using(vertx)
                .build();
    }

    @Test
    public void pruebaDeteccionAtaqueReplay() throws Exception {
        Pool pool = crearPoolDePrueba(); // NUEVO
        String noncePrueba = "nonce-test-" + java.util.UUID.randomUUID();
        long timestampPrueba = Instant.now().getEpochSecond(); // NUEVO: el método ahora pide timestamp también

        // Primer intento legítimo
        // CAMBIADO: se añaden pool y timestampPrueba como argumentos, y se espera el Future con .get()
        boolean primerIntento = NonceStore.registerAndCheckNonce(pool, noncePrueba, timestampPrueba)
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        assertTrue(primerIntento, "El primer uso del Nonce debe ser aceptado por el servidor.");

        // Segundo intento fraudulento (Replay Attack)
        boolean segundoIntento = NonceStore.registerAndCheckNonce(pool, noncePrueba, timestampPrueba)
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        assertFalse(segundoIntento, "El segundo uso del Nonce debe ser rechazado como ataque Replay.");
    }

    @Test
    public void pruebaTimestampValido() {
        // Creamos un timestamp de hace 30 segundos (dentro del límite permitido de 300 segundos)
        long timestampReciente = Instant.now().getEpochSecond() - 30;

        boolean esValido = NonceStore.isTimestampValid(timestampReciente);
        assertTrue(esValido, "El timestamp reciente debe considerarse válido.");
    }

    @Test
    public void pruebaTimestampCaducado() {
        // Creamos un timestamp de hace 1 hora (fuera del límite)
        long timestampAntiguo = Instant.now().getEpochSecond() - 3600;

        boolean esValido = NonceStore.isTimestampValid(timestampAntiguo);
        assertFalse(esValido, "El timestamp antiguo debe ser rechazado.");
    }
}