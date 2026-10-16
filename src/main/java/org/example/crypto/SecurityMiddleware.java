package org.example.crypto;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import io.vertx.sqlclient.Pool;

public class SecurityMiddleware implements Handler<RoutingContext> {

    private final byte[] secretKey;
    private final Pool dbClient;

    public SecurityMiddleware(byte[] secretKey, Pool dbClient) {
        this.secretKey = secretKey;
        this.dbClient = dbClient;
    }

    @Override
    public void handle(RoutingContext ctx) {
        String signature = ctx.request().getHeader("X-Signature");
        String nonce = ctx.request().getHeader("X-Nonce");
        String timestampStr = ctx.request().getHeader("X-Timestamp");

        if (signature == null || nonce == null || timestampStr == null) {
            ctx.response().setStatusCode(400).end("Faltan cabeceras de seguridad requeridas.");
            return;
        }

        long timestamp;
        try {
            timestamp = Long.parseLong(timestampStr);
        } catch (NumberFormatException e) {
            ctx.response().setStatusCode(400).end("Formato de Timestamp inválido.");
            return;
        }

        if (!NonceStore.isTimestampValid(timestamp)) {
            ctx.response().setStatusCode(401).end("Ataque detectado: El paquete ha caducado.");
            return;
        }

        String body = ctx.body().asString();
        if (body == null || body.isEmpty()) {
            ctx.response().setStatusCode(400).end("El cuerpo de la transacción (JSON) está vacío.");
            return;
        }

        // PRIMERO verificamos la firma HMAC — si el mensaje no es auténtico,
        // ni siquiera consultamos/registramos el nonce en BD.
        String messageToVerify = timestampStr + "\n" + nonce + "\n" + body;


        if (!HMACSigner.verifyHmac(messageToVerify, signature, secretKey)) {
            ctx.response().setStatusCode(401).end("Firma HMAC inválida: El mensaje ha sido alterado.");
            return;
        }

        // Solo si la firma es válida, comprobamos y registramos el nonce (RS3)
        NonceStore.registerAndCheckNonce(dbClient, nonce, timestamp)
                .onSuccess(esNuevo -> {
                    if (!esNuevo) {
                        ctx.response().setStatusCode(401).end("Ataque de Replay detectado: Nonce duplicado.");
                        return;
                    }

                    ctx.next();
                })
                .onFailure(err -> {
                    System.err.println("Error comprobando nonce en BD: " + err.getMessage());
                    ctx.response().setStatusCode(500).end("Error interno de seguridad.");
                });
    }
}