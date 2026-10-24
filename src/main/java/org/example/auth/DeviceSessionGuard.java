package org.example.auth;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;
import org.example.crypto.SecurityMiddleware;
import org.example.server.AuditLogger;
import org.example.server.ServerMode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * PAI-2 persona B: primer handler de las rutas protegidas (sustituye al "Handler 1" de /transfer).
 * Además de comprobar que la sesión existe y está activa, exige que la petición llegue por el mismo
 * certificado con el que se hizo el login y que ese certificado no se haya revocado después.
 * Si todo cuadra, delega en el SecurityMiddleware de la PAI-1 (HMAC + nonce + timestamp).
 */
public class DeviceSessionGuard implements Handler<RoutingContext> {

    private final Pool client;

    public DeviceSessionGuard(Pool client) {
        this.client = client;
    }

    @Override
    public void handle(RoutingContext ctx) {
        String authHeader = ctx.request().getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            AuditLogger.logRequestEvent(ctx.request(), "ACCESS_DENIED_NO_SESSION", "petición sin cabecera de sesión a " + ctx.request().path());
            ctx.response().setStatusCode(401).end("Falta cabecera de sesión o formato incorrecto");
            return;
        }
        String sessionId = authHeader.substring(7);
        DeviceIdentity device = DeviceIdentity.fromRequest(ctx.request());

        client.preparedQuery(
                        "SELECT s.hmac_key, u.username, b.cert_fingerprint, (r.serial IS NOT NULL) AS revoked " +
                                "FROM sessions s JOIN users u ON s.user_id = u.id " +
                                "LEFT JOIN session_bindings b ON b.session_id = s.session_id " +
                                "LEFT JOIN revoked_certificates r ON r.serial = b.cert_serial " +
                                "WHERE s.session_id = ? AND s.active = TRUE")
                .execute(Tuple.of(sessionId))
                .onSuccess(rows -> {
                    if (!rows.iterator().hasNext()) {
                        AuditLogger.logRequestEvent(ctx.request(), "ACCESS_DENIED_INVALID_SESSION",
                                "sesión inexistente o cerrada " + AuditLogger.sessionRef(sessionId));
                        ctx.response().setStatusCode(401).end("Sesión inválida o inactiva");
                        return;
                    }
                    Row row = rows.iterator().next();

                    if (ServerMode.tls()) {
                        if (!sameDevice(row.getString("cert_fingerprint"), device)) {
                            AuditLogger.logRequestEvent(ctx.request(), "ACCESS_DENIED_DEVICE_MISMATCH",
                                    "sesión " + AuditLogger.sessionRef(sessionId) + " usada desde " + device);
                            ctx.response().setStatusCode(401).end("La sesión está ligada a otro dispositivo");
                            return;
                        }
                        if (row.getInteger("revoked") == 1) {
                            AuditLogger.logRequestEvent(ctx.request(), "ACCESS_DENIED_REVOKED_CERT",
                                    "sesión " + AuditLogger.sessionRef(sessionId) + " " + device);
                            ctx.response().setStatusCode(403).end("El certificado de esta sesión ha sido revocado");
                            return;
                        }
                    }

                    ctx.put("authenticatedUser", row.getString("username"));
                    byte[] secretKey = Base64.getDecoder().decode(row.getString("hmac_key"));
                    new SecurityMiddleware(secretKey, client).handle(ctx);
                })
                .onFailure(err -> {
                    System.err.println("Error en BD (Validando sesión): " + err.getMessage());
                    ctx.response().setStatusCode(500).end("Error en BD");
                });
    }

    // La huella guardada al hacer login tiene que coincidir con la del certificado de esta conexión
    private static boolean sameDevice(String boundFingerprint, DeviceIdentity device) {
        if (boundFingerprint == null || device == null) return false;
        return MessageDigest.isEqual(boundFingerprint.getBytes(StandardCharsets.US_ASCII),
                device.fingerprint().getBytes(StandardCharsets.US_ASCII));
    }
}