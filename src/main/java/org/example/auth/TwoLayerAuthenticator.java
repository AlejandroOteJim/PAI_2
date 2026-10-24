package org.example.auth;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import io.vertx.mysqlclient.MySQLClient;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;
import org.example.crypto.HMACSigner;
import org.example.crypto.PasswordHasher;
import org.example.server.GatewayVerticle;
import org.example.server.AuditLogger;
import org.example.server.ServerMode;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

/**
 * PAI-2 persona B (RF1 + RF2): registro y login en dos capas.
 *   Capa 1 (transporte): el handshake mTLS ya validó que el certificado lo firmó la CA (TLSConfig, persona A).
 *                        Aquí se comprueba además que CN == usuario, que no está revocado y que está emparejado con ese usuario.
 *   Capa 2 (aplicación): usuario + contraseña con PBKDF2, calculado fuera del event loop (executeBlocking).
 * Las respuestas JSON mantienen los mismos campos que antes para no romper ByodClient.
 */
public class TwoLayerAuthenticator {

    private static final int MAX_INTENTOS = 5;
    private static final int MINUTOS_BLOQUEO = 5;
    // Sal para el hash de relleno cuando el usuario no existe (ver login)
    private static final String SAL_FICTICIA = PasswordHasher.generateSalt();

    // Rechazo controlado: lleva el código HTTP y el tipo de evento para la auditoría
    private static final class Rejection extends RuntimeException {
        final int status;
        final String evento;

        Rejection(int status, String evento, String mensaje) {
            super(mensaje, null, false, false);
            this.status = status;
            this.evento = evento;
        }
    }

    private record Credentials(String username, String password) {}

    private final Pool client;
    private final DeviceRegistry registry;

    public TwoLayerAuthenticator(Pool client, DeviceRegistry registry) {
        this.client = client;
        this.registry = registry;
    }

    // ---------- RF1: registro vinculado al certificado ----------

    public void register(RoutingContext ctx) {
        Credentials c = readCredentials(ctx);
        if (c == null) return;
        DeviceIdentity device = DeviceIdentity.fromRequest(ctx.request());

        checkDeviceForRegister(c.username(), device)
                .compose(v -> client.preparedQuery("SELECT 1 FROM users WHERE username = ?").execute(Tuple.of(c.username())))
                .compose(rows -> rows.size() > 0   // Si ya existe, se responde sin gastar CPU en PBKDF2
                        ? Future.failedFuture(new Rejection(409, "REGISTER_DUPLICATE", "El usuario ya existe"))
                        : Future.succeededFuture())
                .compose(v -> ctx.vertx().executeBlocking(() -> {        // PBKDF2 fuera del event loop
                    String salt = PasswordHasher.generateSalt();
                    return new String[]{salt, PasswordHasher.hashPassword(c.password(), salt)};
                }, false))
                .compose(saltHash -> client.withTransaction(conn -> {
                    String role = device != null && device.role() != null ? device.role() : "PDI"; // RF5: el rol sale de la OU del certificado
                    String iban = GatewayVerticle.generateRandomIban();
                    return conn.preparedQuery("INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)")
                            .execute(Tuple.of(c.username(), saltHash[1], saltHash[0], role))
                            .compose(rows -> {
                                int userId = rows.property(MySQLClient.LAST_INSERTED_ID).intValue();
                                return device != null ? registry.bind(conn, userId, device) : Future.<Void>succeededFuture();
                            })
                            .compose(v -> conn.preparedQuery("INSERT INTO user_ibans (username, iban) VALUES (?, ?)")
                                    .execute(Tuple.of(c.username(), iban)))
                            .map(iban);
                }))
                .onSuccess(iban -> {
                    audit(ctx, "REGISTER_SUCCESS", "usuario=" + c.username() + (device != null ? " " + device : ""));
                    JsonObject res = new JsonObject()
                            .put("status", "Usuario registrado correctamente")
                            .put("assigned_iban", iban);
                    if (device != null) res.put("certificate_serial", device.serial());
                    json(ctx, 201, res);
                })
                .onFailure(err -> {
                    if (err instanceof Rejection r) {
                        deny(ctx, r, c.username());
                    } else if (err.getMessage() != null && err.getMessage().contains("Duplicate entry")) {
                        deny(ctx, new Rejection(409, "REGISTER_DUPLICATE", "El usuario ya existe"), c.username());
                    } else {
                        System.err.println("Error en registro: " + err.getMessage());
                        json(ctx, 500, new JsonObject().put("error", "Error interno en el registro"));
                    }
                });
    }

    // Capa 1 del registro: certificado presente, CN == usuario, no revocado y sin emparejar con otra cuenta
    private Future<Void> checkDeviceForRegister(String username, DeviceIdentity device) {
        if (!ServerMode.tls()) return Future.succeededFuture(); // Modo benchmark sin cifrar: no hay certificado
        if (device == null) {
            return Future.failedFuture(new Rejection(401, "REGISTER_NO_CERT", "Se requiere el certificado del dispositivo"));
        }
        if (!device.belongsTo(username)) {
            return Future.failedFuture(new Rejection(403, "REGISTER_CN_MISMATCH",
                    "El certificado del dispositivo no pertenece a '" + username + "'"));
        }
        return registry.status(device).compose(st -> {
            if (st.revoked()) {
                return Future.failedFuture(new Rejection(403, "REGISTER_REVOKED_CERT", "Certificado revocado"));
            }
            if (st.ownerUserId() != null) {
                return Future.failedFuture(new Rejection(409, "REGISTER_CERT_ALREADY_PAIRED", "Este certificado ya está emparejado con una cuenta"));
            }
            return Future.succeededFuture();
        });
    }

    // ---------- RF2: login en dos capas ----------

    public void login(RoutingContext ctx) {
        Credentials c = readCredentials(ctx);
        if (c == null) return;
        DeviceIdentity device = DeviceIdentity.fromRequest(ctx.request());

        // Capa 1, parte sin BD: el certificado tiene que ser del usuario que intenta entrar
        if (ServerMode.tls()) {
            if (device == null) {
                deny(ctx, new Rejection(401, "LOGIN_NO_CERT", "Se requiere el certificado del dispositivo"), c.username());
                return;
            }
            if (!device.belongsTo(c.username())) {
                deny(ctx, new Rejection(403, "LOGIN_CN_MISMATCH", "El certificado del dispositivo no pertenece a '" + c.username() + "'"), c.username());
                return;
            }
        }

        client.preparedQuery("SELECT id, salt, password_hash, locked_until, failed_attempts FROM users WHERE username = ?")
                .execute(Tuple.of(c.username()))
                .compose(rows -> {
                    if (!rows.iterator().hasNext()) {
                        // Mismo código, mismo mensaje y mismo coste PBKDF2 que una contraseña incorrecta:
                        // ni la respuesta ni el tiempo revelan si el usuario existe
                        return ctx.vertx().executeBlocking(() -> PasswordHasher.hashPassword(c.password(), SAL_FICTICIA), false)
                                .compose(h -> Future.<JsonObject>failedFuture(
                                        new Rejection(401, "LOGIN_UNKNOWN_USER", "Credenciales incorrectas")));
                    }
                    Row row = rows.iterator().next();
                    int userId = row.getInteger("id");
                    LocalDateTime lockedUntil = row.getLocalDateTime("locked_until");
                    if (lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now())) {
                        return Future.<JsonObject>failedFuture(new Rejection(423, "LOGIN_LOCKED", "Usuario bloqueado temporalmente. Inténtalo más tarde."));
                    }

                    return checkDeviceForLogin(userId, device)
                            .compose(v -> ctx.vertx().executeBlocking(() -> PasswordHasher.verifyPassword(
                                    c.password(), row.getString("salt"), row.getString("password_hash")), false))
                            .compose(passwordOk -> passwordOk
                                    ? openSession(userId, device)
                                    : registerFailedAttempt(userId, row.getInteger("failed_attempts"))
                                    .compose(v -> Future.failedFuture(new Rejection(401, "LOGIN_BAD_PASSWORD", "Credenciales incorrectas"))));
                })
                .compose(session -> client.preparedQuery("SELECT iban FROM user_ibans WHERE username = ? LIMIT 1")
                        .execute(Tuple.of(c.username()))
                        .map(ibanRows -> session.put("iban", ibanRows.iterator().hasNext() ? ibanRows.iterator().next().getString("iban") : ""))
                        .otherwise(session))
                .onSuccess(session -> {
                    audit(ctx, "LOGIN_SUCCESS", "usuario=" + c.username() + (device != null ? " " + device : ""));
                    json(ctx, 200, session.put("status", "Login correcto"));
                })
                .onFailure(err -> {
                    if (err instanceof Rejection r) {
                        deny(ctx, r, c.username());
                    } else {
                        System.err.println("Error en login: " + err.getMessage());
                        json(ctx, 500, new JsonObject().put("error", "Error interno en el login"));
                    }
                });
    }

    // Capa 1, parte con BD: certificado no revocado y emparejado precisamente con este usuario
    private Future<Void> checkDeviceForLogin(int userId, DeviceIdentity device) {
        if (!ServerMode.tls()) return Future.succeededFuture();
        return registry.status(device).compose(st -> {
            if (st.revoked()) {
                return Future.failedFuture(new Rejection(403, "LOGIN_REVOKED_CERT", "Certificado revocado"));
            }
            if (!st.pairedWith(userId)) {
                return Future.failedFuture(new Rejection(403, "LOGIN_CERT_NOT_PAIRED", "El certificado no está emparejado con este usuario"));
            }
            return Future.succeededFuture();
        });
    }

    // Igual que en la PAI-1: 5 fallos seguidos bloquean la cuenta 5 minutos
    private Future<Void> registerFailedAttempt(int userId, int failedAttempts) {
        int intentos = failedAttempts + 1;
        Future<?> f = intentos >= MAX_INTENTOS
                ? client.preparedQuery("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?")
                .execute(Tuple.of(LocalDateTime.now().plusMinutes(MINUTOS_BLOQUEO), userId))
                : client.preparedQuery("UPDATE users SET failed_attempts = ? WHERE id = ?").execute(Tuple.of(intentos, userId));
        return f.mapEmpty();
    }

    // Crea la sesión y la liga al certificado con el que se hizo el login (el session_id no vale desde otro dispositivo)
    private Future<JsonObject> openSession(int userId, DeviceIdentity device) {
        String sessionId = UUID.randomUUID().toString();
        String hmacKeyBase64 = Base64.getEncoder().encodeToString(HMACSigner.generate256BitKey());

        return client.withTransaction(conn -> conn.preparedQuery("UPDATE users SET failed_attempts = 0 WHERE id = ?")
                        .execute(Tuple.of(userId))
                        .compose(r -> conn.preparedQuery("INSERT INTO sessions (session_id, user_id, hmac_key, active) VALUES (?, ?, ?, TRUE)")
                                .execute(Tuple.of(sessionId, userId, hmacKeyBase64)))
                        .compose(r -> device == null ? Future.succeededFuture() :
                                conn.preparedQuery("INSERT INTO session_bindings (session_id, cert_serial, cert_fingerprint) VALUES (?, ?, ?)")
                                        .execute(Tuple.of(sessionId, device.serial(), device.fingerprint()))))
                .map(v -> new JsonObject().put("session_id", sessionId).put("hmac_key", hmacKeyBase64));
    }

    // ---------- Utilidades ----------

    // Lee y valida {username, password}. Si falta algo responde 400 y devuelve null
    private Credentials readCredentials(RoutingContext ctx) {
        try {
            JsonObject payload = ctx.body().asJsonObject();
            String username = payload == null ? null : payload.getString("username");
            String password = payload == null ? null : payload.getString("password");
            if (username == null || username.isBlank() || password == null || password.isBlank()) {
                json(ctx, 400, new JsonObject().put("error", "username y password son obligatorios"));
                return null;
            }
            return new Credentials(username, password);
        } catch (Exception e) {
            json(ctx, 400, new JsonObject().put("error", "Error procesando JSON"));
            return null;
        }
    }

    private void deny(RoutingContext ctx, Rejection r, String username) {
        audit(ctx, r.evento, r.getMessage() + " usuario=" + username);
        json(ctx, r.status, new JsonObject().put("error", r.getMessage()));
    }

    // Punto único de auditoría de la autenticación (RS4): va a logs/audit.log con IP, CN, versión TLS y suite
    private static void audit(RoutingContext ctx, String evento, String detalle) {
        AuditLogger.logRequestEvent(ctx.request(), evento, detalle);
    }

    private static void json(RoutingContext ctx, int status, JsonObject body) {
        ctx.response().setStatusCode(status).putHeader("content-type", "application/json").end(body.encode());
    }
}