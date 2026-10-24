package org.example.server;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.Tuple;
import org.example.auth.DeviceIdentity;
import org.example.auth.DeviceRegistry;
import org.example.auth.DeviceSessionGuard;
import org.example.auth.TwoLayerAuthenticator;
import org.example.db.SharedPool;

import javax.net.ssl.SSLException;
import java.util.Random;
import java.util.regex.Pattern;

public class GatewayVerticle extends AbstractVerticle {
    private Pool client;
    private TwoLayerAuthenticator auth;

    @Override
    public void start(Promise<Void> startPromise) {
        // La BD ya la inicializa ServerLauncher una sola vez, antes de desplegar las instancias
        setupDatabase();
        setupHttpServer()
                .onSuccess(server -> {
                    System.out.println("Instancia del Gateway escuchando en " + (ServerMode.tls() ? "HTTPS" : "HTTP (SIN TLS, solo benchmark)")
                            + " puerto " + server.actualPort());
                    startPromise.complete();
                })
                .onFailure(err -> {
                    System.err.println("Fallo estructural de inicio: " + err.getMessage());
                    startPromise.fail(err);
                });
    }

    private void setupDatabase() {
        // PAI-2 persona B (RS3): pool compartido entre todas las instancias del verticle
        this.client = SharedPool.crear(vertx);
        DeviceRegistry registry = new DeviceRegistry(client);
        this.auth = new TwoLayerAuthenticator(client, registry);
    }

    public static String generateRandomIban() {
        Random random = new Random();
        long part1 = 1000000000L + (long)(random.nextDouble() * 9000000000L);
        long part2 = 1000000000L + (long)(random.nextDouble() * 9000000000L);
        int controlDigits = 10 + random.nextInt(90);

        return "ES" + controlDigits + part1 + part2;
    }

    // Expresión regular estándar para validar formato IBAN (ej: ES211234...)
    private static final Pattern IBAN_PATTERN = Pattern.compile("^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$");

    public static boolean isValidIban(String iban) {
        if (iban == null) return false;
        return IBAN_PATTERN.matcher(iban.trim().toUpperCase()).matches();
    }

    private io.vertx.core.Future<io.vertx.core.http.HttpServer> setupHttpServer(){
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        // PAI-2 persona B: registro vinculado al certificado (RF1) y login en dos capas (RF2)
        router.post("/api/v1/login").handler(auth::login);

        router.post("/api/v1/register").handler(auth::register);

        // ---------------------------------------------------------------------------------
        // MODIFICACIÓN DE LA PERSONA C: Cierre seguro de sesión y desmontaje del túnel (RF4)
        // ---------------------------------------------------------------------------------
        router.post("/api/v1/logout").handler(ctx -> {
            try {
                JsonObject payload = ctx.body().asJsonObject();
                String sessionId = payload.getString("session_id");

                if (sessionId == null || sessionId.isBlank()) {
                    ctx.response().setStatusCode(400).putHeader("content-type", "application/json")
                            .end(new JsonObject().put("error", "session_id es obligatorio").encode());
                    return;
                }

                // Solo puede cerrar la sesión el mismo dispositivo (certificado) que hizo el login.
                // Al cerrarla se borra también la clave HMAC: deja de existir en el servidor.
                String sql;
                Tuple params;
                if (ServerMode.tls()) {
                    DeviceIdentity device = DeviceIdentity.fromRequest(ctx.request());
                    if (device == null) {
                        logoutDenegado(ctx, sessionId, "sin certificado de dispositivo");
                        return;
                    }
                    sql = "UPDATE sessions s JOIN session_bindings b ON b.session_id = s.session_id "
                            + "SET s.active = FALSE, s.hmac_key = '' "
                            + "WHERE s.session_id = ? AND s.active = TRUE AND b.cert_fingerprint = ?";
                    params = Tuple.of(sessionId, device.fingerprint());
                } else { // modo benchmark sin TLS: no hay certificado con el que comprobar
                    sql = "UPDATE sessions SET active = FALSE, hmac_key = '' WHERE session_id = ? AND active = TRUE";
                    params = Tuple.of(sessionId);
                }

                client.preparedQuery(sql)
                        .execute(params)
                        .onSuccess(rows -> {
                            if (rows.rowCount() == 0) {
                                // Misma respuesta si no existe, ya estaba cerrada o es de otro dispositivo (no se da pistas)
                                logoutDenegado(ctx, sessionId, "sesión inexistente, cerrada o de otro dispositivo");
                            } else {
                                // 1. Auditoría: Registramos el evento de cierre de sesión (RS4)
                                AuditLogger.logRequestEvent(ctx.request(), "LOGOUT_SUCCESS",
                                        "Cierre seguro de sesión " + AuditLogger.sessionRef(sessionId));

                                // 2. Invalidar el contexto criptográfico TLS para prohibir reanudación (RF4)
                                javax.net.ssl.SSLSession sslSession = ctx.request().connection().sslSession();
                                if (sslSession != null) {
                                    sslSession.invalidate();
                                }

                                // 3. Responder al cliente y desmontar el túnel TCP/TLS inmediatamente (RF4)
                                ctx.response().setStatusCode(200)
                                        .putHeader("content-type", "application/json")
                                        .putHeader("Connection", "close")
                                        .end(new JsonObject().put("status", "Sesión cerrada y canal destruido correctamente").encode())
                                        .onComplete(ar -> {
                                            ctx.request().connection().close(); // Cierra físicamente el socket (envía close_notify)
                                        });
                            }
                        })
                        .onFailure(err -> ctx.response().setStatusCode(500)
                                .end(new JsonObject().put("error", err.getMessage()).encode()));

            } catch (Exception e) {
                ctx.response().setStatusCode(400)
                        .end(new JsonObject().put("error", "Error procesando JSON").encode());
            }
        });
        // ---------------------------------------------------------------------------------

        // Handler 1: sesión activa, ligada al certificado del login y no revocado (persona B); después el middleware HMAC
        router.post("/api/v1/transfer").handler(new DeviceSessionGuard(client));

        // Handler 2: Lógica de Negocio Real (Guardar en Base de Datos con el IBAN del usuario)
        router.post("/api/v1/transfer").handler(ctx -> {
            try {
                String authenticatedUser = ctx.get("authenticatedUser");

                JsonObject payload = ctx.body().asJsonObject();
                String txId = payload.getString("tx_id");
                String dest = payload.getString("destination_account");
                Double amount = payload.getDouble("amount");
                String currency = payload.getString("currency");

                if (!isValidIban(dest)) {
                    ctx.response().setStatusCode(400).putHeader("content-type", "application/json")
                            .end(new JsonObject().put("error", "Estructura de IBAN de destino inválida (ej. ES211234...)").encode());
                    return;
                }
                client.preparedQuery("SELECT iban FROM user_ibans WHERE username = ? LIMIT 1")
                        .execute(Tuple.of(authenticatedUser))
                        .onSuccess(ibanRows -> {
                            if (!ibanRows.iterator().hasNext()) {
                                ctx.response().setStatusCode(400).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", "El usuario no tiene ningún IBAN asociado").encode());
                                return;
                            }

                            String originIban = ibanRows.iterator().next().getString("iban");

                            String timestampStr = ctx.request().getHeader("X-Timestamp");
                            Long timestamp = timestampStr != null ? Long.parseLong(timestampStr) : System.currentTimeMillis() / 1000;

                            client.preparedQuery("INSERT INTO transactions" +
                                            " (tx_id, origin_account, destination_account, amount, currency, timestamp) VALUES (?, ?, ?, ?, ?, ?)")
                                    .execute(Tuple.of(txId, originIban, dest, amount, currency, timestamp))
                                    .onSuccess(rows -> {
                                        ctx.response().setStatusCode(200).putHeader("content-type", "application/json")
                                                .end(new JsonObject()
                                                        .put("status", "Transferencia registrada con éxito en MariaDB")
                                                        .put("origin_account", originIban)
                                                        .encode());
                                    })
                                    .onFailure(err -> {
                                        System.err.println("Error en DB (Insert Transactions): " + err.getMessage());
                                        ctx.response().setStatusCode(500).end("Error interno de base de datos");
                                    });
                        })
                        .onFailure(err -> {
                            System.err.println("Error en DB (Buscando IBAN): " + err.getMessage());
                            ctx.response().setStatusCode(500).end("Error interno buscando cuenta de origen");
                        });

            } catch (Exception e) {
                System.err.println("Error procesando JSON de transferencia: " + e.getMessage());
                ctx.response().setStatusCode(400).end(new JsonObject().put("error", "Formato JSON incorrecto").encode());
            }
        });

        HttpServer server = vertx.createHttpServer(ServerMode.opcionesServidor());

        // RS4: apertura y cierre de cada túnel, con la IP, el CN del certificado, la versión TLS y la suite
        server.connectionHandler(conn -> {
            AuditLogger.Peer peer = AuditLogger.peer(conn);
            AuditLogger.log("TUNNEL_UP", peer, "túnel establecido");
            conn.closeHandler(v -> AuditLogger.log("TUNNEL_DOWN", peer, "túnel cerrado"));
        });

        // RS4: handshakes rechazados (TLS < 1.3, suite no permitida, sin certificado, CA ajena...)
        server.exceptionHandler(err -> {
            if (esErrorTls(err)) {
                AuditLogger.logRawEvent("TLS_HANDSHAKE_REJECTED", "desconocida",
                        err.getClass().getSimpleName() + ": " + err.getMessage());
            }
        });

        return server.requestHandler(router).listen();
    }

    // Respuesta y auditoría comunes a todos los logout rechazados
    private static void logoutDenegado(RoutingContext ctx, String sessionId, String motivo) {
        AuditLogger.logRequestEvent(ctx.request(), "LOGOUT_DENIED", motivo + " " + AuditLogger.sessionRef(sessionId));
        ctx.response().setStatusCode(401).putHeader("content-type", "application/json")
                .end(new JsonObject().put("error", "Sesión inválida").encode());
    }

    // ¿El error (o alguna de sus causas) es un fallo de TLS?
    private static boolean esErrorTls(Throwable err) {
        for (Throwable t = err; t != null; t = t.getCause()) {
            if (t instanceof SSLException) return true;
        }
        return false;
    }
}