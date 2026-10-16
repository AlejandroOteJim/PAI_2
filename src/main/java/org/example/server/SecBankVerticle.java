package org.example.server;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.mysqlclient.MySQLBuilder;
import io.vertx.mysqlclient.MySQLConnectOptions;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.PoolOptions;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;
import org.example.crypto.HMACSigner;
import org.example.crypto.PasswordHasher;
import org.example.crypto.SecurityMiddleware;
import org.example.db.DataBaseInitializer;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;
import java.util.Random;
import java.util.regex.Pattern;

public class SecBankVerticle extends AbstractVerticle {
    private Pool client;

    @Override
    public void start(Promise<Void> startPromise) {
        DataBaseInitializer.init(vertx)
                .compose(v -> {
                    setupDatabase();
                    return setupHttpServer();
                })
                .onSuccess(server -> {
                    System.out.println("Servidor SecBank desplegado en HTTP puerto 8080 (Texto plano).");
                    startPromise.complete();
                })
                .onFailure(err -> {
                    System.err.println("Fallo estructural de inicio: " + err.getMessage());
                    startPromise.fail(err);
                });
    }


    private void setupDatabase() {
        MySQLConnectOptions connectOptions = new MySQLConnectOptions()
                .setPort(3306)
                .setHost("localhost")
                .setDatabase("secbank")
                .setUser("root")
                .setPassword("root");

        PoolOptions poolOptions = new PoolOptions().setMaxSize(5);

        this.client = (Pool) MySQLBuilder.client()
                .with(poolOptions)
                .connectingTo(connectOptions)
                .using(vertx)
                .build();
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

        router.post("/api/v1/login").handler(ctx -> {
            try {
                JsonObject payload = ctx.body().asJsonObject();
                String username = payload.getString("username");
                String password = payload.getString("password");

                client.preparedQuery("SELECT * FROM users WHERE username = ?")
                        .execute(Tuple.of(username))
                        .onSuccess(rows -> {
                            if (!rows.iterator().hasNext()) {
                                ctx.response().setStatusCode(404).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", "Usuario no encontrado").encode());
                                return;
                            }

                            Row row = rows.iterator().next();
                            int userId = row.getInteger("id");
                            String storedSalt = row.getString("salt");
                            String storedHash = row.getString("password_hash");
                            LocalDateTime lockedUntil = row.getLocalDateTime("locked_until");
                            int failedAttempts = row.getInteger("failed_attempts");

                            if (lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now())) {
                                ctx.response().setStatusCode(423).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", "Usuario bloqueado temporalmente. Inténtalo más tarde.").encode());
                                return;
                            }

                            boolean passwordOk = PasswordHasher.verifyPassword(password, storedSalt, storedHash);

                            if (!passwordOk) {
                                int newAttempts = failedAttempts + 1;
                                String updateSql;
                                Tuple updateParams;

                                if (newAttempts >= 5) {
                                    updateSql = "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?";
                                    updateParams = Tuple.of(LocalDateTime.now().plusMinutes(5), userId);
                                } else {
                                    updateSql = "UPDATE users SET failed_attempts = ? WHERE id = ?";
                                    updateParams = Tuple.of(newAttempts, userId);
                                }

                                client.preparedQuery(updateSql).execute(updateParams);

                                ctx.response().setStatusCode(401).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", "Credenciales incorrectas").encode());
                                return;
                            }

                            client.preparedQuery("UPDATE users SET failed_attempts = 0 WHERE id = ?")
                                    .execute(Tuple.of(userId));

                            String sessionId = UUID.randomUUID().toString();
                            byte[] hmacKeyBytes = HMACSigner.generate256BitKey();
                            String hmacKeyBase64 = Base64.getEncoder().encodeToString(hmacKeyBytes);

                            client.preparedQuery("INSERT INTO sessions (session_id, user_id, hmac_key, active) VALUES (?, ?, ?, TRUE)")
                                    .execute(Tuple.of(sessionId, userId, hmacKeyBase64))
                                    .onSuccess(sessionRows -> {
                                        client.preparedQuery("SELECT iban FROM user_ibans WHERE username = ? LIMIT 1")
                                                .execute(Tuple.of(username))
                                                .onSuccess(ibanRows -> {
                                                    String userIban = ibanRows.iterator().hasNext() ? ibanRows.iterator().next().getString("iban") : "";

                                                    ctx.response().setStatusCode(200).putHeader("content-type", "application/json")
                                                            .end(new JsonObject()
                                                                    .put("status", "Login correcto")
                                                                    .put("session_id", sessionId)
                                                                    .put("hmac_key", hmacKeyBase64)
                                                                    .put("iban", userIban)
                                                                    .encode());
                                                })
                                                .onFailure(errIban -> {
                                                    ctx.response().setStatusCode(200).putHeader("content-type", "application/json")
                                                            .end(new JsonObject()
                                                                    .put("status", "Login correcto")
                                                                    .put("session_id", sessionId)
                                                                    .put("hmac_key", hmacKeyBase64)
                                                                    .encode());
                                                });
                                    })
                                    .onFailure(err -> ctx.response().setStatusCode(500)
                                            .end(new JsonObject().put("error", err.getMessage()).encode()));
                        })
                        .onFailure(err -> ctx.response().setStatusCode(500)
                                .end(new JsonObject().put("error", err.getMessage()).encode()));

            } catch (Exception e) {
                ctx.response().setStatusCode(400)
                        .end(new JsonObject().put("error", "Error procesando JSON").encode());
            }
        });

        router.post("/api/v1/register").handler(ctx -> {
            try {
                JsonObject payload = ctx.body().asJsonObject();
                String username = payload.getString("username");
                String password = payload.getString("password");

                if (username == null || username.isBlank() || password == null || password.isBlank()) {
                    ctx.response().setStatusCode(400).putHeader("content-type", "application/json")
                            .end(new JsonObject().put("error", "username y password son obligatorios").encode());
                    return;
                }

                String salt = PasswordHasher.generateSalt();
                String passwordHash = PasswordHasher.hashPassword(password, salt);

                client.preparedQuery("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)")
                        .execute(Tuple.of(username, passwordHash, salt))
                        .onSuccess(rows -> {
                            String assignedIban = generateRandomIban();

                            client.preparedQuery("INSERT INTO user_ibans (username, iban) VALUES (?, ?)")
                                    .execute(Tuple.of(username, assignedIban))
                                    .onSuccess(resIban -> {
                                        ctx.response().setStatusCode(201).putHeader("content-type", "application/json")
                                                .end(new JsonObject()
                                                        .put("status", "Usuario registrado correctamente")
                                                        .put("assigned_iban", assignedIban)
                                                        .encode());
                                    })
                                    .onFailure(errIban -> {
                                        System.err.println("Error asignando IBAN al usuario: " + errIban.getMessage());
                                        ctx.response().setStatusCode(500).putHeader("content-type", "application/json")
                                                .end(new JsonObject().put("error", "Error interno al crear cuenta bancaria").encode());
                                    });

                        })
                        .onFailure(err -> {
                            if (err.getMessage() != null && err.getMessage().contains("Duplicate entry")) {
                                ctx.response().setStatusCode(409).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", "El usuario ya existe").encode());
                            } else {
                                ctx.response().setStatusCode(500).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", err.getMessage()).encode());
                            }
                        });

            } catch (Exception e) {
                ctx.response().setStatusCode(400).putHeader("content-type", "application/json")
                        .end(new JsonObject().put("error", "Error procesando JSON").encode());
            }
        });

        router.post("/api/v1/logout").handler(ctx -> {
            try {
                JsonObject payload = ctx.body().asJsonObject();
                String sessionId = payload.getString("session_id");

                if (sessionId == null || sessionId.isBlank()) {
                    ctx.response().setStatusCode(400).putHeader("content-type", "application/json")
                            .end(new JsonObject().put("error", "session_id es obligatorio").encode());
                    return;
                }

                client.preparedQuery("UPDATE sessions SET active = FALSE WHERE session_id = ? AND active = TRUE")
                        .execute(Tuple.of(sessionId))
                        .onSuccess(rows -> {
                            if (rows.rowCount() == 0) {
                                ctx.response().setStatusCode(404).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("error", "Sesión no encontrada").encode());
                            } else {
                                ctx.response().setStatusCode(200).putHeader("content-type", "application/json")
                                        .end(new JsonObject().put("status", "Sesión cerrada correctamente").encode());
                            }
                        })
                        .onFailure(err -> ctx.response().setStatusCode(500)
                                .end(new JsonObject().put("error", err.getMessage()).encode()));

            } catch (Exception e) {
                ctx.response().setStatusCode(400)
                        .end(new JsonObject().put("error", "Error procesando JSON").encode());
            }
        });

        // Handler 1: Extraer sesión, validar en BD (con JOIN a users) y ejecutar middleware
        router.post("/api/v1/transfer").handler(ctx -> {
            String authHeader = ctx.request().getHeader("Authorization");

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                ctx.response().setStatusCode(401).end("Falta cabecera de sesión o formato incorrecto");
                return;
            }

            String sessionId = authHeader.substring(7);


            client.preparedQuery("SELECT s.hmac_key, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.session_id = ? AND s.active = TRUE")
                    .execute(Tuple.of(sessionId))
                    .onSuccess(rows -> {
                        if (!rows.iterator().hasNext()) {
                            ctx.response().setStatusCode(401).end("Sesión inválida o inactiva");
                            return;
                        }

                        var row = rows.iterator().next();
                        String keyB64 = row.getString("hmac_key");
                        String username = row.getString("username");
                        byte[] secretKey = java.util.Base64.getDecoder().decode(keyB64);


                        ctx.put("authenticatedUser", username);

                        SecurityMiddleware middleware = new SecurityMiddleware(secretKey, client);
                        middleware.handle(ctx);
                    })
                    .onFailure(err -> {
                        System.err.println("Error en BD (Validando sesión): " + err.getMessage());
                        ctx.response().setStatusCode(500).end("Error en BD");
                    });
        });

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

        return vertx.createHttpServer().requestHandler(router).listen(8080);
    }
}