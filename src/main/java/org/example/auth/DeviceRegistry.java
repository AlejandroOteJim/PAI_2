package org.example.auth;

import io.vertx.core.Future;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.SqlClient;
import io.vertx.sqlclient.Tuple;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * PAI-2 persona B (RF1): emparejamiento usuario <-> certificado del dispositivo y lista de revocados.
 * device_certificates es de solo inserción (los triggers de schema.sql impiden UPDATE/DELETE): para cambiar
 * el certificado de un usuario hay que revocar el actual y emparejar uno re-emitido por la CA.
 */
public class DeviceRegistry {

    // Estado de un certificado en la BD: si está revocado y a qué usuario está emparejado (null si a ninguno)
    public record CertStatus(boolean revoked, Integer ownerUserId) {
        public boolean pairedWith(int userId) {
            return !revoked && ownerUserId != null && ownerUserId == userId;
        }
    }

    private final Pool client;

    public DeviceRegistry(Pool client) {
        this.client = client;
    }

    // Consulta en una sola ida a la BD si el certificado está revocado y con quién está emparejado
    public Future<CertStatus> status(DeviceIdentity id) {
        return client.preparedQuery(
                        "SELECT EXISTS(SELECT 1 FROM revoked_certificates WHERE serial = ?) AS revoked, " +
                        "(SELECT user_id FROM device_certificates WHERE serial = ? AND fingerprint_sha256 = ?) AS owner")
                .execute(Tuple.of(id.serial(), id.serial(), id.fingerprint()))
                .map(rows -> {
                    Row r = rows.iterator().next();
                    return new CertStatus(r.getInteger("revoked") == 1, r.getInteger("owner"));
                });
    }

    // Empareja el certificado con el usuario. Se pasa la conexión para poder hacerlo dentro de la transacción del registro
    public Future<Void> bind(SqlClient conn, int userId, DeviceIdentity id) {
        return conn.preparedQuery("INSERT INTO device_certificates (serial, user_id, cn, role, fingerprint_sha256) VALUES (?, ?, ?, ?, ?)")
                .execute(Tuple.of(id.serial(), userId, id.cn(), id.role() == null ? "PDI" : id.role(), id.fingerprint()))
                .mapEmpty();
    }

    // Añade el número de serie a la lista de revocados. Devuelve false si ya lo estaba
    public Future<Boolean> revoke(String serial, String reason) {
        return client.preparedQuery("INSERT INTO revoked_certificates (serial, reason) VALUES (?, ?)")
                .execute(Tuple.of(serial, reason))
                .map(rows -> true)
                .recover(err -> err.getMessage() != null && err.getMessage().contains("Duplicate entry")
                        ? Future.succeededFuture(false) : Future.failedFuture(err));
    }

    // Certificado emparejado y no revocado del usuario, o null si no tiene ninguno
    public Future<DeviceIdentity> activeCertificateOf(String username) {
        return client.preparedQuery(
                        "SELECT d.serial, d.cn, d.role, d.fingerprint_sha256 FROM device_certificates d " +
                        "JOIN users u ON u.id = d.user_id LEFT JOIN revoked_certificates r ON r.serial = d.serial " +
                        "WHERE u.username = ? AND r.serial IS NULL ORDER BY d.issued_at DESC LIMIT 1")
                .execute(Tuple.of(username))
                .map(rows -> {
                    if (!rows.iterator().hasNext()) return null;
                    Row r = rows.iterator().next();
                    return new DeviceIdentity(r.getString("cn"), r.getString("role"), r.getString("serial"), r.getString("fingerprint_sha256"));
                });
    }

    // Re-emisión: empareja el certificado nuevo solo si el usuario ya no tiene ninguno activo (es decir, el anterior se revocó)
    public Future<Void> bindReissued(String username, DeviceIdentity nuevo) {
        if (!nuevo.belongsTo(username)) {
            return Future.failedFuture(new IllegalArgumentException("El CN del certificado (" + nuevo.cn() + ") no es " + username));
        }
        return activeCertificateOf(username).compose(actual -> {
            if (actual != null) {
                return Future.failedFuture(new IllegalStateException(
                        "El usuario " + username + " aún tiene activo el certificado " + actual.serial() + ". Revócalo antes de re-emitir."));
            }
            return client.preparedQuery("SELECT id FROM users WHERE username = ?").execute(Tuple.of(username))
                    .compose(rows -> {
                        if (!rows.iterator().hasNext()) return Future.failedFuture(new IllegalArgumentException("No existe el usuario " + username));
                        return bind(client, rows.iterator().next().getInteger("id"), nuevo);
                    });
        });
    }

    // Todas las parejas usuario-certificado con su estado, para el listado de la herramienta de revocación
    public Future<List<String>> listBindings() {
        return client.query(
                        "SELECT d.cn, d.role, d.serial, d.issued_at, r.revoked_at, r.reason FROM device_certificates d " +
                        "LEFT JOIN revoked_certificates r ON r.serial = d.serial ORDER BY d.cn, d.issued_at")
                .execute()
                .map(rows -> {
                    List<String> out = new ArrayList<>();
                    for (Row r : rows) {
                        String estado = r.getValue("revoked_at") == null ? "ACTIVO" : "REVOCADO " + r.getValue("revoked_at") + " (" + r.getString("reason") + ")";
                        out.add(String.format("%-10s %-4s %-34s %s", r.getString("cn"), r.getString("role"), r.getString("serial"), estado));
                    }
                    return out;
                });
    }

    /**
     * RF5: empareja los usuarios precargados con los certificados que la CA les emitió, leyendo pki/ca/index.txt.
     * Solo toca usuarios que existen en la BD y aún no tienen certificado activo, y nunca reutiliza un número de serie.
     */
    public Future<Integer> seedFromCaIndex(Path index) {
        Map<String, String[]> ultimoPorCn = new LinkedHashMap<>();
        try {
            if (!Files.exists(index)) return Future.succeededFuture(0);
            for (String line : Files.readAllLines(index, StandardCharsets.UTF_8)) {
                if (line.isBlank() || line.startsWith("#")) continue;
                String[] f = line.split("\t"); // serie, CN, rol, caduca, sha256
                if (f.length < 5 || f[2].equals("CA") || f[2].equals("SERVIDOR")) continue;
                ultimoPorCn.put(f[1], f); // Si un CN tiene varios certificados, vale el último emitido
            }
        } catch (IOException e) {
            return Future.failedFuture(e);
        }

        Future<Integer> chain = Future.succeededFuture(0);
        for (String[] f : ultimoPorCn.values()) {
            chain = chain.compose(total -> client.preparedQuery(
                            "INSERT INTO device_certificates (serial, user_id, cn, role, fingerprint_sha256) " +
                            "SELECT ?, u.id, ?, ?, ? FROM users u WHERE u.username = ? " +
                            "AND NOT EXISTS (SELECT 1 FROM device_certificates WHERE serial = ?) " +
                            "AND NOT EXISTS (SELECT 1 FROM device_certificates d LEFT JOIN revoked_certificates r ON r.serial = d.serial " +
                            "                WHERE d.user_id = u.id AND r.serial IS NULL)")
                    .execute(Tuple.of(f[0], f[1], f[2], f[4], f[1], f[0]))
                    .map(rows -> total + rows.rowCount()));
        }
        return chain;
    }
}
