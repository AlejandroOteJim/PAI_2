package org.example.pki;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.Tuple;
import org.example.auth.DeviceIdentity;
import org.example.auth.DeviceRegistry;
import org.example.db.SharedPool;
import org.example.tls.TLSConfig;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * PAI-2 persona B (RF1): procedimiento explícito de revocación y re-emisión de certificados de dispositivo.
 *   RevocationTool listar
 *   RevocationTool revocar  <usuario> <motivo...>
 *   RevocationTool reemitir <usuario> <motivo...>   (revoca el actual, la CA emite uno nuevo y se empareja)
 * Se ejecuta desde la raíz del proyecto, con la BD arrancada (el servidor puede seguir en marcha).
 */
public final class RevocationTool {

    private RevocationTool() {}

    public static void main(String[] args) {
        if (args.length == 0 || (!args[0].equals("listar") && args.length < 3)) usage();

        Vertx vertx = Vertx.vertx();
        Pool pool = SharedPool.crear(vertx);
        DeviceRegistry registry = new DeviceRegistry(pool);

        Future<?> op = switch (args[0]) {
            case "listar" -> registry.listBindings().onSuccess(l -> l.forEach(System.out::println));
            case "revocar" -> revoke(registry, args[1], motivo(args));
            case "reemitir" -> reissue(vertx, pool, registry, args[1], motivo(args));
            default -> {
                usage();
                yield Future.succeededFuture();
            }
        };

        op.onComplete(ar -> {
            if (ar.failed()) System.err.println("ERROR: " + ar.cause().getMessage());
            vertx.close().onComplete(c -> System.exit(ar.succeeded() ? 0 : 1));
        });
    }

    // Revoca el certificado activo del usuario. Desde ese momento no puede registrarse, entrar ni usar sesiones abiertas
    static Future<DeviceIdentity> revoke(DeviceRegistry registry, String username, String motivo) {
        return registry.activeCertificateOf(username).compose(actual -> {
            if (actual == null) {
                return Future.failedFuture(new IllegalStateException(username + " no tiene ningún certificado activo"));
            }
            return registry.revoke(actual.serial(), motivo).map(nueva -> {
                System.out.println((nueva ? "Revocado " : "Ya estaba revocado ") + actual + " (" + motivo + ")");
                return actual;
            });
        });
    }

    // Re-emisión: revocar el actual, pedir a la CA uno nuevo con el mismo CN y rol, y emparejarlo
    static Future<Void> reissue(Vertx vertx, Pool pool, DeviceRegistry registry, String username, String motivo) {
        return pool.preparedQuery("SELECT role FROM users WHERE username = ?").execute(Tuple.of(username))
                .compose(rows -> {
                    if (!rows.iterator().hasNext()) return Future.failedFuture(new IllegalArgumentException("No existe el usuario " + username));
                    String role = rows.iterator().next().getString("role");
                    return revoke(registry, username, "re-emisión: " + motivo)
                            .recover(err -> Future.succeededFuture()) // Si no tenía ninguno activo, se emite igualmente
                            .compose(v -> vertx.executeBlocking(() -> readCertificate(CertificateAuthority.load().issueClient(username, role))));
                })
                .compose(nuevo -> registry.bindReissued(username, nuevo).onSuccess(v ->
                        System.out.println("Re-emitido y emparejado " + nuevo + " -> pki/clients/" + username + ".p12")));
    }

    // Saca el certificado del .p12 que acaba de generar la CA
    private static DeviceIdentity readCertificate(Path p12) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(p12)) {
            ks.load(in, TLSConfig.CONTRASENA.toCharArray());
        }
        return DeviceIdentity.fromCertificate((X509Certificate) ks.getCertificate(ks.aliases().nextElement()));
    }

    private static String motivo(String[] args) {
        return String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length));
    }

    private static void usage() {
        System.err.println("""
                Uso: RevocationTool listar
                     RevocationTool revocar  <usuario> <motivo>
                     RevocationTool reemitir <usuario> <motivo>""");
        System.exit(1);
    }
}
