package org.example.client.attacks;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.client.ByodClient;
import org.example.client.EvidenceLog;
import org.example.tls.TLSConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * session_id robado: alice inicia sesión desde su dispositivo y el atacante consigue su session_id.
 *   1. Lo usa desde OTRO dispositivo (certificado de bob)   -> debe dar 401 (sesión ligada al dispositivo).
 *   2. Alice cierra sesión y se reutiliza el session_id     -> debe dar 401 (sesión cerrada).
 * Requiere el servidor arrancado en modo TLS.
 */
public class StolenSessionAttacks {

    private static final String TRANSFER = ByodClient.DEFAULT_URL + ByodClient.TRANSFER_PATH;
    private static final String BODY = "{\"tx_id\":\"TX-ROBADA-001\",\"destination_account\":\"ES7921000813610123456789\",\"amount\":5000.0,\"currency\":\"EUR\"}";

    public static void main(String[] args) {
        EvidenceLog log = new EvidenceLog("ataque-sesion-robada");
        log.log("--- ATAQUE DE SESSION_ID ROBADO ---");
        try {
            // Paso 0: login legítimo de alice desde su dispositivo
            ByodClient alice = new ByodClient(ByodClient.DEFAULT_URL, "pki/clients/alice.p12", TLSConfig.CONTRASENA);
            ByodClient.Response login = alice.login("alice", "alice");
            if (login.status() != 200) {
                log.log("[ERROR] Falló el login legítimo de alice: " + login.status() + " " + login.body());
                return;
            }
            String sessionId = new ObjectMapper().readTree(login.body()).get("session_id").asText();
            log.log("[+] alice ha iniciado sesión. El atacante captura su session_id.");

            // Paso 1: el atacante usa el session_id desde el dispositivo de bob
            HttpResponse<String> r1 = transferir(dispositivo("bob"), sessionId);
            log.log("[1] session_id de alice usado desde el certificado de bob -> " + r1.statusCode() + " " + r1.body());
            boolean ok1 = r1.statusCode() == 401;
            log.log(ok1 ? "[ÉXITO] BLOQUEADO: la sesión está ligada al dispositivo de alice."
                    : "[FALLO] El servidor aceptó la sesión desde otro dispositivo.");

            // Paso 2: alice cierra sesión y se intenta reutilizar el session_id desde su propio dispositivo
            alice.logout();
            log.log("[+] alice ha cerrado sesión.");
            HttpResponse<String> r2 = transferir(dispositivo("alice"), sessionId);
            log.log("[2] session_id reutilizado tras el logout -> " + r2.statusCode() + " " + r2.body());
            boolean ok2 = r2.statusCode() == 401;
            log.log(ok2 ? "[ÉXITO] BLOQUEADO: la sesión ya no existe tras el logout."
                    : "[FALLO] El servidor aceptó una sesión cerrada.");
        } catch (Exception e) {
            log.log("[ERROR] No se pudo realizar la prueba (¿servidor TLS arrancado?): " + e);
        }
    }

    // Cliente HTTPS con el certificado del dispositivo indicado
    private static HttpClient dispositivo(String usuario) throws Exception {
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .sslContext(TLSConfig.contextoCliente("pki/clients/" + usuario + ".p12", TLSConfig.CONTRASENA))
                .sslParameters(TLSConfig.parametrosCliente())
                .build();
    }

    private static HttpResponse<String> transferir(HttpClient cliente, String sessionId) throws Exception {
        return cliente.send(HttpRequest.newBuilder(URI.create(TRANSFER))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + sessionId)
                .POST(HttpRequest.BodyPublishers.ofString(BODY))
                .build(), HttpResponse.BodyHandlers.ofString());
    }
}
