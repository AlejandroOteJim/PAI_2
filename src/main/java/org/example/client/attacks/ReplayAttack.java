package org.example.client.attacks;

import org.example.client.ByodClient;
import org.example.client.EvidenceLog;
import org.example.tls.TLSConfig;

/**
 * Replay: se reenvía exactamente la misma transferencia firmada (mismo cuerpo, nonce, timestamp y HMAC).
 * La primera vez se acepta; la repetición debe rechazarse porque el nonce ya se usó.
 * Requiere el servidor arrancado en modo TLS.
 */
public class ReplayAttack {

    public static void main(String[] args) {
        EvidenceLog log = new EvidenceLog("ataque-replay");
        log.log("--- ATAQUE DE REPETICIÓN (REPLAY) ---");
        try {
            ByodClient alice = new ByodClient(ByodClient.DEFAULT_URL, "pki/clients/alice.p12", TLSConfig.CONTRASENA);
            ByodClient.Response login = alice.login("alice", "alice");
            if (login.status() != 200) {
                log.log("[ERROR] Falló el login de alice: " + login.status() + " " + login.body());
                return;
            }

            ByodClient.SignedRequest capturada = alice.buildTransfer("AUTO_ORIGIN", "ES7921000813610123456789", 100.0, "EUR");
            ByodClient.Response original = alice.send(capturada);
            log.log("[+] Transferencia original -> " + original.status() + " " + original.body());

            ByodClient.Response repetida = alice.send(capturada);
            log.log("[!] Misma petición reenviada -> " + repetida.status() + " " + repetida.body());

            if (original.status() == 200 && repetida.status() == 401) {
                log.log("[ÉXITO] Replay BLOQUEADO: nonce duplicado.");
            } else {
                log.log("[FALLO] Resultado inesperado (original " + original.status() + ", repetida " + repetida.status() + ").");
            }
            alice.logout();
        } catch (Exception e) {
            log.log("[ERROR] No se pudo realizar la prueba (¿servidor TLS arrancado?): " + e);
        }
    }
}
