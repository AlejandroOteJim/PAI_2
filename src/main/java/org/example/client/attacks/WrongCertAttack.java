package org.example.client.attacks;

import org.example.client.ByodClient;
import org.example.client.EvidenceLog;
import org.example.tls.TLSConfig;

/**
 * Suplantación: el atacante tiene el dispositivo de alice (su certificado es válido y lo firmó nuestra CA)
 * y conoce la contraseña de bob. Intenta entrar como bob. El servidor debe rechazarlo porque el CN del
 * certificado (alice) no coincide con el usuario (bob). Requiere el servidor arrancado en modo TLS.
 */
public class WrongCertAttack {

    public static void main(String[] args) {
        EvidenceLog log = new EvidenceLog("ataque-certificado-ajeno");
        log.log("--- ATAQUE DE SUPLANTACIÓN: certificado de alice, credenciales de bob ---");
        try {
            ByodClient atacante = new ByodClient(ByodClient.DEFAULT_URL, "pki/clients/alice.p12", TLSConfig.CONTRASENA);
            ByodClient.Response r = atacante.login("bob", "bob");
            log.log("Respuesta del servidor: " + r.status() + " " + r.body());

            if (r.status() == 403) {
                log.log("[ÉXITO] Ataque BLOQUEADO: el certificado del dispositivo no pertenece a bob.");
            } else {
                log.log("[FALLO] El servidor no rechazó la suplantación (status " + r.status() + ").");
            }
        } catch (Exception e) {
            log.log("[ERROR] No se pudo realizar la prueba (¿servidor TLS arrancado?): " + e);
        }
    }
}
