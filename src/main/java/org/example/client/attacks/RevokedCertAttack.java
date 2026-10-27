package org.example.client.attacks;

import org.example.client.ByodClient;
import org.example.client.EvidenceLog;
import org.example.tls.TLSConfig;

/**
 * Certificado revocado: el atacante tiene el dispositivo (y la contraseña) de un usuario cuyo certificado
 * ya se ha revocado. El handshake TLS se completa (el certificado sigue firmado por la CA), pero el servidor
 * debe rechazar el login porque el número de serie está en la lista de revocados.
 *
 * Antes de ejecutarlo, revocar el certificado:
 *   java -cp ... org.example.pki.RevocationTool revocar inv01 dispositivo robado
 * Uso: RevokedCertAttack [usuario]   (por defecto inv01; su contraseña es su nombre de usuario)
 */
public class RevokedCertAttack {

    public static void main(String[] args) {
        String usuario = args.length > 0 ? args[0] : "inv01";
        EvidenceLog log = new EvidenceLog("ataque-certificado-revocado");
        log.log("--- ATAQUE CON CERTIFICADO REVOCADO: dispositivo de " + usuario + " ---");
        try {
            ByodClient atacante = new ByodClient(ByodClient.DEFAULT_URL, "pki/clients/" + usuario + ".p12", TLSConfig.CONTRASENA);
            ByodClient.Response r = atacante.login(usuario, usuario);
            log.log("Respuesta del servidor: " + r.status() + " " + r.body());

            if (r.status() == 403 && r.body().contains("revocado")) {
                log.log("[ÉXITO] Ataque BLOQUEADO: el servidor detectó que el certificado está revocado.");
            } else if (r.status() == 200) {
                log.log("[FALLO] Login aceptado. ¿Se revocó antes el certificado con RevocationTool revocar " + usuario + "?");
            } else {
                log.log("[?] Respuesta inesperada (status " + r.status() + ").");
            }
        } catch (Exception e) {
            log.log("[ERROR] No se pudo realizar la prueba (¿servidor TLS arrancado?): " + e);
        }
    }
}
