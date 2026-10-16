package org.example.client.attacks;

import org.example.client.EvidenceLog;
import org.example.client.SecBankClient;
import org.example.client.SecBankClient.Response;
import org.example.client.SecBankClient.SignedRequest;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** Simula un MitM: altera el importe en transito sin recalcular la firma. */
public class MitmAttack {
    static final String ORIGIN = "ES1234567890123456789012";
    static final String DEST = "ES9876543210987654321098";

    public static void main(String[] args) throws Exception {
        EvidenceLog log = new EvidenceLog("mitm");
        SecBankClient client = new SecBankClient();
        String user = "mitm_" + UUID.randomUUID().toString().substring(0, 8);
        client.register(user, "Passw0rd!x");
        client.login(user, "Passw0rd!x");

        // Control: una transferencia legitima debe aceptarse
        SignedRequest legit = client.buildTransfer(ORIGIN, DEST, 1250.75, "EUR");
        Response r1 = client.send(legit);
        log.log("[LEGITIMA] body=" + legit.bodyAsString() + " -> " + r1.status() + " " + r1.body());

        // Ataque: el atacante cambia el importe pero conserva firma, nonce y timestamp
        SignedRequest original = client.buildTransfer(ORIGIN, DEST, 1250.75, "EUR");
        String tamperedBody = original.bodyAsString().replace("1250.75", "9999.99");
        SignedRequest tampered = original.withBody(tamperedBody.getBytes(StandardCharsets.UTF_8));
        log.log("[MITM] original=" + original.bodyAsString());
        log.log("[MITM] alterado=" + tampered.bodyAsString() + " (firma sin cambios)");
        Response r2 = client.send(tampered);
        log.log("[MITM] respuesta servidor -> " + r2.status() + " " + r2.body());
        log.log(r2.status() >= 400 ? "RESULTADO: manipulacion RECHAZADA (correcto)"
                : "RESULTADO: manipulacion ACEPTADA (FALLO de seguridad)");
    }
}