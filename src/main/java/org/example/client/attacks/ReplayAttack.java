package org.example.client.attacks;

import org.example.client.EvidenceLog;
import org.example.client.SecBankClient;
import org.example.client.SecBankClient.Response;
import org.example.client.SecBankClient.SignedRequest;

import java.util.UUID;

/** Simula un Replay: reenvia un paquete valido capturado, y otro con timestamp caducado. */
public class ReplayAttack {
    static final String ORIGIN = "ES1234567890123456789012";
    static final String DEST = "ES9876543210987654321098";

    public static void main(String[] args) throws Exception {
        EvidenceLog log = new EvidenceLog("replay");
        SecBankClient client = new SecBankClient();
        String user = "replay_" + UUID.randomUUID().toString().substring(0, 8);
        client.register(user, "Passw0rd!x");
        client.login(user, "Passw0rd!x");

        // 1) Mensaje legitimo
        SignedRequest captured = client.buildTransfer(ORIGIN, DEST, 400.00, "EUR");
        Response first = client.send(captured);
        log.log("[ORIGINAL] nonce=" + captured.nonce() + " -> " + first.status() + " " + first.body());

        // 2) Replay: mismos bytes, misma firma, mismo nonce
        Response replay = client.send(captured);
        log.log("[REPLAY] nonce=" + captured.nonce() + " -> " + replay.status() + " " + replay.body());
        log.log(replay.status() >= 400 ? "RESULTADO: replay RECHAZADO por nonce repetido (correcto)"
                : "RESULTADO: replay ACEPTADO (FALLO de seguridad)");

        // 3) Timestamp caducado (firmado correctamente, pero de hace 10 minutos)
        long old = System.currentTimeMillis() / 1000 - 600;
        SignedRequest stale = client.buildTransfer(ORIGIN, DEST, 400.00, "EUR", old);
        Response staleRes = client.send(stale);
        log.log("[TIMESTAMP CADUCADO] ts=" + old + " -> " + staleRes.status() + " " + staleRes.body());
        log.log(staleRes.status() >= 400 ? "RESULTADO: mensaje caducado RECHAZADO (correcto)"
                : "RESULTADO: mensaje caducado ACEPTADO (FALLO de seguridad)");
    }
}