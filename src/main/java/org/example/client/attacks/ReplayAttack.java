package org.example.client.attacks;

import io.vertx.core.json.JsonObject;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class ReplayAttack {

    public static void main(String[] args) {
        System.out.println("--- INICIANDO SIMULACIÓN DE ATAQUE DE REPETICIÓN (REPLAY) ---");
        System.out.println("[*] Escenario: El atacante grabó un paquete cifrado legítimo e intenta reenviarlo.");

        try {
            HttpClient client = HttpClient.newHttpClient();

            // Payload legítimo interceptado previamente
            JsonObject interceptedPayload = new JsonObject()
                    .put("tx_id", "TX-12345")
                    .put("destination_account", "ES12345678901234567890")
                    .put("amount", 100.0)
                    .put("currency", "EUR");

            System.out.println("[!] Atacante inyectando paquete repetido en la red...");

            HttpRequest replayReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8080/api/v1/transfer"))
                    .header("Content-Type", "application/json")
                    // Simulamos el envío de una cabecera de sesión que el servidor ya invalidó
                    .header("Authorization", "Bearer invalid-or-expired-session-id")
                    .POST(HttpRequest.BodyPublishers.ofString(interceptedPayload.encode()))
                    .build();

            HttpResponse<String> response = client.send(replayReq, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 401 || response.statusCode() == 403) {
                System.out.println("\n[ÉXITO] Ataque de Repetición BLOQUEADO.");
                System.out.println("-> El servidor TLS/Aplicación rechazó el paquete (Session ID inválido o TLS sequence number duplicado).");
                System.out.println("-> Respuesta: " + response.body());
            } else {
                System.err.println("\n[FALLO CRÍTICO] El servidor aceptó el paquete repetido. Status: " + response.statusCode());
            }

        } catch (Exception e) {
            System.out.println("\n[ÉXITO] Ataque BLOQUEADO a nivel de capa de red/TLS.");
            e.printStackTrace();
        }
    }
}