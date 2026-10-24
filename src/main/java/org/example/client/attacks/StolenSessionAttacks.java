package org.example.client.attacks;

import io.vertx.core.json.JsonObject;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class StolenSessionAttacks {

    public static void main(String[] args) {
        System.out.println("--- INICIANDO ATAQUE DE SESSION_ID ROBADO ---");

        try {
            // Usamos el cliente HTTP nativo de Java (no requiere Maven)
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();

            JsonObject credentials = new JsonObject()
                    .put("username", "admin")
                    .put("password", "admin123");

            // PASO 0: Registrar usuario por si la BD está vacía
            System.out.println("[*] Intentando registrar usuario de prueba...");
            HttpRequest regReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8080/api/v1/register"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(credentials.encode()))
                    .build();
            client.send(regReq, HttpResponse.BodyHandlers.ofString()); // Ignoramos si ya existe

            // PASO 1: Login Legítimo
            HttpRequest loginReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8080/api/v1/login"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(credentials.encode()))
                    .build();
            HttpResponse<String> loginRes = client.send(loginReq, HttpResponse.BodyHandlers.ofString());

            if (loginRes.statusCode() != 200) {
                System.err.println("Fallo en login inicial: " + loginRes.body());
                return;
            }

            String sessionId = new JsonObject(loginRes.body()).getString("session_id");
            System.out.println("[+] Login correcto. Session ID obtenido: " + sessionId);

            // PASO 2: Logout Legítimo
            JsonObject logoutPayload = new JsonObject().put("session_id", sessionId);
            HttpRequest logoutReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8080/api/v1/logout"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(logoutPayload.encode()))
                    .build();
            client.send(logoutReq, HttpResponse.BodyHandlers.ofString());
            System.out.println("[+] Logout ejecutado. La sesión debería estar muerta.");

            // PASO 3: EL ATAQUE (Intentar transferencia con la sesión robada/muerta)
            JsonObject transferPayload = new JsonObject()
                    .put("tx_id", "TX-ROBADA-001")
                    .put("destination_account", "ES12345678901234567890")
                    .put("amount", 5000.0)
                    .put("currency", "EUR");

            System.out.println("[!] Atacante intentando transferencia con Session ID robado...");

            HttpRequest attackReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8080/api/v1/transfer"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + sessionId) // Inyectamos session_id viejo
                    .POST(HttpRequest.BodyPublishers.ofString(transferPayload.encode()))
                    .build();

            HttpResponse<String> attackRes = client.send(attackReq, HttpResponse.BodyHandlers.ofString());

            if (attackRes.statusCode() == 401) {
                System.out.println("[ÉXITO] Ataque BLOQUEADO por el servidor (Status 401). Mensaje: " + attackRes.body());
            } else {
                System.err.println("[FALLO CRÍTICO] El servidor permitió el ataque. Status: " + attackRes.statusCode());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}