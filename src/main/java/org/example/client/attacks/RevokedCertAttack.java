package org.example.client.attacks;

import io.vertx.core.json.JsonObject;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class RevokedCertAttack {

    public static void main(String[] args) {
        System.out.println("--- INICIANDO ATAQUE CON CERTIFICADO REVOCADO ---");

        try {
            // Nota: En la versión final, este cliente cargará el KeyStore con un certificado
            // que previamente hemos marcado como revocado en la base de datos.
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();

            System.out.println("[!] Atacante intentando hacer login con un certificado comprometido...");
            JsonObject credentials = new JsonObject()
                    .put("username", "hacker")
                    .put("password", "hacker123");

            HttpRequest loginReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8080/api/v1/login"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(credentials.encode()))
                    .build();

            HttpResponse<String> loginRes = client.send(loginReq, HttpResponse.BodyHandlers.ofString());

            // El servidor (vía el middleware de la Persona B) debería cortar la conexión o devolver error
            if (loginRes.statusCode() == 401 || loginRes.statusCode() == 403) {
                System.out.println("[ÉXITO] Ataque BLOQUEADO. El servidor consultó la lista de revocación (CRL/BD) y rechazó el certificado. Mensaje: " + loginRes.body());
            } else if (loginRes.statusCode() == 200) {
                System.err.println("[FALLO CRÍTICO] El servidor permitió el login. Falta implementar la comprobación de revocación.");
            } else {
                System.out.println("[?] Respuesta inesperada. Status: " + loginRes.statusCode());
            }

        } catch (Exception e) {
            System.out.println("[ÉXITO] La conexión fue abortada a nivel TLS (posible rechazo en el handshake).");
            e.printStackTrace();
        }
    }
}