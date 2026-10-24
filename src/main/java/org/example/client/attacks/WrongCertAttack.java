package org.example.client.attacks;

import io.vertx.core.json.JsonObject;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class WrongCertAttack {

    public static void main(String[] args) {
        System.out.println("--- INICIANDO ATAQUE DE SUPLANTACIÓN (CERTIFICADO vs PAYLOAD) ---");

        try {
            // Nota: Cuando vuestro compañero (Persona A) active el mTLS definitivo,
            // a este HttpClient habrá que inyectarle el certificado del "atacante" (SSLContext).
            // Por ahora probamos la lógica a nivel HTTP.
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();

            // EL ATAQUE: El atacante intenta usar el nombre de otra persona (ej. "admin" o "profesor")
            System.out.println("[!] El atacante intentará iniciar sesión como 'admin'...");
            JsonObject maliciousCredentials = new JsonObject()
                    .put("username", "admin")
                    .put("password", "admin123");

            HttpRequest loginReq = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:8080/api/v1/login"))
                    .header("Content-Type", "application/json")
                    // Si el servidor (Persona A/B) hace bien su trabajo, verificará que el CN
                    // del certificado del atacante coincida con este "username".
                    .POST(HttpRequest.BodyPublishers.ofString(maliciousCredentials.encode()))
                    .build();

            System.out.println("[*] Enviando payload malicioso...");
            HttpResponse<String> loginRes = client.send(loginReq, HttpResponse.BodyHandlers.ofString());

            // Idealmente, cuando todo el backend esté unido, esto debería devolver un 401 o 403
            if (loginRes.statusCode() == 401 || loginRes.statusCode() == 403) {
                System.out.println("[ÉXITO] El ataque fue BLOQUEADO. " +
                        "El servidor detectó que el certificado no pertenece a 'admin'. Mensaje: " + loginRes.body());
            } else if (loginRes.statusCode() == 200) {
                System.err.println("[FALLO CRÍTICO] El servidor permitió el login. " +
                        "La validación mTLS CN vs Username aún no está implementada en el servidor.");
                System.out.println("-> Respuesta del servidor: " + loginRes.body());
            } else {
                System.out.println("[?] Respuesta inesperada del servidor. Status: " + loginRes.statusCode());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
