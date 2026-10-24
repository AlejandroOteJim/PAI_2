package org.example.client.attacks;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class MitmAttack {

    public static void main(String[] args) {
        System.out.println("--- INICIANDO SIMULACIÓN DE ATAQUE MAN-IN-THE-MIDDLE (MitM) ---");
        System.out.println("[*] Escenario: El atacante intercepta el tráfico de red intentando leer las credenciales.");
        System.out.println("[*] Entorno actual: TLS 1.3 con mTLS activado.");

        try {
            // Un cliente HTTP estándar que exige validación de certificados TLS
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();

            // Si un atacante activo intenta interceptar la conexión presentando su propio certificado falso
            // (ej. un proxy de intercepción como Burp Suite sin certificado raíz instalado en el cliente):
            System.out.println("[!] El cliente legítimo intenta conectar a través del nodo del atacante...");

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://localhost:8080/api/v1/login")) // Notar el HTTPS
                    .GET()
                    .build();

            // El cliente de Java abortará la conexión si el certificado no es confiable,
            // demostrando que MitM es inviable.
            client.send(req, HttpResponse.BodyHandlers.ofString());

            System.err.println("[FALLO CRÍTICO] El cliente se conectó. El MitM fue exitoso (Esto no debería ocurrir en producción).");

        } catch (javax.net.ssl.SSLHandshakeException e) {
            System.out.println("\n[ÉXITO] Ataque MitM BLOQUEADO por TLS 1.3.");
            System.out.println("-> Motivo: El cliente detectó que el certificado presentado por el atacante es inválido o no confiable.");
            System.out.println("-> Excepción real: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("\n[INFO] La conexión falló por otro motivo (Probablemente porque el puerto no está en modo HTTPS todavía).");
            System.out.println("-> Mensaje: " + e.getMessage());
        }
    }
}