package org.example.server;

import io.vertx.core.http.HttpServerRequest;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;

public class AuditLogger {

    private static final String LOG_DIR = "logs";
    private static final String LOG_FILE = "logs/audit.log";

    // Este bloque estático se asegura de crear la carpeta "logs" si no existe al arrancar
    static {
        File dir = new File(LOG_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    /**
     * Registra un evento extrayendo automáticamente los metadatos del túnel TLS y mTLS.
     */
    public static synchronized void logRequestEvent(HttpServerRequest req, String eventType, String details) {
        String ip = (req.remoteAddress() != null) ? req.remoteAddress().host() : "UNKNOWN_IP";
        String cn = "NO_CERT";
        String tlsProtocol = "NONE (HTTP)";
        String cipherSuite = "NONE";

        // Extraer la sesión TLS/SSL de Vert.x para sacar los datos criptográficos
        SSLSession sslSession = req.connection().sslSession();
        if (sslSession != null) {
            tlsProtocol = sslSession.getProtocol();
            cipherSuite = sslSession.getCipherSuite();
            try {
                // Obtener el certificado del cliente y extraer su Common Name (CN)
                Certificate[] certs = sslSession.getPeerCertificates();
                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate x509 = (X509Certificate) certs[0];
                    cn = extractCN(x509.getSubjectX500Principal().getName());
                }
            } catch (SSLPeerUnverifiedException ignored) {
                cn = "UNVERIFIED_CLIENT";
            }
        }

        writeEntry(eventType, ip, cn, tlsProtocol, cipherSuite, details);
    }

    /**
     * Registra eventos a nivel de socket (ej. handshakes fallidos antes de llegar a HTTP)
     */
    public static synchronized void logRawEvent(String eventType, String ip, String details) {
        writeEntry(eventType, ip, "N/A", "TLS_HANDSHAKE", "N/A", details);
    }

    private static void writeEntry(String eventType, String ip, String cn, String protocol, String suite, String details) {
        // Formato exacto que pide el requisito RS4
        String logLine = String.format("[%s] [%s] IP=%s | CN=%s | Protocol=%s | Suite=%s | Info=%s",
                Instant.now().toString(), eventType, ip, cn, protocol, suite, details);

        // Imprimir por consola para que os sirva de debug mientras programáis
        System.out.println(logLine);

        // Escribir en el archivo audit.log (añadiendo al final sin sobreescribir)
        try (FileWriter fw = new FileWriter(LOG_FILE, true);
             PrintWriter pw = new PrintWriter(fw)) {
            pw.println(logLine);
        } catch (IOException e) {
            System.err.println("Error crítico escribiendo en audit.log: " + e.getMessage());
        }
    }

    /**
     * Utilidad para extraer solo el "Nombre" (CN) de la ristra completa del certificado
     */
    private static String extractCN(String principalName) {
        for (String part : principalName.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return principalName;
    }
}