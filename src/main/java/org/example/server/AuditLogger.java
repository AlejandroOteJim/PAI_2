package org.example.server;

import io.vertx.core.http.HttpConnection;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.SocketAddress;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * PAI-2 persona C (RS4): registro de auditoría en logs/audit.log.
 * Formato de cada línea: [fecha] [EVENTO] IP=.. | CN=.. | Protocol=.. | Suite=.. | Info=..
 * Eventos: TUNNEL_UP / TUNNEL_DOWN, TLS_HANDSHAKE_REJECTED, LOGIN_* / REGISTER_*, ACCESS_DENIED_*, LOGOUT_*.
 */
public final class AuditLogger {

    private static final Path LOG_FILE = Path.of("logs", "audit.log");
    private static PrintWriter out;

    /** Datos del extremo del túnel: se capturan al abrir la conexión para poder usarlos también al cerrarla. */
    public record Peer(String ip, String cn, String protocol, String suite) {}

    private AuditLogger() {}

    // ---------------------------------------------------------------- API

    /** Evento de una petición HTTP (login, logout, accesos denegados...). */
    public static void logRequestEvent(HttpServerRequest req, String eventType, String details) {
        log(eventType, peer(req.connection(), req.remoteAddress()), details);
    }

    /** Evento de una conexión (apertura y cierre del túnel). */
    public static void logConnectionEvent(HttpConnection conn, String eventType, String details) {
        log(eventType, peer(conn), details);
    }

    /** Evento a nivel de socket sin petición HTTP (por ejemplo, un handshake rechazado). */
    public static void logRawEvent(String eventType, String ip, String details) {
        log(eventType, new Peer(ip, "N/A", "TLS_HANDSHAKE", "N/A"), details);
    }

    public static Peer peer(HttpConnection conn) {
        return peer(conn, conn.remoteAddress());
    }

    public static synchronized void log(String eventType, Peer p, String details) {
        String line = String.format("[%s] [%s] IP=%s | CN=%s | Protocol=%s | Suite=%s | Info=%s",
                Instant.now(), eventType, p.ip(), p.cn(), p.protocol(), p.suite(), details);
        System.out.println(line);
        try {
            if (out == null) {
                Files.createDirectories(LOG_FILE.getParent());
                // Se abre una sola vez en modo "añadir"; autoflush para no perder líneas si el servidor se cae
                out = new PrintWriter(new FileWriter(LOG_FILE.toFile(), true), true);
            }
            out.println(line);
        } catch (IOException e) {
            System.err.println("Error crítico escribiendo en audit.log: " + e.getMessage());
        }
    }

    /** Recorta un session_id para el log: identifica la sesión sin dejar el token completo escrito en disco. */
    public static String sessionRef(String sessionId) {
        if (sessionId == null) return "-";
        return sessionId.length() <= 8 ? sessionId : sessionId.substring(0, 8) + "...";
    }

    // ---------------------------------------------------------------- utilidades

    private static Peer peer(HttpConnection conn, SocketAddress address) {
        String ip = address != null ? address.host() : "UNKNOWN_IP";
        SSLSession ssl = conn != null ? conn.sslSession() : null;
        if (ssl == null) return new Peer(ip, "NO_CERT", "NONE (HTTP)", "NONE");

        String cn = "NO_CERT";
        try {
            Certificate[] certs = ssl.getPeerCertificates();
            if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                cn = extractCN(x509.getSubjectX500Principal().getName());
            }
        } catch (SSLPeerUnverifiedException e) {
            cn = "UNVERIFIED_CLIENT";
        }
        return new Peer(ip, cn, ssl.getProtocol(), ssl.getCipherSuite());
    }

    // Extrae solo el CN de "CN=alice,OU=PDI,O=U-Secure..."
    private static String extractCN(String principalName) {
        for (String part : principalName.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) return trimmed.substring(3);
        }
        return principalName;
    }
}