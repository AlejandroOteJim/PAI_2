package org.example.client.attacks;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.example.client.EvidenceLog;
import org.example.tls.TLSConfig;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Extra (+10 %): Man-in-the-Middle en una red no confiable.
 *   1. Servidor falso: el atacante se hace pasar por el gateway con un certificado para "localhost" que NO ha
 *      firmado la CA de U-Secure. El dispositivo de alice debe abortar el handshake sin enviar las credenciales.
 *   2. Dispositivo falso: el atacante conecta al servidor real con un certificado de "alice" firmado por él
 *      mismo. El servidor debe rechazarlo en el handshake mTLS.
 * El escenario 2 requiere el servidor real arrancado en modo TLS (puerto 8443).
 */
public class MitmAttack {

    private static final int PUERTO_ATACANTE = 9443;

    public static void main(String[] args) throws Exception {
        EvidenceLog log = new EvidenceLog("ataque-mitm");
        log.log("--- ATAQUE MAN-IN-THE-MIDDLE ---");
        boolean ok1 = servidorFalso(log);
        boolean ok2 = dispositivoFalso(log);
        log.log(ok1 && ok2 ? "[ÉXITO] Los dos intentos de MitM se detectaron y se abortaron."
                : "[FALLO] Algún intento de MitM no se detectó (ver arriba).");
    }

    // Escenario 1: el cliente legítimo se conecta sin saberlo al servidor del atacante
    private static boolean servidorFalso(EvidenceLog log) throws Exception {
        SSLContext ctxAtacante = SSLContext.getInstance(TLSConfig.PROTOCOLO);
        ctxAtacante.init(keyManagers(identidadFalsa("localhost")), null, new SecureRandom());

        try (SSLServerSocket servidor = (SSLServerSocket) ctxAtacante.getServerSocketFactory().createServerSocket(PUERTO_ATACANTE)) {
            servidor.setEnabledProtocols(new String[]{TLSConfig.PROTOCOLO});
            Thread atacante = new Thread(() -> {
                try (SSLSocket victima = (SSLSocket) servidor.accept()) {
                    victima.startHandshake();
                    log.log("    [atacante] la víctima ha aceptado el certificado falso");
                } catch (Exception e) {
                    log.log("    [atacante] la víctima ha cortado el handshake: " + e.getMessage());
                }
            });
            atacante.start();

            log.log("[1] El dispositivo de alice se conecta al servidor falso (puerto " + PUERTO_ATACANTE + ")...");
            HttpClient alice = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .sslContext(TLSConfig.contextoCliente("pki/clients/alice.p12", TLSConfig.CONTRASENA))
                    .sslParameters(TLSConfig.parametrosCliente())
                    .build();
            try {
                alice.send(HttpRequest.newBuilder(URI.create("https://localhost:" + PUERTO_ATACANTE + "/api/v1/login"))
                        .POST(HttpRequest.BodyPublishers.ofString("{\"username\":\"alice\",\"password\":\"alice\"}"))
                        .build(), HttpResponse.BodyHandlers.ofString());
                log.log("[1] [FALLO] El cliente ha enviado sus credenciales al servidor falso.");
                return false;
            } catch (javax.net.ssl.SSLHandshakeException e) {
                log.log("[1] [ÉXITO] BLOQUEADO: el cliente no confía en el certificado del atacante (" + e.getMessage() + ")");
                return true;
            } finally {
                atacante.join(2000);
            }
        }
    }

    // Escenario 2: el atacante se hace pasar por el dispositivo de alice ante el servidor real
    private static boolean dispositivoFalso(EvidenceLog log) throws Exception {
        log.log("[2] El atacante conecta al servidor real con un certificado falso de 'alice' firmado por él mismo...");
        KeyStore ts = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(TLSConfig.ALMACEN_CONFIANZA)) {
            ts.load(in, TLSConfig.CONTRASENA.toCharArray()); // El atacante sí reconoce al servidor real
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        SSLContext ctx = SSLContext.getInstance(TLSConfig.PROTOCOLO);
        // El gestor de claves de Java no enviaría un certificado de una CA que el servidor no pide;
        // el atacante lo fuerza para que el servidor reciba y tenga que rechazar el certificado falso
        javax.net.ssl.X509KeyManager real = (javax.net.ssl.X509KeyManager) keyManagers(identidadFalsa("alice"))[0];
        javax.net.ssl.X509ExtendedKeyManager forzado = new javax.net.ssl.X509ExtendedKeyManager() {
            public String chooseEngineClientAlias(String[] t, java.security.Principal[] i, javax.net.ssl.SSLEngine e) { return "falsa"; }
            public String chooseClientAlias(String[] t, java.security.Principal[] i, java.net.Socket s) { return "falsa"; }
            public X509Certificate[] getCertificateChain(String a) { return real.getCertificateChain(a); }
            public java.security.PrivateKey getPrivateKey(String a) { return real.getPrivateKey(a); }
            public String[] getClientAliases(String t, java.security.Principal[] i) { return new String[]{"falsa"}; }
            public String[] getServerAliases(String t, java.security.Principal[] i) { return null; }
            public String chooseServerAlias(String t, java.security.Principal[] i, java.net.Socket s) { return null; }
        };
        ctx.init(new javax.net.ssl.KeyManager[]{forzado}, tmf.getTrustManagers(), new SecureRandom());

        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("localhost", TLSConfig.PUERTO)) {
            s.setSSLParameters(TLSConfig.parametrosCliente());
            s.startHandshake();
            // En TLS 1.3 el servidor valida el certificado del cliente al final del handshake: forzamos un intercambio
            s.getOutputStream().write(("POST /api/v1/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            s.getOutputStream().flush();
            if (s.getInputStream().read() == -1) {
                log.log("[2] [ÉXITO] BLOQUEADO: el servidor ha cerrado la conexión sin responder.");
                return true;
            }
            log.log("[2] [FALLO] El servidor ha aceptado el certificado falso.");
            return false;
        } catch (java.net.ConnectException e) {
            log.log("[2] [ERROR] No hay servidor en el puerto " + TLSConfig.PUERTO + " (¿está arrancado en modo TLS?).");
            return false;
        } catch (javax.net.ssl.SSLException | java.net.SocketException e) {
            log.log("[2] [ÉXITO] BLOQUEADO: el servidor ha rechazado el certificado falso en el handshake mTLS (" + e.getMessage() + ")");
            return true;
        }
    }

    private static javax.net.ssl.KeyManager[] keyManagers(KeyStore ks) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, TLSConfig.CONTRASENA.toCharArray());
        return kmf.getKeyManagers();
    }

    // Certificado autofirmado con el CN indicado: parece legítimo, pero no lo ha firmado la CA de U-Secure
    private static KeyStore identidadFalsa(String cn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        X500Name nombre = new X500Name("C=ES, O=Universidad Publica U-Secure, CN=" + cn);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(nombre, BigInteger.valueOf(System.nanoTime()),
                Date.from(Instant.now().minus(5, ChronoUnit.MINUTES)), Date.from(Instant.now().plus(1, ChronoUnit.DAYS)),
                nombre, kp.getPublic());
        b.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
        X509Certificate cert = new JcaX509CertificateConverter()
                .getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate())));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("falsa", kp.getPrivate(), TLSConfig.CONTRASENA.toCharArray(), new Certificate[]{cert});
        return ks;
    }
}
