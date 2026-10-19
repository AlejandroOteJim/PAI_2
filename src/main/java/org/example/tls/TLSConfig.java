package org.example.tls;

import io.vertx.core.http.ClientAuth;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.KeyStoreOptions;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;


public final class TLSConfig {

    public static final String PROTOCOLO = "TLSv1.3";

    // Cipher Suites (combinaciones de algoritmos con los que se cifran los datos)
    public static final List<String> SUITES = List.of(
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256"
    );

    public static final int PUERTO = 8443; // Puerto seguro para HTTPS
    public static final String CONTRASENA = "cambiame"; // Contraseña para los .p12
    public static final String ALMACEN_CONFIANZA = "pki/truststore.p12";
    public static final String ALMACEN_SERVIDOR = "pki/server/server.p12";

    private TLSConfig() {}

    // Configura la Maquina Virutal de Java para forzar que use TLSv1.3
    public static void endurecerJvm() {
        System.setProperty("jdk.tls.server.protocols", PROTOCOLO);
        System.setProperty("jdk.tls.client.protocols", PROTOCOLO);
    }


    public static HttpServerOptions opcionesServidor() {
        HttpServerOptions o = new HttpServerOptions()
                .setPort(PUERTO) // Puerto seguro
                .setSsl(true) // Activa TLS
                .setKeyCertOptions(new KeyStoreOptions().setType("PKCS12")
                        .setPath(ALMACEN_SERVIDOR).setPassword(CONTRASENA)) // Clave privada y certificado del servidor (lo que presenta en el handshake)
                .setTrustOptions(new KeyStoreOptions().setType("PKCS12")
                        .setPath(ALMACEN_CONFIANZA).setPassword(CONTRASENA)) // Cuando un cliente presente su certificado, el servidor comprobara que lo firmo esa CA
                .setClientAuth(ClientAuth.REQUIRED) // Linea que activa la autenticacion mutua
                .setEnabledSecureTransportProtocols(Set.of(PROTOCOLO)) // Solo TLSv1.3
                .setUseAlpn(false);
        SUITES.forEach(o::addEnabledCipherSuite); // Recorre la lista SUITES y añade cada una como permitida
        return o;
    }




    public static SSLContext contextoCliente(String almacenDispositivo, String contrasena) throws Exception {
        KeyStore ks = cargar(almacenDispositivo, contrasena);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); //Cuando el servidor pide certificado lo entrega y firma el handshake con su clave privada
        kmf.init(ks, contrasena.toCharArray());

        KeyStore ts = cargar(ALMACEN_CONFIANZA, CONTRASENA); // Carga el almacen de confianza con la CA de U-Secure
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // Comprueba que el certificado del servidor lo firmo esa CA
        tmf.init(ts);

        SSLContext ctx = SSLContext.getInstance(PROTOCOLO); // Crea el contexto TLS 1.3
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom()); // Como parametros se le pasa el que tiene que presentar, en que confiar y la fuente de aleatoridad
        return ctx;
    }

    public static SSLParameters parametrosCliente() {
        SSLParameters p = new SSLParameters();
        p.setProtocols(new String[]{PROTOCOLO}); // El cliente solo ofre TLSv1.3
        p.setCipherSuites(SUITES.toArray(String[]::new)); // El cliente solo ofrece las dos suites robustas
        p.setEndpointIdentificationAlgorithm("HTTPS"); // Activa la comprobacion del nombre del servidor
        return p;
    }

    // Abre un .p12 y lo descifra con la contraseña
    private static KeyStore cargar(String ruta, String contrasena) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(ruta)) {
            ks.load(in, contrasena.toCharArray());
        }
        return ks;
    }
}