package org.example.tls;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

// Clase de prueba para verificar que el servidor U-Secure cumple la política TLS 1.3 + mTLS y rechaza versiones antiguas, suites no permitidas y certificados no válidos (RS1 y RS2).
public final class TLSPolicyCheck {

    private static final String TLS13 = "TLSv1.3"; // Nombre de TLS 1.3 en Java

    public static void main(String[] args) throws Exception {
        // Se reactivan las versiones antiguas de TLS para realizar las pruebas
        Security.setProperty("jdk.tls.disabledAlgorithms", "");

        String host = args.length > 0 ? args[0] : "localhost"; // Decide a que servidor conectarse
        int port = args.length > 1 ? Integer.parseInt(args[1]) : TLSConfig.PUERTO; // Puerto del sevidor
        String user = args.length > 2 ? args[2] : "bob"; // Certificado del cliente a usar
        char[] pass = TLSConfig.CONTRASENA.toCharArray(); // Coge la contraseña de los certificados y la convierte en un array de caracteres

        KeyStore trust = cargar(TLSConfig.ALMACEN_CONFIANZA, pass); // Abre el certificado de la CA
        KeyStore device = cargar("pki/clients/" + user + ".p12", pass); // Abre el certificado del dispositivo elegido
        TrustManager[] confiaEnCa = trustManagers(trust); // Confia en la CA de U-Secure
        KeyManager[] certValido = keyManagers(device, pass); // Convierte el .p12 del dispositivo en un gestor de claves


        KeyStore falso = identidadFalsa(user, pass); // Crea un certificado falso
        KeyManager[] certAjeno = keyManagers(falso, pass); // Convierte el .p12 del certificado falso en un gestor de claves
        KeyStore trustFalso = KeyStore.getInstance("PKCS12"); // Crea un almacen de confianza vacio
        trustFalso.load(null, null);
        trustFalso.setCertificateEntry("falsa", falso.getCertificate("falsa")); // Mete en este almacen el certificado del atacante
        TrustManager[] confiaEnOtraCa = trustManagers(trustFalso); // Representacion de un cliente que no se fia de nuestra CA

        // Suites que se van a probar, las dos primeras estan permitidas, la ultima no
        String[] aes256 = {"TLS_AES_256_GCM_SHA384"};
        String[] chacha = {"TLS_CHACHA20_POLY1305_SHA256"};
        String[] aes128 = {"TLS_AES_128_GCM_SHA256"};

        int ok = 0;
        ok += probar(host, port, "01_tls13_mtls_aes256", true, new String[]{TLS13}, aes256, certValido, confiaEnCa); // Prueba con AES-256
        ok += probar(host, port, "02_tls13_mtls_chacha20", true, new String[]{TLS13}, chacha, certValido, confiaEnCa); // Prueba con ChaCha20
        ok += probar(host, port, "03_tls12_rechazado", false, new String[]{"TLSv1.2"}, null, certValido, confiaEnCa); // Prueba con TLS 1.2, que debe ser rechazado
        ok += probar(host, port, "04_tls11_rechazado", false, new String[]{"TLSv1.1"}, null, certValido, confiaEnCa); // Prueba con TLS 1.1, que debe ser rechazado
        ok += probar(host, port, "05_tls10_rechazado", false, new String[]{"TLSv1"}, null, certValido, confiaEnCa); // Prueba con TLS 1.0, que debe ser rechazado
        ok += probar(host, port, "06_suite_aes128_rechazada", false, new String[]{TLS13}, aes128, certValido, confiaEnCa); // Prueba con AES-128, que debe ser rechazada
        ok += probar(host, port, "07_sin_certificado", false, new String[]{TLS13}, null, null, confiaEnCa); // Prueba sin certificado
        ok += probar(host, port, "08_certificado_ca_ajena", false, new String[]{TLS13}, null, certAjeno, confiaEnCa); // Prueba con certificado de CA ajena
        ok += probar(host, port, "09_servidor_no_confiable", false, new String[]{TLS13}, null, certValido, confiaEnOtraCa); // Prueba con servidor no confiable

        System.out.printf("%nResultado: %d/9 pruebas correctas%n", ok);
    }

    private static int probar(String host, int port, String nombre, boolean debeConectar,
                              String[] protocolos, String[] suites, KeyManager[] km, TrustManager[] tm) {
        boolean conecta; // Variable que indica si la conexion se ha realizado o no
        String detalle; // Variable que indica el detalle de la conexion, si ha sido correcta o no
        try {
            SSLContext ctx = SSLContext.getInstance("TLS"); // Crea un contexto TLS en general para que pueda admitir otras versiones
            ctx.init(km, tm, new SecureRandom()); // Inicializa el contexto con los gestores de claves y confianza, y un generador de numeros aleatorios
            try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, port)) { // Abre una conexion TSL contra el servidor
                s.setSoTimeout(5000); // Si el servidor no responde en 5 segundos, se considera que la conexion ha fallado
                SSLParameters p = s.getSSLParameters(); // Obtiene la configuracion para poder modificarla
                p.setProtocols(protocolos); // Limita las versiones de TLS a usar
                if (suites != null) p.setCipherSuites(suites);
                p.setEndpointIdentificationAlgorithm("HTTPS"); // Habilita la comprobacion del SAN del certificado del servidor
                s.setSSLParameters(p); // Aplica la configuracion
                s.startHandshake(); // Inicia el handshake TLS para establecer la conexion

                OutputStream out = s.getOutputStream(); // Obtiene el canal para enviar
                out.write(("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII)); // Envia la peticion mas simple HTTP y la convierte en bytes
                out.flush(); // Fuerza a enviar los datos al servidor
                String primera = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII)).readLine(); // Lee la primera linea de lo que responde el servidor
                conecta = primera != null && primera.startsWith("HTTP/"); // Comprueba que la respuesta es HTTP
                detalle = conecta ? s.getSession().getProtocol() + " " + s.getSession().getCipherSuite()
                        : "conexión cerrada por el servidor sin respuesta"; // Guarda la version y el suite que se intercambio
            }
        } catch (Exception e) {
            conecta = false;
            detalle = e.getClass().getSimpleName() + ": " + e.getMessage();
        }

        boolean correcto = conecta == debeConectar;
        System.out.printf("%-28s esperado=%-8s obtenido=%-8s [%s]  %s%n",
                nombre, debeConectar ? "OK" : "RECHAZO", conecta ? "OK" : "RECHAZO",
                correcto ? "CORRECTO" : "FALLO", detalle);
        return correcto ? 1 : 0;
    }

    // ------------------------------------------------------------ utilidades

    private static KeyStore identidadFalsa(String cn, char[] pass) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC"); // Pide a java un generador de claves de curva eliptica
        kpg.initialize(new ECGenParameterSpec("secp256r1")); // Le dice que se use esa curva concreta
        KeyPair kp = kpg.generateKeyPair(); // Genera claves nuevas (atacante)
        X500Name nombre = new X500Name("O=Atacante,OU=PDI,CN=" + cn); // Crea el nombre del certificado con CN= bob
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(nombre, BigInteger.valueOf(666),
                Date.from(Instant.now().minus(5, ChronoUnit.MINUTES)), Date.from(Instant.now().plus(1, ChronoUnit.DAYS)),
                nombre, kp.getPublic()); // Rellena los datos del certificado
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false)); // Indica que el certificado no pertence a una CA
        b.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth})); // Indica que el certificado se pueda usar para cliente y como servidor
        X509Certificate cert = new JcaX509CertificateConverter()
                .getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate()))); // Crea un firmante con la clave privada del atancante, firma el formulario y convierte el certificado en el tipo estandar de Java
        KeyStore ks = KeyStore.getInstance("PKCS12"); // Crea un almacen
        ks.load(null, null); // Lo crea vacio
        ks.setKeyEntry("falsa", kp.getPrivate(), pass, new Certificate[]{cert}); // Guarda la clave privada del atacante y su certificado
        return ks;
    }

    private static KeyStore cargar(String ruta, char[] pass) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12"); // Crea un almacen
        try (InputStream in = Files.newInputStream(Path.of(ruta))) { // Abre el fichero
            ks.load(in, pass); // Lee el fichero y lo descifra con la contraseña
        }
        return ks;
    }

    private static KeyManager[] keyManagers(KeyStore ks, char[] pass) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); // Crea un festor de claves del tipo por defecto
        kmf.init(ks, pass); // Inicializa el gestor con el almacen de claves y la contraseña
        return kmf.getKeyManagers(); // Devuelve el array de gestores de claves
    }

    private static TrustManager[] trustManagers(KeyStore ks) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); // Pide a java un gestor de confianza
        tmf.init(ks); // Le pasa los certificados en que confiar
        return tmf.getTrustManagers(); // Devuelve el array de gestores de confianza
    }
}
