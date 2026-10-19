package org.example.pki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;


public final class CertificateAuthority {

    private static final String CURVA_CA = "secp384r1";          // La CA usa claves de curva eliptica P-384 (mas importante == mayor margen)
    private static final String CURVA_DISPOSITIVOS = "secp256r1";        // Para servidor/clientes (handshake rapido)
    private static final String ALGORITMO_FIRMA = "SHA384withECDSA";   // Algoritmo de firma de los certificados

    //Duracion de la CA y de los certificados de servidor/cliente (en dias)

    private static final int CA_DIAS = 3650;
    private static final int DISPOSITIVOS_DIAS = 365;

    // Rutas de los ficheros de la PKI para guardarlos cada fichero y luego buscarlo
    private static final Path DIRECCION_PKI = Path.of(System.getProperty("usecure.pki.dir", "pki"));
    private static final Path CA_ALMACEN = DIRECCION_PKI.resolve("ca/ca.p12"); // Guarda la clave privada de la CA y su certificado, se utiliza cada vez que emite un certificado nuevo
    private static final Path CERT_CA_PEM = DIRECCION_PKI.resolve("ca/ca.crt"); // Guarda el certificado en texto (Es publico)
    private static final Path REGISTRO = DIRECCION_PKI.resolve("ca/index.txt"); // Guarda el registro de todo lo que se emite (uno por certificado)
    private static final Path ALMACEN_CONFIANZA = DIRECCION_PKI.resolve("truststore.p12"); // Guarda unicamente el certificado de la CA, sin clave privada (lo usa cliente/servidor durante el handshake)
    private static final Path ALMACEN_SERVIDOR = DIRECCION_PKI.resolve("server/server.p12"); // Guarda la clave privada del servidor y su certificado (lo usa el servidor durante el handshake)
    private static final Path CLIENTES = DIRECCION_PKI.resolve("clients"); // Guarda la clave privada y el certificado del dispositivo

    private static final char[] CONTRASENA = System.getProperty("usecure.pki.pass", "cambiame").toCharArray(); // Contraseña de los .p12 de servidor cliente y almacen de confianza. Por defecto es "cambiame"
    private static final char[] CA_CONTRASENA = System.getProperty("usecure.ca.pass", new String(CONTRASENA)).toCharArray(); // Contraseña que protege el fichero ca.p12, donde se guarda la clave privada de la CA

    // Lista de pares {usuario, rol} a los que se le emite un certificado al iniciar
    // RF5: HAY CUENTAS DE LOS TRES ROLES DE LA UNIVERSIDAD (PDI, PAS, INV)
    private static final List<String[]> PRECARGADOS = List.of(
            new String[]{"alice", "PDI"}, new String[]{"bob", "PAS"},
            new String[]{"pdi01", "PDI"}, new String[]{"pas01", "PAS"}, new String[]{"inv01", "INV"});

    // Generador de numeros aleatorios para generar las claves y los numeros de serie
    private static final SecureRandom RANDOM = new SecureRandom();

    private final X509Certificate caCert; // Certificado de la CA
    private final PrivateKey caKey; // Clave privada de la CA con la que se firman

    // Constructor privado, se utiliza desde loadOrCreate() y load() para que sea imposible crear una CA con un certificado y una clave que no se casen
    private CertificateAuthority(X509Certificate caCert, PrivateKey caKey) {
        this.caCert = caCert;
        this.caKey = caKey;
    }



    public static void main(String[] args) throws Exception {
        try {
            run(args);
        } catch (IllegalArgumentException | IllegalStateException e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void run(String[] args) throws Exception {
        String cmd = args.length == 0 ? "init" : args[0]; // Guarrda la orden del programa
        switch (cmd) {
            case "init" -> {
                CertificateAuthority ca = loadOrCreate(); // Crea o carga la CA
                ca.issueServer();  // Emite el certificado del servidor VPN. Forma en la que el servidor demuestra a cada cliente que es el servidor autentico y o un impostor
                for (String[] u : PRECARGADOS) ca.issueClient(u[0], u[1]); // Emite el certificado digital de un dispositivo
                System.out.println("\nPKI lista en " + DIRECCION_PKI.toAbsolutePath());
            }
            case "emitir" -> {
                if (args.length != 3) usage(); // Comprueba que no faltan argumentos
                load().issueClient(args[1], args[2].toUpperCase()); // Carga la CA que ya existe, sin crear una nueva.
            }
            case "carga" -> {
                int n = args.length > 1 ? Integer.parseInt(args[1]) : 300; // Si hay un numero de carga lo convierte de texto a numero.
                CertificateAuthority ca = load(); // Carga la CA existente una sola vez
                for (int i = 1; i <= n; i++) ca.issueClient(String.format("carga%03d", i), "PDI", false); // Construye el nombre de usuario
                System.out.println("Emitidos " + n + " certificados de carga (carga001..carga" + String.format("%03d", n) + ")");
            }
            default -> usage();
        }
    }

    private static void usage() {
        System.err.println("""
                Uso: CertificateAuthority                    (CA + servidor + usuarios precargados)
                     CertificateAuthority emitir <usuario> <PDI|PAS|INV>
                     CertificateAuthority carga <N>""");
        System.exit(1);
    }



    public static CertificateAuthority loadOrCreate() throws Exception {
        if (Files.exists(CA_ALMACEN)) {
            System.out.println("[CA] Ya existe " + CA_ALMACEN + ", se reutiliza.");
            return load();
        }

        // Genera las claves y el nombre
        System.out.println("[CA] Generando clave ECDSA P-384 y certificado raíz autofirmado...");
        KeyPair kp = generateKeyPair(CURVA_CA);
        X500Name name = dn("Servicio de Informatica", "U-Secure Root CA");
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();

        // Rellena el certificado con sus seis datos en orden
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                name, newSerial(), notBefore(), notAfter(CA_DIAS), name, kp.getPublic());

        // Añade las extensiones de la CA, el segundo parametro indica si la extension es critica
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));   // CA:TRUE, pathlen:0
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(kp.getPublic()));

        // Firma el documento con la clave privada de la CA
        X509Certificate cert = sign(b, kp.getPrivate());

        // Guarda la CA en el almacén (secreto)
        KeyStore store = emptyStore();
        store.setKeyEntry("u-secure-root-ca", kp.getPrivate(), CA_CONTRASENA, new Certificate[]{cert}); // mete dentro la clave privada, protegida con CA_CONTRASENA y su certificado
        save(store, CA_ALMACEN, CA_CONTRASENA);
        writePem(cert, CERT_CA_PEM); // Guarda el certificado en texto

        // Crea el almacen de confianza (publica) con unicamente el certificado de la CA sin clave privada
        KeyStore trust = emptyStore();
        trust.setCertificateEntry("u-secure-root-ca", cert);
        save(trust, ALMACEN_CONFIANZA, CONTRASENA);

        // Crea el fichero de registro de certificados emitidos
        Files.writeString(REGISTRO, "# serie\tCN\trol\tcaduca\tsha256\n", StandardCharsets.UTF_8);
        log(cert, "CA");
        System.out.println("[CA] OK -> " + CA_ALMACEN + ", " + ALMACEN_CONFIANZA);
        return new CertificateAuthority(cert, kp.getPrivate());
    }

    // Abre el almacen, saca el certificado y la clave privada de la CA, y los mete en un objeto CertificateAuthority
    public static CertificateAuthority load() throws Exception {
        if (!Files.exists(CA_ALMACEN)) {
            throw new IllegalStateException("No existe la CA (" + CA_ALMACEN + "). Ejecuta primero sin argumentos.");
        }
        KeyStore store = KeyStore.getInstance("PKCS12"); // Prepara un almacen vacio del tipo correcto
        try (InputStream in = Files.newInputStream(CA_ALMACEN)) { // lee y cifra el fichero y comprueba que no haya sido modificado
            store.load(in, CA_CONTRASENA);
        }
        String alias = store.aliases().nextElement(); // Busca la entrada dentro de un .p12 y devuelve la lista de alias y coge el primero

        // Saca el certificado y la clave privada y crea el objeto
        return new CertificateAuthority((X509Certificate) store.getCertificate(alias),
                (PrivateKey) store.getKey(alias, CA_CONTRASENA));
    }


    public void issueServer() throws Exception {
        KeyPair kp = generateKeyPair(CURVA_DISPOSITIVOS); // Genera un par de claves para el servidor
        X509v3CertificateBuilder b = leafBuilder(dn("Gateway VPN", "vpn.u-secure.local"), kp); // Plantilla de certificado del servidor
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)); // Limita el uso del certificado a identificar servidores TLS

        // Parte que diferencia un certificado de servidor con uno de cliente
        b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.dNSName, "vpn.u-secure.local"), //nombre corporativo
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")})); // Por si cualquier persona quiere conectarse por IP

        X509Certificate cert = sign(b, caKey); // La CA firma el certificado
        saveIdentity("server", kp.getPrivate(), cert, ALMACEN_SERVIDOR);
        log(cert, "SERVIDOR");
        System.out.println("[SERVIDOR] OK -> " + ALMACEN_SERVIDOR + "  serie=" + serial(cert));
    }



    public Path issueClient(String username, String role) throws Exception {
        return issueClient(username, role, true);
    }


    public Path issueClient(String username, String role, boolean verbose) throws Exception {
        if (!username.matches("[A-Za-z0-9_.-]{1,64}")) {
            throw new IllegalArgumentException("Nombre de usuario no válido: " + username);
        }
        if (!List.of("PDI", "PAS", "INV").contains(role)) { // Validar el rol
            throw new IllegalArgumentException("Rol no válido (PDI, PAS o INV): " + role);
        }
        KeyPair kp = generateKeyPair(CURVA_DISPOSITIVOS);
        X509v3CertificateBuilder b = leafBuilder(dn(role, username), kp); // Construye el certificado con el nombre del usuario
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth)); // Limita el uso unicamente a clientes TLS

        X509Certificate cert = sign(b, caKey); // Firma con la clave privada

        //Guarda la identidad del cliente en un fichero .p12
        Path out = CLIENTES.resolve(username + ".p12");
        saveIdentity(username, kp.getPrivate(), cert, out);

        writePem(cert, CLIENTES.resolve(username + ".crt")); // Guarda el certificado en texto
        log(cert, role); // Añade a index.txt una linea con numero de serie, rol, caducidad y huella SHA-256. (RF1)
        if (verbose) System.out.println("  [CLIENTE] " + username + " (" + role + ") -> " + out + "  serie=" + serial(cert));
        return out;
    }




    private X509v3CertificateBuilder leafBuilder(X500Name subject, KeyPair kp) throws Exception {
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils(); // Herramienta para identificadores de clave
        //Datos basicos para el certificado
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                caCert, newSerial(), notBefore(), notAfter(DISPOSITIVOS_DIAS), subject, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false)); // Este certificado no puede firmar
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature)); // La clave privada del titular solo puede usarse para firmas digitales.
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(kp.getPublic())); // Como DNI: permite identificar esa clave de forma corta y unica
        b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(caCert)); // Identificador de la clave de la CA
        return b;
    }

    // Construye el nombre completo de quien aparece en un certificado
    private static X500Name dn(String ou, String cn) {
        return new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES") //Pais
                .addRDN(BCStyle.ST, "Sevilla") //Provincia
                .addRDN(BCStyle.L, "Las Cabezas de San Juan") // Localidad
                .addRDN(BCStyle.O, "Universidad Publica U-Secure") // Organizacion
                .addRDN(BCStyle.OU, ou) // Rol
                .addRDN(BCStyle.CN, cn) // Usuario o servidor
                .build();
    }

    // Genera una clave privada y su clave publica correspondiente
    private static KeyPair generateKeyPair(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(curve), RANDOM);
        return kpg.generateKeyPair();
    }



    // Genera un nuevo número de serie
    private static BigInteger newSerial() {
        return new BigInteger(127, RANDOM).add(BigInteger.ONE);
    }

    private static Date notBefore() {
        return Date.from(Instant.now().minus(5, ChronoUnit.MINUTES));   // margen por desfase de relojes
    }

    private static Date notAfter(int days) {
        return Date.from(Instant.now().plus(days, ChronoUnit.DAYS));
    }

    // Funcion para firmar el certificado
    private static X509Certificate sign(X509v3CertificateBuilder b, PrivateKey signer) throws Exception {
        ContentSigner cs = new JcaContentSignerBuilder(ALGORITMO_FIRMA).build(signer); // Calcula el resumen con el algoritmo y luego firma con la clave privada de signer
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(b.build(cs)); // Conveirte al tipo estandar de Java
        cert.checkValidity(); // Comprueba fechas
        return cert;
    }

    // Guarda la identidad(clave privada + certificado + certidicado de la CA) en un .p12
    private void saveIdentity(String alias, PrivateKey key, X509Certificate cert, Path out) throws Exception {
        cert.verify(caCert.getPublicKey());   // Comprueba con la clave publica que la firma del certificado es la correcta
        KeyStore ks = emptyStore();
        ks.setKeyEntry(alias, key, CONTRASENA, new Certificate[]{cert, caCert});
        save(ks, out, CONTRASENA); // Guarda en el .p12
    }

    private static KeyStore emptyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        return ks;
    }

    private static void save(KeyStore ks, Path out, char[] pass) throws Exception {
        Files.createDirectories(out.toAbsolutePath().getParent());
        try (OutputStream os = Files.newOutputStream(out)) {
            ks.store(os, pass);
        }
    }

    // Escribe un certificado en formato PEM
    private static void writePem(X509Certificate cert, Path out) throws Exception {
        Files.createDirectories(out.toAbsolutePath().getParent());
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(cert.getEncoded());
        Files.writeString(out, "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n", StandardCharsets.US_ASCII);
    }

    private static String serial(X509Certificate cert) {
        return cert.getSerialNumber().toString(16).toUpperCase();
    }

    // Apunta cada certificado emitido en el registro de la CA
    private static void log(X509Certificate cert, String role) throws IOException {
        String cn = cert.getSubjectX500Principal().getName().replaceAll(".*CN=([^,]+).*", "$1"); // Sacar el nombre de usuario del certificado
        String fp;
        try {
            fp = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())); // Calcula la huella SHA-256
        } catch (Exception e) {
            fp = "?";
        }
        String line = serial(cert) + "\t" + cn + "\t" + role + "\t" + cert.getNotAfter().toInstant() + "\t" + fp + "\n"; // Monta la linea con los datos del certificado
        Files.writeString(REGISTRO, line, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND); // Añade al ficehro de registro
    }
}