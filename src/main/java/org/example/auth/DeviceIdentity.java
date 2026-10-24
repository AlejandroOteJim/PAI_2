package org.example.auth;

import io.vertx.core.http.HttpServerRequest;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.List;

/**
 * PAI-2 persona B (RF1/RF2): identidad del dispositivo BYOD sacada del certificado X.509 que presentó en el handshake mTLS.
 * El número de serie y la huella usan el mismo formato que pki/ca/index.txt (CertificateAuthority).
 */
public record DeviceIdentity(String cn, String role, String serial, String fingerprint) {

    // Devuelve la identidad del certificado de cliente de la petición, o null si la conexión no es TLS / no hay certificado
    public static DeviceIdentity fromRequest(HttpServerRequest req) {
        if (!req.isSSL()) return null;
        try {
            List<Certificate> certs = req.connection().peerCertificates();
            if (certs == null || certs.isEmpty() || !(certs.get(0) instanceof X509Certificate x509)) return null;
            return fromCertificate(x509);
        } catch (SSLPeerUnverifiedException e) {
            return null;
        }
    }

    public static DeviceIdentity fromCertificate(X509Certificate cert) {
        String cn = null;
        String ou = null;
        try {
            for (Rdn rdn : new LdapName(cert.getSubjectX500Principal().getName()).getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) cn = rdn.getValue().toString();
                if (rdn.getType().equalsIgnoreCase("OU")) ou = rdn.getValue().toString();
            }
            String serial = cert.getSerialNumber().toString(16).toUpperCase(); // Igual que CertificateAuthority.serial()
            String fp = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
            return new DeviceIdentity(cn, ou, serial, fp);
        } catch (Exception e) {
            throw new IllegalArgumentException("Certificado de cliente ilegible: " + e.getMessage(), e);
        }
    }

    // RF1/RF2: el certificado tiene que ser del mismo usuario que se registra o inicia sesión
    public boolean belongsTo(String username) {
        return cn != null && cn.equals(username);
    }

    @Override
    public String toString() {
        return "CN=" + cn + ", OU=" + role + ", serie=" + serial;
    }
}
