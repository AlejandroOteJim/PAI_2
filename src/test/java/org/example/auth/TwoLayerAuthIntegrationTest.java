package org.example.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.client.ByodClient;
import org.example.client.ByodClient.Response;
import org.example.tls.TLSConfig;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PAI-2 persona B (RF1, RF2): requiere el servidor arrancado en modo TLS (https://localhost:8443),
 * la PKI inicializada y los certificados de carga emitidos (CertificateAuthority carga 300).
 */
class TwoLayerAuthIntegrationTest {

    static final String URL = ByodClient.DEFAULT_URL;
    static final String PASS = TLSConfig.CONTRASENA;

    static ByodClient dispositivo(String usuario) {
        return new ByodClient(URL, "pki/clients/" + usuario + ".p12", PASS);
    }

    @Test // RF2: certificado de alice + credenciales de alice
    void loginConCertificadoYCredencialesCorrectos() throws Exception {
        ByodClient alice = dispositivo("alice");
        assertEquals(200, alice.login("alice", "alice").status());
        assertEquals(200, alice.sendTransfer("AUTO_ORIGIN", "ES7921000813610123456789", 1.0, "EUR").status());
        alice.logout();
    }

    @Test // RF2: la contraseña de bob es correcta, pero el dispositivo es de alice
    void loginConCertificadoDeOtroUsuarioRechazado() throws Exception {
        assertEquals(403, dispositivo("alice").login("bob", "bob").status());
    }

    @Test // RF2: certificado correcto pero contraseña incorrecta
    void loginConPasswordIncorrectaRechazado() throws Exception {
        assertEquals(401, dispositivo("pdi01").login("pdi01", "incorrecta").status());
    }

    @Test // RF1: no se puede registrar un nombre distinto del CN del certificado
    void registroConNombreDistintoDelCertificadoRechazado() throws Exception {
        assertEquals(403, dispositivo("carga299").register("intruso", "Passw0rd!x").status());
    }

    @Test // RF1: el registro empareja el certificado; un segundo registro con él se rechaza
    void registroEmparejaElCertificado() throws Exception {
        ByodClient c = dispositivo("carga300");
        Response primero = c.register("carga300", "Passw0rd!x");
        assertTrue(primero.status() == 201 || primero.status() == 409, primero.body());
        assertEquals(409, c.register("carga300", "Passw0rd!x").status());
    }

    @Test // Sesión ligada al dispositivo: el session_id de alice no sirve desde el certificado de bob
    void sessionIdRobadoDesdeOtroDispositivoRechazado() throws Exception {
        Response login = dispositivo("alice").login("alice", "alice");
        String sessionId = new ObjectMapper().readTree(login.body()).get("session_id").asText();

        HttpClient deBob = HttpClient.newBuilder()
                .sslContext(TLSConfig.contextoCliente("pki/clients/bob.p12", PASS))
                .sslParameters(TLSConfig.parametrosCliente())
                .build();
        HttpResponse<String> r = deBob.send(HttpRequest.newBuilder(URI.create(URL + "/api/v1/transfer"))
                .header("Authorization", "Bearer " + sessionId)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build(), HttpResponse.BodyHandlers.ofString());

        assertEquals(401, r.statusCode());
        assertTrue(r.body().contains("otro dispositivo"), r.body());
    }
}
