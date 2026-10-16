package org.example.client;

import org.junit.jupiter.api.Test;
import org.example.client.SecBankClient;
import org.example.client.SecBankClient.Response;
import org.example.client.SecBankClient.SignedRequest;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Requiere el servidor arrancado en http://localhost:8080. */
class SecBankIntegrationTest {

    static final String PASS = "Passw0rd!x";
    static final String ORIGIN = "ES1234567890123456789012";
    static final String DEST = "ES9876543210987654321098";
    static final int MAX_ATTEMPTS = 5; // N intentos fallidos (RS1.b): ajustar al valor de A

    static String newUser() { return "test_" + UUID.randomUUID().toString().substring(0, 8); }

    static boolean ok(Response r) { return r.status() >= 200 && r.status() < 300; }

    static boolean rejected(Response r) { return r.status() >= 400; }

    SecBankClient loggedClient() throws Exception {
        SecBankClient c = new SecBankClient();
        String u = newUser();
        assertTrue(ok(c.register(u, PASS)), "registro");
        assertTrue(ok(c.login(u, PASS)), "login");
        return c;
    }

    @Test // RF1.a
    void registroCorrecto() throws Exception {
        assertTrue(ok(new SecBankClient().register(newUser(), PASS)));
    }

    @Test // RF1.c
    void registroDuplicadoRechazado() throws Exception {
        SecBankClient c = new SecBankClient();
        String u = newUser();
        assertTrue(ok(c.register(u, PASS)));
        assertTrue(rejected(c.register(u, PASS)));
    }

    @Test
    void loginConPasswordIncorrectoRechazado() throws Exception {
        SecBankClient c = new SecBankClient();
        String u = newUser();
        c.register(u, PASS);
        assertTrue(rejected(c.login(u, "incorrecta")));
    }

    @Test // RF2
    void transferenciaValidaAceptada() throws Exception {
        assertTrue(ok(loggedClient().sendTransfer(ORIGIN, DEST, 1250.75, "EUR")));
    }

    @Test // RS2 (MitM)
    void transferenciaAlteradaRechazada() throws Exception {
        SecBankClient c = loggedClient();
        SignedRequest sr = c.buildTransfer(ORIGIN, DEST, 1250.75, "EUR");
        String altered = sr.bodyAsString().replace("1250.75", "9999.99");
        assertTrue(rejected(c.send(sr.withBody(altered.getBytes(StandardCharsets.UTF_8)))));
    }

    @Test // RS3 (Replay)
    void replayRechazado() throws Exception {
        SecBankClient c = loggedClient();
        SignedRequest sr = c.buildTransfer(ORIGIN, DEST, 400.00, "EUR");
        assertTrue(ok(c.send(sr)));
        assertTrue(rejected(c.send(sr)));
    }

    @Test // RS3 (timestamp)
    void timestampCaducadoRechazado() throws Exception {
        SecBankClient c = loggedClient();
        long old = System.currentTimeMillis() / 1000 - 600;
        assertTrue(rejected(c.send(c.buildTransfer(ORIGIN, DEST, 400.00, "EUR", old))));
    }

    @Test // RF1.d
    void transferenciaTrasLogoutRechazada() throws Exception {
        SecBankClient c = loggedClient();
        SignedRequest sr = c.buildTransfer(ORIGIN, DEST, 10.00, "EUR");
        c.logout();
        assertTrue(rejected(c.send(sr)));
    }

    @Test // RS1.b
    void bloqueoTrasIntentosFallidos() throws Exception {
        SecBankClient c = new SecBankClient();
        String u = newUser();
        c.register(u, PASS);
        for (int i = 0; i < MAX_ATTEMPTS; i++) c.login(u, "mala" + i);
        assertTrue(rejected(c.login(u, PASS)), "cuenta deberia estar bloqueada");
    }
}