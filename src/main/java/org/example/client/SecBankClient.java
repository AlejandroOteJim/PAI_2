package org.example.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Cliente SecBank (parte C). Firma cada transferencia con HMAC-SHA256 en la capa de
 * aplicacion. Transporte: HTTP plano (sin TLS), como exige el enunciado.
 *
 * CONTRATO ASUMIDO (acordar con A y B, ajustar aqui si cambia):
 *  - POST /api/v1/register  {"username","password"}
 *  - POST /api/v1/login     {"username","password"} -> {"token":"...","hmacKey":"<hex>"}
 *  - POST /api/v1/logout    cabecera Authorization: Bearer <token>
 *  - POST /api/v1/transfer  body JSON (con tx_id..timestamp) + X-Signature, X-Nonce, X-Timestamp + Authorization
 *  (el servidor actual solo tiene /api/v1/login, y sin token todavia)
 *  - Firma: HMAC-SHA256( timestamp + "\n" + nonce + "\n" + bodyBytes ), en hexadecimal
 */
public class SecBankClient {

    public static final String DEFAULT_URL = "http://localhost:8080";
    public static final String API = "/api/v1";
    public static final String TRANSFER_PATH = API + "/transfer";

    public record Response(int status, String body) {}

    /** Peticion ya firmada. Los ataques la manipulan o la reenvian tal cual. */
    public record SignedRequest(byte[] body, String nonce, long timestamp, String signature) {
        public SignedRequest withBody(byte[] newBody) {
            return new SignedRequest(newBody, nonce, timestamp, signature);
        }
        public String bodyAsString() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    // Forzamos HTTP/1.1: por defecto HttpClient.newHttpClient() negocia HTTP/2
    // (upgrade h2c en texto plano) y eso hace que Wireshark deje de mostrar las
    // peticiones como texto legible (HTTP/1.1), sino como framing binario HTTP/2.
    // Para la práctica (captura/análisis manual) necesitamos quedarnos en HTTP/1.1.
    private final HttpClient http = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    private final ObjectMapper mapper = new ObjectMapper();
    private final String baseUrl;
    private String token;
    private byte[] hmacKey;

    public SecBankClient() { this(DEFAULT_URL); }

    public SecBankClient(String baseUrl) { this.baseUrl = baseUrl; }

    // ---------- Gestion de usuarios ----------

    public Response register(String username, String password) throws Exception {
        return postJson(API + "/register", Map.of("username", username, "password", password), false);
    }

    public Response login(String username, String password) throws Exception {
        Response r = postJson(API + "/login", Map.of("username", username, "password", password), false);
        if (r.status() == 200) {
            JsonNode n = mapper.readTree(r.body());

            // 1. Tu servidor envía "session_id", así que buscamos eso
            if (n.hasNonNull("session_id")) {
                this.token = n.get("session_id").asText();
            }

            // 2. Tu servidor envía "hmac_key" en Base64, así que buscamos eso
            if (n.hasNonNull("hmac_key")) {
                this.hmacKey = java.util.Base64.getDecoder().decode(n.get("hmac_key").asText());
            }
        }
        return r;
    }

    public Response logout() throws Exception {
        // Aseguramos que no sea null para evitar que Map.of() falle
        String idSesion = (this.token != null) ? this.token : "";

        // Enviamos el token dentro del JSON como "session_id"
        Response r = postJson(API + "/logout", Map.of("session_id", idSesion), true);

        // Borramos el token de la memoria local
        this.token = null;
        return r;
    }

    // ---------- Transacciones ----------

    public SignedRequest buildTransfer(String origin, String dest, double amount, String currency) throws Exception {
        return buildTransfer(origin, dest, amount, currency, System.currentTimeMillis() / 1000);
    }

    /** Permite fijar el timestamp (para probar mensajes caducados). */
    public SignedRequest buildTransfer(String origin, String dest, double amount, String currency, long timestamp)
            throws Exception {
        Map<String, Object> tx = new LinkedHashMap<>();
        tx.put("tx_id", UUID.randomUUID().toString());
        tx.put("origin_account", origin);
        tx.put("destination_account", dest);
        tx.put("amount", amount);
        tx.put("currency", currency);
        tx.put("timestamp", timestamp); // el modelo Transaction del servidor lo incluye

        // Se serializa UNA sola vez: estos mismos bytes se firman y se envian.
        byte[] body = mapper.writeValueAsBytes(tx);
        String nonce = UUID.randomUUID().toString();
        return new SignedRequest(body, nonce, timestamp, sign(body, nonce, timestamp));
    }

    public Response send(SignedRequest r) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + TRANSFER_PATH))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + token)
                .header("X-Signature", r.signature())
                .header("X-Nonce", r.nonce())
                .header("X-Timestamp", Long.toString(r.timestamp()))
                .POST(HttpRequest.BodyPublishers.ofByteArray(r.body()))
                .build();
        return exec(req);
    }

    public Response sendTransfer(String origin, String dest, double amount, String currency) throws Exception {
        return send(buildTransfer(origin, dest, amount, currency));
    }

    // ---------- Criptografia ----------

    public String sign(byte[] body, String nonce, long timestamp) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
        mac.update((timestamp + "\n" + nonce + "\n").getBytes(StandardCharsets.UTF_8));

        // Cambiamos a Base64 para que coincida exactamente con el servidor
        byte[] hmacBytes = mac.doFinal(body);
        return java.util.Base64.getEncoder().encodeToString(hmacBytes);
    }

    // ---------- HTTP ----------

    private Response postJson(String path, Map<String, ?> payload, boolean auth) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(payload)));
        if (auth) b.header("Authorization", "Bearer " + token);
        return exec(b.build());
    }

    private Response exec(HttpRequest req) throws Exception {
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        return new Response(res.statusCode(), res.body());
    }

}