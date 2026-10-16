package org.example.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class HMACSigner {

    // Se especifica el algoritmo requerido por el proyecto
    private static final String ALGORITHM = "HmacSHA256";

    /**
     * Genera una clave segura de 256 bits usando un PRNG criptográficamente seguro.
     */
    public static byte[] generate256BitKey() {
        byte[] key = new byte[32]; // 32 bytes * 8 bits/byte = 256 bits

        // El proyecto exige que las claves se generen mediante un PRNG seguro.
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key); // Rellena el array con valores aleatorios seguros
        return key;
    }

    /**
     * Genera la firma HMAC-SHA256 a partir de los datos y la clave.
     */
    public static String calculateHmac(String data, byte[] key) {
        try {
            // Inicializamos el objeto Mac con el algoritmo HMAC-SHA256
            Mac mac = Mac.getInstance(ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
            mac.init(secretKeySpec);

            // Calculamos la firma de los datos (el mensaje completo: timestamp + nonce + body)
            byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

            // Devolvemos la firma codificada en Base64
            return Base64.getEncoder().encodeToString(hmacBytes);

        } catch (Exception e) {
            throw new RuntimeException("Error al calcular HMAC-SHA256", e);
        }
    }

    public static boolean verifyHmac(String data, String receivedHmacBase64, byte[] key) {
        try {
            // 1. Calculamos cómo debería ser la firma con los datos recibidos
            String expectedHmacBase64 = calculateHmac(data, key);

            // 2. Decodificamos ambas firmas de Base64 a arrays de bytes crudos
            byte[] expectedMacBytes = Base64.getDecoder().decode(expectedHmacBase64);
            byte[] receivedMacBytes = Base64.getDecoder().decode(receivedHmacBase64);

            // 3. Comparamos en tiempo constante
            return ConstantTimeComparer.isEquals(expectedMacBytes, receivedMacBytes);

        } catch (IllegalArgumentException e) {
            // Si el Base64 que envía el atacante tiene un formato inválido, fallamos con seguridad
            return false;
        }
    }
}