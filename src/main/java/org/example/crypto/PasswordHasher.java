package org.example.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class PasswordHasher {

    // Parámetros de seguridad para hacer el algoritmo resistente a fuerza bruta
    private static final int ITERATIONS = 65536; //forzamos al servidor a encriptar el resultado sobre sí mismo 65.536 veces
    private static final int KEY_LENGTH = 256;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    /**
     * Genera una sal (salt) aleatoria única de 16 bytes para cada usuario.
     */

    //RS1. Almacenamiento y Verificación de Credenciales
    //Se prohíbe guardar contraseñas en texto plano o usar algoritmos obsoletos como MD5 o SHA1.
    public static String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Deriva la contraseña usando PBKDF2, la salt del usuario y múltiples iteraciones.
     */
    public static String hashPassword(String password, String saltBase64) {
        try {
            byte[] salt = Base64.getDecoder().decode(saltBase64);

            // Mezclamos la contraseña con la sal, aplicando 65536 iteraciones
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);

            byte[] hashBytes = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hashBytes);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error al derivar la contraseña con PBKDF2", e);
        }
    }

    /**
     * Verifica si un intento de inicio de sesión es correcto.
     */
    public static boolean verifyPassword(String inputPassword, String storedSalt, String storedHash) {
        // 1. Calculamos el hash de la contraseña introducida usando la sal guardada en la BD
        String calculatedHash = hashPassword(inputPassword, storedSalt);

        // 2. Usamos el comparador de tiempo constante creado anteriormente para evitar Timing Attacks
        byte[] calculatedBytes = Base64.getDecoder().decode(calculatedHash);
        byte[] storedBytes = Base64.getDecoder().decode(storedHash);

        return ConstantTimeComparer.isEquals(calculatedBytes, storedBytes);
    }
}