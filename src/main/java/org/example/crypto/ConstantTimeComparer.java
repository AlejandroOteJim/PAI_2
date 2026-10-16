package org.example.crypto;

import java.security.MessageDigest;

public class ConstantTimeComparer {

    /**
     * Compara dos arrays de bytes en tiempo constante para evitar Timing Attacks.
     */
    public static boolean isEquals(byte[] macReceptor, byte[] macCalculado) {
        //RS4. Mitigación de Canales Laterales de Tiempo (Timing Attacks)
        /*MessageDigest.isEqual es el metodo para Java el cual garantiza que el tiempo de comparación dependa*/
        // solo de la longitud de los arrays, no de los bytes que coincidan. A diferencia del típico metodo
        //Arrays.equals(), recorre todos los bytes del mensaje, aunque haya errores desde el principio.

        return MessageDigest.isEqual(macReceptor, macCalculado);
    }
}
