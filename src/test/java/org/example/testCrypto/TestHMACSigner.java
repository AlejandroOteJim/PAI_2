package org.example.testCrypto;

import org.example.crypto.HMACSigner;
import org.testng.annotations.Test;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class TestHMACSigner {

    @Test
    public void pruebaFirmaYVerificacionCorrecta() {
        String mensajeJson = "{\"monto\": 1500.50, \"destino\": \"ES9876543210987654321098\"}";
        byte[] claveSecreta = HMACSigner.generate256BitKey();

        String firmaGenerada = HMACSigner.calculateHmac(mensajeJson, claveSecreta);
        boolean esValida = HMACSigner.verifyHmac(mensajeJson, firmaGenerada, claveSecreta);

        assertTrue(esValida, "La firma original debería ser válida para el mensaje intacto.");
    }

    @Test
    public void pruebaRechazoFirmaAlteradaMitM() {
        String mensajeOriginal = "{\"monto\": 1500.50}";
        byte[] claveSecreta = HMACSigner.generate256BitKey();
        String firmaGenerada = HMACSigner.calculateHmac(mensajeOriginal, claveSecreta);

        // Simulamos que un atacante altera el JSON interceptado en la red pública
        String mensajeAlterado = "{\"monto\": 9999.99}";

        boolean esValida = HMACSigner.verifyHmac(mensajeAlterado, firmaGenerada, claveSecreta);

        assertFalse(esValida, "El sistema debe rechazar la firma si el mensaje ha sido modificado.");
    }
}
