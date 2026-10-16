package org.example.testCrypto;

import org.example.crypto.PasswordHasher;
import org.testng.annotations.Test;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class TestPasswordHasher {

    @Test
    public void pruebaHashYLoginCorrecto() {
        String contrasena = "MiSecreto123!";

        // Simulamos un registro
        String salGenerada = PasswordHasher.generateSalt();
        String hashGuardado = PasswordHasher.hashPassword(contrasena, salGenerada);

        // Simulamos el login
        boolean loginExitoso = PasswordHasher.verifyPassword(contrasena, salGenerada, hashGuardado);

        assertTrue(loginExitoso, "El usuario debe poder iniciar sesión con su contraseña correcta.");
    }

    @Test
    public void pruebaRechazoContrasenaIncorrecta() {
        String contrasenaReal = "MiSecreto123!";
        String contrasenaFalsa = "Atacante456!";

        String salGenerada = PasswordHasher.generateSalt();
        String hashGuardado = PasswordHasher.hashPassword(contrasenaReal, salGenerada);

        boolean loginExitoso = PasswordHasher.verifyPassword(contrasenaFalsa, salGenerada, hashGuardado);

        assertFalse(loginExitoso, "El inicio de sesión debe fallar con una contraseña incorrecta.");
    }
}