package org.example.client;

import org.example.tls.TLSConfig;
import java.util.Scanner;

public class gitByodTerminal {
    // El cliente se crea después de elegir el certificado del dispositivo BYOD
    private static ByodClient apiClient;

    // Estado de la sesión del usuario
    private static boolean isAuthenticated = false;
    private static String currentUser = null;
    private static String currentIban = null; // Variable para almacenar el IBAN del usuario logueado

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        System.out.println("=========================================");
        System.out.println("     U-SECURE BYOD - TERMINAL (VPN TLS)  ");
        System.out.println("=========================================");

        // Certificado X.509 del dispositivo emitida por la CA para el túnel TLS
        while (apiClient == null) {
            System.out.print("Certificado del dispositivo (.p12): ");
            String ks = scanner.nextLine().trim();

            if (ks.isEmpty()) {
                System.out.println("Es obligatorio indicar el certificado del dispositivo.");
                continue;                                   // vuelve a preguntar
            }

            try {
                apiClient = new ByodClient(ByodClient.DEFAULT_URL, ks, TLSConfig.CONTRASENA); // Crea el cliente con el certificado
                System.out.println("Túnel TLS 1.3 + mTLS configurado contra " + ByodClient.DEFAULT_URL);
            } catch (IllegalStateException e) {
                System.out.println(e.getMessage());
                System.out.println("Inténtalo de nuevo.");
                // apiClient sigue siendo null → el bucle vuelve a preguntar
            }
        }

        while (!exit) {
            if (!isAuthenticated) {
                mostrarMenuAnonimo();
                int opcion = leerOpcionEntera(scanner);

                switch (opcion) {
                    case 1:
                        manejarRegistro(scanner);
                        break;
                    case 2:
                        manejarLogin(scanner);
                        break;
                    case 3:
                        exit = true;
                        System.out.println("Saliendo de la terminal U-Secure...");
                        break;
                    default:
                        System.out.println("Opción inválida. Inténtalo de nuevo.");
                }
            } else {
                mostrarMenuAutenticado();
                int opcion = leerOpcionEntera(scanner);

                switch (opcion) {
                    case 1:
                        manejarTransferencia(scanner);
                        break;
                    case 2:
                        manejarLogout();
                        break;
                    default:
                        System.out.println("Opción inválida. Inténtalo de nuevo.");
                }
            }
        }
        scanner.close();
    }

    private static void mostrarMenuAnonimo() {
        System.out.println("\n--- MENÚ PRINCIPAL ---");
        System.out.println("1. Registrar nuevo usuario");
        System.out.println("2. Iniciar Sesión (Login)");
        System.out.println("3. Salir");
        System.out.print("Elige una opción: ");
    }

    private static void mostrarMenuAutenticado() {
        System.out.println("\n--- U-SECURE | Usuario: " + currentUser + " ---");
        System.out.println("1. Hacer una Transferencia");
        System.out.println("2. Cerrar Sesión (Logout)");
        System.out.print("Elige una opción: ");
    }

    private static int leerOpcionEntera(Scanner scanner) {
        try {
            return Integer.parseInt(scanner.nextLine().trim());
        } catch (NumberFormatException e) {
            return -1; // Retorna -1 para que salte el default del switch
        }
    }

    private static void manejarRegistro(Scanner scanner) {
        System.out.println("\n--- REGISTRO DE USUARIO ---");
        System.out.print("Introduce un username: ");
        String user = scanner.nextLine().trim();
        System.out.print("Introduce una password: ");
        String pass = scanner.nextLine().trim();

        System.out.println("Enviando petición al servidor...");

        try {
            ByodClient.Response res = apiClient.register(user, pass);

            if (res.status() == 201) {
                System.out.println("Usuario '" + user + "' registrado de verdad en la base de datos.");
            } else {
                System.out.println("El servidor rechazó el registro: " + res.body());
            }
        } catch (Exception e) {
            System.out.println("Error de conexión: " + e.getMessage());
        }
    }

    private static void manejarLogin(Scanner scanner) {
        System.out.println("\n--- INICIO DE SESIÓN ---");
        System.out.print("Username: ");
        String user = scanner.nextLine().trim();
        System.out.print("Password: ");
        String pass = scanner.nextLine().trim();

        System.out.println("Verificando credenciales en la base de datos...");

        try {
            ByodClient.Response res = apiClient.login(user, pass);

            if (res.status() == 200) {
                isAuthenticated = true;
                currentUser = user;

                try {
                    com.fasterxml.jackson.databind.JsonNode jsonNode = new com.fasterxml.jackson.databind.ObjectMapper().readTree(res.body());
                    if (jsonNode.has("iban")) {
                        currentIban = jsonNode.get("iban").asText();
                    } else {
                        currentIban = "Asignado automáticamente por el servidor";
                    }
                } catch (Exception ex) {
                    currentIban = "Cuenta origen vinculada en BD";
                }

                System.out.println("Login exitoso. Sesión iniciada.");
            } else {
                System.out.println("Login fallido (Status " + res.status() + "): " + res.body());
            }
        } catch (Exception e) {
            System.out.println("Error de conexión con el servidor: " + e.getMessage());
        }
    }

    private static void manejarLogout() {
        System.out.println("Cerrando sesión en el servidor...");

        try {
            ByodClient.Response res = apiClient.logout();

            if (res.status() == 200) {
                System.out.println("Sesión cerrada correctamente de forma remota.");
            } else {
                System.out.println("El servidor devolvió un error (Status " + res.status() + "): " + res.body());
            }
        } catch (Exception e) {
            System.out.println("Error de conexión al hacer logout: " + e.getMessage());
        } finally {
            isAuthenticated = false;
            currentUser = null;
            currentIban = null; // Limpiamos el IBAN al cerrar sesión
            System.out.println("Sesión local terminada.");
        }
    }

    private static void manejarTransferencia(Scanner scanner) {
        System.out.println("\n--- NUEVA TRANSFERENCIA ---");
        System.out.println("Sesión activa actual: " + currentUser);
        System.out.println("Cuenta origen: " + currentIban);

        System.out.print("Cuenta destino: ");
        String destIban = scanner.nextLine().trim();

        if (destIban.isEmpty()) {
            System.out.println("La cuenta destino no puede estar vacía.");
            return;
        }

        System.out.print("Cantidad: ");
        double amount;
        try {
            amount = Double.parseDouble(scanner.nextLine().trim());
        } catch (NumberFormatException e) {
            System.out.println("Cantidad inválida. Usa números y punto para decimales.");
            return;
        }

        System.out.print("Moneda: ");
        String currency = scanner.nextLine().trim();

        System.out.println("Firmando criptográficamente y enviando al servidor...");

        try {
            // El servidor sobrescribe el origen con el IBAN real de la BD a partir de la sesión
            ByodClient.Response res = apiClient.sendTransfer("AUTO_ORIGIN", destIban, amount, currency);

            if (res.status() == 200) {
                System.out.println("Transferencia completada: " + res.body());
            } else {
                System.out.println("Rechazada por el servidor (Status " + res.status() + "): " + res.body());
            }
        } catch (Exception e) {
            System.out.println("Error en la transferencia: " + e.getMessage());
        }
    }
}