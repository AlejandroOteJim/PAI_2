package org.example.server;

import io.vertx.core.http.HttpServerOptions;
import org.example.tls.TLSConfig;

/**
 * PAI-2 persona B (RS3): parámetros de despliegue del servidor.
 * Se leen de propiedades del sistema (-Dusecure.tls=false ...) o de los argumentos del launcher.
 */
public final class ServerMode {

    public static final int PUERTO_PLANO = 8080; // Solo para el benchmark sin cifrar

    private ServerMode() {}

    // Lee los argumentos del launcher y los guarda como propiedades del sistema
    public static void aplicarArgumentos(String[] args) {
        for (String a : args) {
            if (a.equals("--sin-tls")) System.setProperty("usecure.tls", "false");
            else if (a.startsWith("--instancias=")) System.setProperty("usecure.instancias", a.substring(13));
            else if (a.startsWith("--pool=")) System.setProperty("usecure.pool", a.substring(7));
            else throw new IllegalArgumentException("Argumento desconocido: " + a
                    + " (válidos: --sin-tls, --instancias=N, --pool=N)");
        }
    }

    // true salvo que se arranque con --sin-tls
    public static boolean tls() {
        return !"false".equalsIgnoreCase(System.getProperty("usecure.tls", "true"));
    }

    // Una instancia del verticle por núcleo: cada una tiene su propio event loop
    public static int instancias() {
        return Integer.getInteger("usecure.instancias", Runtime.getRuntime().availableProcessors());
    }

    // Tamaño del pool de conexiones a la BD compartido por todas las instancias
    public static int tamanoPool() {
        return Integer.getInteger("usecure.pool", 32);
    }

    public static int puerto() {
        return tls() ? TLSConfig.PUERTO : PUERTO_PLANO;
    }

    public static String etiqueta() {
        return tls() ? "tls" : "plano";
    }

    // Con TLS usa la configuración de la persona A; sin TLS, HTTP plano en el 8080
    public static HttpServerOptions opcionesServidor() {
        HttpServerOptions o = tls() ? TLSConfig.opcionesServidor() : new HttpServerOptions().setPort(PUERTO_PLANO);
        return o.setAcceptBacklog(1024); // Cola de conexiones pendientes para picos de 300 clientes
    }
}
