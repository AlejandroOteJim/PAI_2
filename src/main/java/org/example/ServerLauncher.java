package org.example;

import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import org.example.auth.DeviceRegistry;
import org.example.db.DataBaseInitializer;
import org.example.db.SharedPool;
import org.example.server.GatewayVerticle;
import org.example.server.ResourceMonitor;
import org.example.server.ServerMode;
import org.example.tls.TLSConfig;                 // ← NUEVO

import java.nio.file.Path;

public class ServerLauncher {
    // Argumentos opcionales (persona B, RS3): --sin-tls  --instancias=N  --pool=N
    public static void main(String [] args) {
        ServerMode.aplicarArgumentos(args);
        TLSConfig.endurecerJvm();                  // Solo TLS 1.3 en toda la JVM

        if (!ServerMode.tls()) {
            System.out.println("*** AVISO: servidor SIN TLS en el puerto " + ServerMode.PUERTO_PLANO
                    + ". Solo para el benchmark comparativo (RS3), nunca en producción. ***");
        }

        Vertx vertx = Vertx.vertx();
        int instancias = ServerMode.instancias();

        // 1. Esquema de BD una sola vez (antes lo hacía cada verticle y con varias instancias chocarían)
        // 2. RF5: emparejar los usuarios precargados con los certificados que ya emitió la CA
        // 3. Una instancia del verticle por núcleo, todas en el mismo puerto (Vert.x reparte las conexiones)
        DataBaseInitializer.init(vertx)
                .compose(v -> new DeviceRegistry(SharedPool.crear(vertx)).seedFromCaIndex(Path.of("pki/ca/index.txt")))
                .compose(emparejados -> {
                    System.out.println("Certificados precargados emparejados: " + emparejados);
                    return vertx.deployVerticle(GatewayVerticle::new, new DeploymentOptions().setInstances(instancias));
                })
                .onSuccess(id -> {
                    System.out.println("Gateway U-Secure listo: " + instancias + " instancias, pool BD de "
                            + ServerMode.tamanoPool() + " conexiones, modo " + ServerMode.etiqueta().toUpperCase()
                            + ", puerto " + ServerMode.puerto());
                    ResourceMonitor.start(vertx, ServerMode.etiqueta());
                })
                .onFailure(err -> {
                    System.err.println("No se pudo desplegar GatewayVerticle: " + err.getMessage());
                    System.exit(1);
                });
    }
}
