package org.example;

import io.vertx.core.Vertx;
import org.example.server.GatewayVerticle;
import org.example.tls.TLSConfig;                 // ← NUEVO

public class ServerLauncher {
    public static void main(String [] args) {
        TLSConfig.endurecerJvm();                  // Solo TLS 1.3 en toda la JVM

        Vertx vertx = Vertx.vertx();
        vertx.deployVerticle(new GatewayVerticle())
                .onFailure(err -> {
                    System.err.println("No se pudo desplegar GatewayVerticle: " + err.getMessage());
                    System.exit(1);
                });
    }
}