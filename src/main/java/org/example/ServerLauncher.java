package org.example;

import io.vertx.core.Vertx;
import org.example.server.SecBankVerticle;

public class ServerLauncher {
    public static void main(String [] args) {
        Vertx vertx = Vertx.vertx();
        vertx.deployVerticle(new SecBankVerticle())
                .onFailure(err -> {
                    System.err.println("No se pudo desplegar SecBankVerticle: " + err.getMessage());
                    System.exit(1);
                });
    }
}
