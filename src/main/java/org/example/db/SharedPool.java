package org.example.db;

import io.vertx.core.Vertx;
import io.vertx.mysqlclient.MySQLBuilder;
import io.vertx.mysqlclient.MySQLConnectOptions;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.PoolOptions;
import org.example.server.ServerMode;

/**
 * PAI-2 persona B (RS3): pool de conexiones a "usecure" compartido por todas las instancias del verticle.
 * Al ser "shared" con un nombre fijo, Vert.x devuelve el mismo pool a quien lo pida, en vez de abrir uno por instancia.
 */
public final class SharedPool {

    public static final String NOMBRE = "usecure-pool";

    private SharedPool() {}

    public static MySQLConnectOptions opcionesConexion() {
        return new MySQLConnectOptions()
                .setPort(3306)
                .setHost("localhost")
                .setDatabase("usecure")
                .setUser("root")
                .setPassword("root");
    }

    public static Pool crear(Vertx vertx) {
        PoolOptions poolOptions = new PoolOptions()
                .setShared(true)
                .setName(NOMBRE)
                .setMaxSize(ServerMode.tamanoPool())
                .setMaxWaitQueueSize(2000); // Peticiones que pueden esperar una conexión libre

        return MySQLBuilder.pool()
                .with(poolOptions)
                .connectingTo(opcionesConexion())
                .using(vertx)
                .build();
    }
}
