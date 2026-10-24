package org.example.bench;

import org.example.client.ByodClient;
import org.example.server.ServerMode;
import org.example.tls.TLSConfig;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * PAI-2 persona B (RS3): cliente de carga con N dispositivos BYOD concurrentes (por defecto 300).
 * Cada dispositivo es un hilo con su propio certificado (pki/clients/cargaNNN.p12) y su propio túnel TLS.
 * Todos avanzan a la vez por las fases HANDSHAKE -> REGISTRO -> LOGIN -> TRANSFERENCIAS -> LOGOUT
 * (una barrera las separa), de modo que en la fase de transferencias hay N sesiones abiertas simultáneamente.
 *
 * Uso: LoadTestClient [--modo=tls|plano] [--usuarios=300] [--transferencias=5] [--host=localhost]
 * Antes: CertificateAuthority carga 300 (crea los certificados) y el servidor arrancado en el mismo modo.
 */
public final class LoadTestClient {

    static final String[] FASES = {"HANDSHAKE", "REGISTRO", "LOGIN", "TRANSFERENCIA", "LOGOUT"};
    static final String PASSWORD = "Carga.U-Secure.2026";
    static final String IBAN_DESTINO = "ES9121000418450200051332"; // IBAN de alice

    private final boolean tls;
    private final int usuarios;
    private final int transferencias;
    private final String host;
    private final Metricas metricas = new Metricas();
    private final long[] inicioFase = new long[FASES.length + 1];

    LoadTestClient(boolean tls, int usuarios, int transferencias, String host) {
        this.tls = tls;
        this.usuarios = usuarios;
        this.transferencias = transferencias;
        this.host = host;
    }

    public static void main(String[] args) throws Exception {
        boolean tls = true;
        int usuarios = 300, transferencias = 5;
        String host = "localhost";
        for (String a : args) {
            if (a.startsWith("--modo=")) tls = !a.substring(7).equalsIgnoreCase("plano");
            else if (a.startsWith("--usuarios=")) usuarios = Integer.parseInt(a.substring(11));
            else if (a.startsWith("--transferencias=")) transferencias = Integer.parseInt(a.substring(17));
            else if (a.startsWith("--host=")) host = a.substring(7);
            else throw new IllegalArgumentException("Argumento desconocido: " + a);
        }
        if (tls) TLSConfig.endurecerJvm();
        new LoadTestClient(tls, usuarios, transferencias, host).run();
    }

    void run() throws Exception {
        String modo = tls ? "tls" : "plano";
        int puerto = tls ? TLSConfig.PUERTO : ServerMode.PUERTO_PLANO;
        String url = (tls ? "https://" : "http://") + host + ":" + puerto;
        System.out.printf("Benchmark %s contra %s: %d dispositivos, %d transferencias cada uno%n",
                modo.toUpperCase(), url, usuarios, transferencias);

        // Cada barrera apunta la hora a la que todos los dispositivos han terminado la fase anterior
        int[] fase = {0};
        CyclicBarrier barrera = new CyclicBarrier(usuarios, () -> inicioFase[fase[0]++] = System.nanoTime());
        MuestreoRecursos recursos = MuestreoRecursos.iniciar();

        List<Thread> hilos = new ArrayList<>();
        for (int i = 1; i <= usuarios; i++) {
            String usuario = String.format("carga%03d", i);
            Thread t = new Thread(() -> dispositivo(usuario, url, puerto, barrera), "byod-" + usuario);
            hilos.add(t);
            t.start();
        }
        for (Thread t : hilos) t.join();
        recursos.parar();

        Informe.imprimirYGuardar(modo, usuarios, transferencias, metricas, inicioFase, recursos);
    }

    // Lo que hace un dispositivo: preparar su cliente y recorrer las fases sincronizado con los demás
    private void dispositivo(String usuario, String url, int puerto, CyclicBarrier barrera) {
        ByodClient cliente = null;
        SSLContext ctx = null;
        boolean vivo = true;
        try {
            // Cargar el .p12 es caro (descifrado PBE): se hace antes de empezar a medir
            if (tls) ctx = TLSConfig.contextoCliente("pki/clients/" + usuario + ".p12", TLSConfig.CONTRASENA);
            cliente = tls ? new ByodClient(url, "pki/clients/" + usuario + ".p12", TLSConfig.CONTRASENA) : ByodClient.sinTls(url);
        } catch (Exception e) {
            metricas.error("PREPARACION", usuario, e);
            vivo = false;
        }

        try {
            barrera.await(); // Salida: todos empiezan a la vez

            if (vivo) vivo = medirHandshake(usuario, puerto, ctx);
            barrera.await();

            if (vivo) vivo = medir("REGISTRO", usuario, cliente, c -> c.register(usuario, PASSWORD), 201, 409);
            barrera.await();

            if (vivo) vivo = medir("LOGIN", usuario, cliente, c -> c.login(usuario, PASSWORD), 200);
            barrera.await(); // Aquí hay N sesiones abiertas a la vez

            for (int k = 0; vivo && k < transferencias; k++) {
                vivo = medir("TRANSFERENCIA", usuario, cliente, c -> c.sendTransfer("AUTO_ORIGIN", IBAN_DESTINO, 10.0, "EUR"), 200);
            }
            barrera.await();

            if (vivo) medir("LOGOUT", usuario, cliente, ByodClient::logout, 200);
            barrera.await();
        } catch (Exception e) {
            metricas.error("BARRERA", usuario, e);
        }
    }

    // Tiempo de establecer la conexión: TCP + handshake TLS 1.3 con mTLS, o solo TCP en modo plano
    private boolean medirHandshake(String usuario, int puerto, SSLContext ctx) {
        long t0 = System.nanoTime();
        for (int intento = 1; ; intento++) {
            try {
                if (tls) {
                    try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, puerto)) {
                        s.setSSLParameters(TLSConfig.parametrosCliente());
                        s.startHandshake();
                    }
                } else {
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(host, puerto));
                    }
                }
                metricas.ok("HANDSHAKE", usuario, System.nanoTime() - t0);
                return true;
            } catch (java.net.ConnectException e) {
                if (intento >= 5) {
                    metricas.error("HANDSHAKE", usuario, e);
                    return false;
                }
                try { Thread.sleep(20L * intento); } catch (InterruptedException ie) { return false; }
            } catch (Exception e) {
                metricas.error("HANDSHAKE", usuario, e);
                return false;
            }
        }
    }

    @FunctionalInterface
    interface Operacion {
        ByodClient.Response ejecutar(ByodClient c) throws Exception;
    }

    // Ejecuta una petición, mide su latencia y la cuenta como correcta si el código HTTP es uno de los esperados
    private boolean medir(String fase, String usuario, ByodClient cliente, Operacion op, int... esperados) {
        long t0 = System.nanoTime();
        try {
            ByodClient.Response r = op.ejecutar(cliente);
            long dt = System.nanoTime() - t0;
            for (int e : esperados) {
                if (r.status() == e) {
                    metricas.ok(fase, usuario, dt);
                    return true;
                }
            }
            metricas.fallo(fase, usuario, dt, r.status() + " " + r.body());
            return false;
        } catch (Exception e) {
            metricas.error(fase, usuario, e);
            return false;
        }
    }

    /** CPU y RAM del propio cliente de carga (la del servidor la apunta ResourceMonitor). */
    static final class MuestreoRecursos {
        private final ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor();
        private final List<double[]> muestras = new ArrayList<>(); // {cpu%, heapMB}

        static MuestreoRecursos iniciar() {
            MuestreoRecursos m = new MuestreoRecursos();
            var os = (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
            var mem = ManagementFactory.getMemoryMXBean();
            m.exec.scheduleAtFixedRate(() -> {
                synchronized (m.muestras) {
                    m.muestras.add(new double[]{Math.max(0, os.getProcessCpuLoad()) * 100,
                            mem.getHeapMemoryUsage().getUsed() / (1024.0 * 1024)});
                }
            }, 0, 500, TimeUnit.MILLISECONDS);
            return m;
        }

        void parar() throws InterruptedException {
            exec.shutdown();
            exec.awaitTermination(2, TimeUnit.SECONDS);
        }

        double[] mediaYMaximo(int col) {
            synchronized (muestras) {
                double suma = 0, max = 0;
                for (double[] s : muestras) {
                    suma += s[col];
                    max = Math.max(max, s[col]);
                }
                return new double[]{muestras.isEmpty() ? 0 : suma / muestras.size(), max};
            }
        }
    }
}
