# PAI-2 · BYODSEC — Reparto del trabajo

Punto de partida: el proyecto de la PAI-1 (API REST con Vert.x sobre HTTP plano, con HMAC, nonces y PBKDF2).
Entrega: martes 27 de octubre, 23:59, como `PAI2-STX.zip`.

---

## Persona A: PKI y canal seguro TLS 1.3
**Cubre:** objetivos 1 y 2 · RS1 · RS2 · RF5

- [ ] Crear el script de la PKI con OpenSSL y keytool:
  - CA corporativa.
  - Certificado del servidor (serverAuth, con SAN `localhost` / `127.0.0.1`).
  - Certificados de cliente por usuario (clientAuth, CN = usuario, OU = rol).
  - Keystores `.p12` y truststore.
- [ ] Generar los certificados de los usuarios precargados por rol (PDI, PAS, Investigadores) y 300 certificados para las pruebas de carga (RF5).
- [ ] Pasar el servidor Vert.x de HTTP a HTTPS:
  - Solo TLS 1.3, con SSLv3, TLS 1.0, 1.1 y 1.2 deshabilitados.
  - Solo las suites `TLS_AES_256_GCM_SHA384` y `TLS_CHACHA20_POLY1305_SHA256`.
  - Certificado de cliente obligatorio (`ClientAuth.REQUIRED`).
- [ ] Pasar el cliente a HTTPS: `SSLContext` con el certificado del dispositivo y el truststore de la CA, forzando TLS 1.3 y verificando el nombre del servidor.
- [ ] Comprobar con `openssl s_client` que se rechazan TLS 1.2, la conexión sin certificado, una CA ajena y una suite débil, y guardar los logs.
- [ ] Memoria: resumen de decisiones técnicas (PKI, algoritmos, suites, PFS) y manual de despliegue y uso.

## Persona B: autenticación en dos capas y rendimiento
**Cubre:** objetivo 3 · RF1 · RF2 · RS3

- [ ] RF1, registro: vincular cada usuario nuevo a su certificado (número de serie y huella en BD) y permitir el registro solo si el CN del certificado coincide con el usuario.
- [ ] RF1, inmutabilidad: tabla de certificados revocados y procedimiento de revocación y re-emisión.
- [ ] RF2, login en dos capas: certificado válido (mTLS), más CN igual al usuario, más certificado emparejado y no revocado, más usuario y contraseña con PBKDF2.
- [ ] Ligar la sesión al dispositivo: un `session_id` no sirve desde otro certificado.
- [ ] Preparar el servidor para 300 sesiones simultáneas:
  - Varias instancias del verticle (una por núcleo).
  - Pool de BD compartido y más grande.
  - PBKDF2 fuera del event loop (`executeBlocking`).
- [ ] Añadir un modo sin TLS (con un flag) para poder comparar.
- [ ] Escribir un cliente de carga con 300 dispositivos concurrentes y medir throughput, latencia, tiempo de handshake, CPU y RAM, con y sin TLS.
- [ ] Memoria: modelo de concurrencia, metodología del benchmark, resultados con gráficas y análisis del sobrecoste.

## Persona C: cierre de sesión, auditoría y ataques
**Cubre:** objetivos 4 y 5 · RF4 · RS4

- [ ] RF4, logout: invalidar la sesión, borrar la clave HMAC y cerrar la conexión TLS. Desactivar los session tickets para que no se pueda reanudar el túnel.
- [ ] RS4, registro de auditoría (`logs/audit.log`): apertura y cierre de túnel (IP, CN, versión y suite TLS), handshakes rechazados, logins correctos y fallidos, y accesos denegados.
- [ ] Capturas `.pcap` en Wireshark:
  - HTTP frente a HTTPS (credenciales visibles frente a cifradas).
  - Handshake TLS 1.3 con mTLS.
  - Cierre del túnel en el logout.
- [ ] Adaptar los tests y ataques de la PAI-1 (MitM, Replay) al nuevo canal.
- [ ] Añadir ataques nuevos: certificado de otro usuario, `session_id` robado y certificado revocado.
- [ ] **Extra opcional (+10 %):** MitM real con un proxy y un certificado falso, demostrando que se detecta y se aborta.
- [ ] Memoria: análisis de tráfico y ataques, tabla de grado de completitud (requisito → código → evidencia) y encaje con RGPD, LOPDGDD y ENS.
