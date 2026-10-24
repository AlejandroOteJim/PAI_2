CREATE DATABASE IF NOT EXISTS usecure CHARACTER SET utf8mb4;
USE usecure;

-- Requisito funcional 1: Gestión de Usuarios (Registro e Inicio de Sesión)
CREATE TABLE IF NOT EXISTS users (
                                     id               INT AUTO_INCREMENT PRIMARY KEY,
                                     username         VARCHAR(64) UNIQUE NOT NULL,
    password_hash    VARCHAR(255) NOT NULL,       -- RS1.a: salida de PBKDF2
    salt             VARCHAR(255) NOT NULL,       -- RS1.a: salt aleatorio único por usuario
    failed_attempts  INT DEFAULT 0,               -- RS1.b: rate limiting / bloqueo temporal
    locked_until     TIMESTAMP NULL,              -- RS1.b
    role             VARCHAR(8) NOT NULL DEFAULT 'PDI'   -- PAI-2 RF5: PDI, PAS o INV (coincide con la OU del certificado)
    );

-- Requisito funcional 1.d: sesiones activas y cierre de sesión
CREATE TABLE IF NOT EXISTS sessions (
                                        session_id   VARCHAR(64) PRIMARY KEY,
    user_id      INT NOT NULL,
    hmac_key     VARCHAR(255) NOT NULL,           -- RS2.a: clave secreta derivada de la sesión
    active       BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id)
    );

-- Requisito funcional 2: campos del JSON de transacción
CREATE TABLE IF NOT EXISTS transactions (
                                            tx_id                VARCHAR(36) PRIMARY KEY,
    origin_account       VARCHAR(34) NOT NULL,
    destination_account  VARCHAR(34) NOT NULL,
    amount               DECIMAL(15,2) NOT NULL,
    currency             VARCHAR(3) NOT NULL,
    timestamp            BIGINT NOT NULL
    );

-- RS3: registro de nonces procesados
CREATE TABLE IF NOT EXISTS nonces (
                                      nonce        VARCHAR(64) PRIMARY KEY,
    timestamp    BIGINT NOT NULL
    );

CREATE TABLE IF NOT EXISTS user_ibans (
                                          username VARCHAR(50) NOT NULL,
    iban VARCHAR(34) NOT NULL,
    PRIMARY KEY (username, iban)
    );


-- PAI-2 persona B (RF1): emparejamiento usuario <-> certificado del dispositivo (serie y huella SHA-256 del DER)
CREATE TABLE IF NOT EXISTS device_certificates (
    serial              VARCHAR(64) PRIMARY KEY,
    user_id             INT NOT NULL,
    cn                  VARCHAR(64) NOT NULL,
    role                VARCHAR(8) NOT NULL,
    fingerprint_sha256  CHAR(64) NOT NULL UNIQUE,
    issued_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
    );

-- PAI-2 persona B (RF1): certificados revocados. Una revocación no se puede deshacer
CREATE TABLE IF NOT EXISTS revoked_certificates (
    serial      VARCHAR(64) PRIMARY KEY,
    revoked_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason      VARCHAR(255) NOT NULL
    );

-- PAI-2 persona B (RF2): cada sesión queda ligada al certificado con el que se hizo el login
CREATE TABLE IF NOT EXISTS session_bindings (
    session_id        VARCHAR(64) PRIMARY KEY,
    cert_serial       VARCHAR(64) NOT NULL,
    cert_fingerprint  CHAR(64) NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    );

-- PAI-2 persona B (RF1, inmutabilidad): los emparejamientos y las revocaciones no se modifican ni se borran.
-- (Triggers de una sola sentencia, sin ';' internos, para que DataBaseInitializer pueda trocear el script)
DROP TRIGGER IF EXISTS device_certificates_no_update;
CREATE TRIGGER device_certificates_no_update BEFORE UPDATE ON device_certificates FOR EACH ROW
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'RF1: el emparejamiento es inmutable, revoca el certificado y re-emite uno nuevo';
DROP TRIGGER IF EXISTS device_certificates_no_delete;
CREATE TRIGGER device_certificates_no_delete BEFORE DELETE ON device_certificates FOR EACH ROW
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'RF1: el emparejamiento es inmutable, revoca el certificado y re-emite uno nuevo';
DROP TRIGGER IF EXISTS revoked_certificates_no_update;
CREATE TRIGGER revoked_certificates_no_update BEFORE UPDATE ON revoked_certificates FOR EACH ROW
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'RF1: una revocacion no se puede modificar';
DROP TRIGGER IF EXISTS revoked_certificates_no_delete;
CREATE TRIGGER revoked_certificates_no_delete BEFORE DELETE ON revoked_certificates FOR EACH ROW
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'RF1: una revocacion no se puede deshacer';

-- Usuarios de prueba (contraseña = nombre de usuario)

INSERT IGNORE INTO users (username, password_hash, salt) VALUES
('alice', 'yN4TPL6rDvJqtqOvpj4MbAUWm3SUs47v9yMF+ubFSw4=', '7msolAU+tjCy9r7/Jtm60A=='),
('bob',   's2vwkCRg6tGJgqKjWYKorrFffvqWCnpZEErLfC3BmtE=', 'FqQe8df4akAtH8avrNeGPA==');

-- PAI-2 RF5: cuentas corporativas precargadas por rol (contraseña = nombre de usuario)
-- Sus certificados los emite CertificateAuthority con CN = usuario y OU = rol
INSERT IGNORE INTO users (username, password_hash, salt, role) VALUES
('pdi01', 'nQS8ocUgDkQIQB4xeTw12WhU3CvQd6imX9Y/GXeL6YA=', 'CEYvFPapnum0qPyPtFG6Ww==', 'PDI'),
('pas01', '3vgva0+5J/vU317f04PogSPhZD07N6AtbrM+JY3YA24=', 'I+ma/BF+YxhKolp+w/z8BQ==', 'PAS'),
('inv01', '4IzzvL554Q+odHkdw45GuIuA3yYh1uBDuljH0dUMoQc=', 'uoyCcoBL4isnJHRvLlq+xA==', 'INV');

-- PAI-2 RF5: bob es PAS (igual que la OU de su certificado). alice se queda en PDI por defecto
UPDATE users SET role = 'PAS' WHERE username = 'bob';

INSERT IGNORE INTO user_ibans (username, iban) VALUES
('alice', 'ES9121000418450200051332'),
('bob',   'ES7921000813610123456789'),
('pdi01', 'ES1121000418450200051001'),
('pas01', 'ES2221000418450200051002'),
('inv01', 'ES3321000418450200051003');

-- PAI-2 persona B (RF1, inmutabilidad): el nombre y el rol de un usuario no cambian aunque se haga un UPDATE sobre users.
-- Va al final para que el UPDATE de bob de arriba se aplique la primera vez que se crea la BD.
DROP TRIGGER IF EXISTS users_identity_immutable;
CREATE TRIGGER users_identity_immutable BEFORE UPDATE ON users FOR EACH ROW
    SET NEW.username = OLD.username, NEW.role = OLD.role;
