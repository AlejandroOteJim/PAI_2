CREATE DATABASE IF NOT EXISTS secbank CHARACTER SET utf8mb4;
USE secbank;

-- Requisito funcional 1: Gestión de Usuarios (Registro e Inicio de Sesión)
CREATE TABLE IF NOT EXISTS users (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    username         VARCHAR(64) UNIQUE NOT NULL,
    password_hash    VARCHAR(255) NOT NULL,       -- RS1.a: salida de PBKDF2
    salt             VARCHAR(255) NOT NULL,       -- RS1.a: salt aleatorio único por usuario
    failed_attempts  INT DEFAULT 0,               -- RS1.b: rate limiting / bloqueo temporal
    locked_until     TIMESTAMP NULL               -- RS1.b
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


-- Usuarios de prueba (contraseña = nombre de usuario)

INSERT IGNORE INTO users (username, password_hash, salt) VALUES
('alice', 'yN4TPL6rDvJqtqOvpj4MbAUWm3SUs47v9yMF+ubFSw4=', '7msolAU+tjCy9r7/Jtm60A=='),
('bob',   's2vwkCRg6tGJgqKjWYKorrFffvqWCnpZEErLfC3BmtE=', 'FqQe8df4akAtH8avrNeGPA==');

INSERT IGNORE INTO user_ibans (username, iban) VALUES
('alice', 'ES9121000418450200051332'),
('bob',   'ES7921000813610123456789');
