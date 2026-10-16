package org.example.model;

import java.time.LocalDateTime;

public class User {
    private Integer id;
    private String username;
    private String password_hash;
    private String salt;
    private Integer failed_attempts;
    private LocalDateTime locked_until;

    // Constructor
    public User(String username, String password_hash, String salt) {
        this.username = username;
        this.password_hash = password_hash;
        this.salt = salt;
        this.failed_attempts = 0; // Por defecto a 0 al crear
    }

    // --- GETTERS Y SETTERS ---

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword_hash() {
        return password_hash;
    }

    public void setPassword_hash(String password_hash) {
        this.password_hash = password_hash;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public Integer getFailed_attempts() {
        return failed_attempts;
    }

    public void setFailed_attempts(Integer failed_attempts) {
        this.failed_attempts = failed_attempts;
    }

    public LocalDateTime getLocked_until() {
        return locked_until;
    }

    public void setLocked_until(LocalDateTime locked_until) {
        this.locked_until = locked_until;
    }


}





