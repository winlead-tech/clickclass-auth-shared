package com.clickclass.auth.shared.model;

import java.util.UUID;

public class JwtUserContext {

    private final UUID userId;
    private final UUID escolaId;

    private final String token;

    public JwtUserContext(UUID userId, UUID escolaId, String token) {
        this.userId = userId;
        this.escolaId = escolaId;
        this.token = token;
    }

    public UUID getUserId() {
        return userId;
    }

    public UUID getEscolaId() {
        return escolaId;
    }

    public String getToken() {
        return token;
    }
}