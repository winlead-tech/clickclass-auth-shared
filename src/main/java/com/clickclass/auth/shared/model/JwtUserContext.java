package com.clickclass.auth.shared.model;

import java.util.UUID;

public class JwtUserContext {

    private final UUID userId;
    private final UUID escolaId;

    public JwtUserContext(UUID userId, UUID escolaId) {
        this.userId = userId;
        this.escolaId = escolaId;
    }

    public UUID getUserId() {
        return userId;
    }

    public UUID getEscolaId() {
        return escolaId;
    }
}