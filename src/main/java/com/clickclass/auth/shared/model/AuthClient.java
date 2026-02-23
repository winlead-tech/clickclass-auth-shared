package com.clickclass.auth.shared.model;

import java.time.OffsetDateTime;
import java.util.UUID;

public class AuthClient {
    private UUID id;
    private String clientId;
    private String clientSecretHash;
    private String status;
    private OffsetDateTime createdAt;

    // Construtor
    public AuthClient(UUID id, String clientId, String clientSecretHash, String status, OffsetDateTime createdAt) {
        this.id = id;
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.status = status;
        this.createdAt = createdAt;
    }

    // Getters
    public UUID getId() { return id; }
    public String getClientId() { return clientId; }
    public String getClientSecretHash() { return clientSecretHash; }
    public String getStatus() { return status; }
    public OffsetDateTime getCreatedAt() { return createdAt; }
}