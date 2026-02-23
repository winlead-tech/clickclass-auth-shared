package com.clickclass.auth.shared.repository;

import com.clickclass.auth.shared.model.AuthClient;
import java.util.Optional;

public interface ClientCredentialsRepository {
    Optional<AuthClient> findByClientIdAndStatus(String clientId, String status);
}