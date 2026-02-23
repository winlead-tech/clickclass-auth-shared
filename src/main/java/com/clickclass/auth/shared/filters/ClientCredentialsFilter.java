package com.clickclass.auth.shared.filters;

import com.clickclass.auth.shared.config.SecurityProperties;
import com.clickclass.auth.shared.exception.AuthException;
import com.clickclass.auth.shared.model.AuthClient;
import com.clickclass.auth.shared.repository.ClientCredentialsRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class ClientCredentialsFilter extends OncePerRequestFilter {

    private final ClientCredentialsRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityProperties securityProperties;
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    public ClientCredentialsFilter(ClientCredentialsRepository repository,
                                   PasswordEncoder passwordEncoder,
                                   SecurityProperties securityProperties) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.securityProperties = securityProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        if (!securityProperties.shouldValidate("clientCredentials", path)) {
            log.info("[ClientCredentials] Bypass: {}", path);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String clientId = request.getHeader("x-client-id");
            String clientSecret = request.getHeader("x-client-secret");

            if (clientId == null || clientSecret == null) {
                log.info("[ClientCredentials] Headers ausentes: {}", path);
                throw new AuthException("CLIENT_CREDENTIALS_REQUIRED",
                        "x-client-id e x-client-secret são obrigatórios", 400);
            }

            AuthClient client = repository.findByClientIdAndStatus(clientId, "ACTIVE")
                    .orElseThrow(() -> {
                        log.info("[ClientCredentials] Cliente invalido/inativo: {}", clientId);
                        return new AuthException("INVALID_CLIENT",
                                "Cliente inválido ou inativo", 401);
                    });

            if (!passwordEncoder.matches(clientSecret, client.getClientSecretHash())) {
                log.info("[ClientCredentials] Secret incorreto para: {}", clientId);
                throw new AuthException("INVALID_CLIENT_SECRET",
                        "Client secret inválido", 401);
            }

            log.info("[ClientCredentials] Autenticado: {}", clientId);
            filterChain.doFilter(request, response);

        } catch (AuthException ex) {
            handleException(response, ex);
        } catch (Exception ex) {
            log.error("[ClientCredentials] Erro inesperado: {}", ex.getMessage());
            handleException(response, new AuthException("INTERNAL_ERROR",
                    "Erro interno no servidor", 500));
        }
    }

    private void handleException(HttpServletResponse response, AuthException ex) throws IOException {
        response.setStatus(ex.getStatusCode());
        response.setContentType("application/json");

        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("code", ex.getErrorCode());
        errorBody.put("message", ex.getMessage());
        errorBody.put("timestamp", LocalDateTime.now().toString());

        response.getWriter().write(objectMapper.writeValueAsString(errorBody));
    }
}