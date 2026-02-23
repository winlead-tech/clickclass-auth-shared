package com.clickclass.auth.shared.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.springframework.util.AntPathMatcher;
import java.util.ArrayList;
import java.util.List;

@Data
public class SecurityProperties {

    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    @JsonProperty("public-paths")
    private List<String> publicPaths = new ArrayList<>();

    @JsonProperty("onboarding")
    private Onboarding onboarding = new Onboarding();

    @JsonProperty("client-credentials")
    private ClientCredentials clientCredentials = new ClientCredentials();

    @JsonProperty("jwt")
    private Jwt jwt = new Jwt();

    @JsonProperty("must-change-password")
    private MustChangePassword mustChangePassword = new MustChangePassword();

    public boolean shouldValidate(String filterName, String uri) {
        if (publicPaths != null && isMatch(publicPaths, uri)) return false;

        return switch (filterName) {
            case "onboarding" -> onboarding.getRequiredPaths() != null && isMatch(onboarding.getRequiredPaths(), uri);
            case "clientCredentials" -> clientCredentials.getAllowedPaths() == null || !isMatch(clientCredentials.getAllowedPaths(), uri);
            case "jwt" -> jwt.getAllowedPaths() == null || !isMatch(jwt.getAllowedPaths(), uri);
            case "mustChangePassword" -> mustChangePassword.getAllowedPaths() == null || !isMatch(mustChangePassword.getAllowedPaths(), uri);
            default -> true;
        };
    }

    private boolean isMatch(List<String> patterns, String uri) {
        if (patterns == null) return false;
        return patterns.stream().anyMatch(pattern -> pathMatcher.match(pattern, uri));
    }

    @Data
    public static class Onboarding {
        @JsonProperty("required-paths")
        private List<String> requiredPaths = new ArrayList<>();
        private String description;
    }

    @Data
    public static class ClientCredentials {
        @JsonProperty("allowed-paths")
        private List<String> allowedPaths = new ArrayList<>();
        private String description;
    }

    @Data
    public static class Jwt {
        @JsonProperty("allowed-paths")
        private List<String> allowedPaths = new ArrayList<>();
        private String description;
    }

    @Data
    public static class MustChangePassword {
        @JsonProperty("allowed-paths")
        private List<String> allowedPaths = new ArrayList<>();
        private String description;
    }
}