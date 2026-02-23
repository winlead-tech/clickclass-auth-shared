package com.clickclass.auth.shared.filters;

import com.clickclass.auth.shared.config.SecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.logging.Logger;

public class OnboardingApiKeyFilter extends OncePerRequestFilter {

    private static final Logger logger = Logger.getLogger(OnboardingApiKeyFilter.class.getName());
    private final SecurityProperties securityProperties;
    private final String onboardingApiKey;

    public OnboardingApiKeyFilter(SecurityProperties securityProperties, String onboardingApiKey) {
        this.securityProperties = securityProperties;
        this.onboardingApiKey = onboardingApiKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String uri = request.getRequestURI();

        if (!securityProperties.shouldValidate("onboarding", uri)) {
            logger.info("[OnboardingApiKey] Bypass " + uri);
            filterChain.doFilter(request, response);
            return;
        }

        String apiKey = request.getHeader("x-api-key");
        if (apiKey == null || !apiKey.equals(onboardingApiKey)) {
            logger.info("[OnboardingApiKey] Acesso NÃO autorizado para URI " + uri);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("API key invalida");
            return;
        }

        logger.info("[OnboardingApiKey] Acesso AUTORIZADO para " + uri);
        filterChain.doFilter(request, response);
    }
}