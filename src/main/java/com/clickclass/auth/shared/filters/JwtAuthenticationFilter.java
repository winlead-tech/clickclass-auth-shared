package com.clickclass.auth.shared.filters;

import com.clickclass.auth.shared.config.SecurityProperties;
import com.clickclass.auth.shared.model.JwtUserContext;
import com.clickclass.auth.shared.util.JwtTokenUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.UUID;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtTokenUtil jwtTokenUtil;
    private final SecurityProperties securityProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        if (!securityProperties.shouldValidate("jwt", path)) {
            log.info("[JWT] Bypass para path: {}", path);
            filterChain.doFilter(request, response);
            return;
        }

        String token = jwtTokenUtil.resolveToken(request);

        if (token == null || !jwtTokenUtil.isValid(token)) {
            log.warn("[JWT] Token ausente ou inválido: {}", path);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
            return;
        }

        try {
            UUID userId = jwtTokenUtil.getUserIdFromToken(token);
            UUID escolaId = jwtTokenUtil.getEscolaIdFromToken(token);

            JwtUserContext principal = new JwtUserContext(userId, escolaId);
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(principal, null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(auth);

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error processing token");
        }
    }
}