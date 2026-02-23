package com.clickclass.auth.shared.filters;

import com.clickclass.auth.shared.service.BlacklistService;
import com.clickclass.auth.shared.util.JwtTokenUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class BlacklistCheckingFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final BlacklistService blacklistService;

    public BlacklistCheckingFilter(JwtTokenUtil jwtTokenUtil, BlacklistService blacklistService) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.blacklistService = blacklistService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = jwtTokenUtil.resolveToken(request);

        if (token != null && jwtTokenUtil.isValid(token)) {
            String jti = jwtTokenUtil.getJti(token);

            if (blacklistService.isTokenBlacklisted(jti)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("""
                    {
                      "error": "TOKEN_REVOKED",
                      "message": "Token revogado. Faça login novamente."
                    }
                """);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}