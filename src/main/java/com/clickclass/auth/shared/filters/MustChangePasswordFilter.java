package com.clickclass.auth.shared.filters;

import com.clickclass.auth.shared.config.SecurityProperties;
import com.clickclass.auth.shared.util.JwtTokenUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class MustChangePasswordFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final SecurityProperties securityProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getServletPath();

        boolean mustValidate = securityProperties.shouldValidate("mustChangePassword", path);

        if (!mustValidate) {
            log.info("[MustChangePassword] Bypass para path: {}", path);
            filterChain.doFilter(request, response);
            return;
        }

        String token = jwtTokenUtil.resolveToken(request);

        if (token == null || !jwtTokenUtil.isValid(token)) {
            log.info("[MustChangePassword] Token inválido ou ausente para path: {}", path);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("""
                {
                  "error": "UNAUTHORIZED",
                  "message": "Token ausente ou inválido."
                }
            """);
            return;
        }

        if (jwtTokenUtil.isMustChangePassword(token)) {
            log.info("[MustChangePassword] Usuário precisa trocar a senha para acessar: {}", path);

            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("""
                {
                  "error": "PASSWORD_CHANGE_REQUIRED",
                  "message": "É necessário alterar a senha para continuar."
                }
            """);
            return;
        }

        filterChain.doFilter(request, response);
    }
}