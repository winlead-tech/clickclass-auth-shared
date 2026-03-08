package com.clickclass.auth.shared.context;

import com.clickclass.auth.shared.model.JwtUserContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public final class SecurityContextUtils {

    private SecurityContextUtils() {}

    public static JwtUserContext getCurrentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !(auth.getPrincipal() instanceof JwtUserContext ctx)) {
            throw new IllegalStateException("No authenticated user found");
        }

        return ctx;
    }

    public static String getCurrentToken() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            throw new IllegalStateException("No authenticated user found");
        }

        if (auth.getPrincipal() instanceof JwtUserContext ctx) {
            if (ctx.getToken() == null) {
                throw new IllegalStateException("JWT token não encontrado no JwtUserContext");
            }
            return ctx.getToken();
        }

        throw new IllegalStateException("JWT token não encontrado no SecurityContext");
    }
}