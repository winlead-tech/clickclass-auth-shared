package com.clickclass.auth.shared.context;

import com.clickclass.auth.shared.model.JwtUserContext;
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
}