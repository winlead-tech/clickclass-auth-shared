package com.clickclass.auth.shared.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class JwtTokenUtil {

    private final SecretKey key;
    private final long accessTokenExpirationSeconds;

    /**
     * Construtor que recebe as configurações necessárias
     * @param jwtSecret Base64 secret para assinar/verificar JWT
     * @param accessTokenExpirationSeconds tempo de expiração em segundos (opcional)
     */
    public JwtTokenUtil(String jwtSecret, Long accessTokenExpirationSeconds) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
        this.accessTokenExpirationSeconds = accessTokenExpirationSeconds != null ? accessTokenExpirationSeconds : 3600;
    }

    /**
     * Construtor simplificado com valor padrão para expiração
     */
    public JwtTokenUtil(String jwtSecret) {
        this(jwtSecret, 3600L);
    }

    public boolean isMustChangePassword(String token) {
        return Boolean.TRUE.equals(getClaimsFromToken(token).get("mustChangePassword", Boolean.class));
    }

    public String getJti(String token) {
        return getClaimsFromToken(token).get("jti", String.class);
    }

    public UUID getUserIdFromToken(String token) {
        return UUID.fromString(getClaimsFromToken(token).getSubject());
    }

    public List<String> getRolesFromToken(String token) {
        return getClaimsFromToken(token).get("roles", List.class);
    }

    public long getRemainingSeconds(String token) {
        Date expiration = getClaimsFromToken(token).getExpiration();
        long remainingMillis = expiration.getTime() - System.currentTimeMillis();
        return Math.max(0, TimeUnit.MILLISECONDS.toSeconds(remainingMillis));
    }

    public Date getIssuedAt(String token) {
        return getClaimsFromToken(token).getIssuedAt();
    }

    private Claims getClaimsFromToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        } catch (JwtException e) {
            throw new RuntimeException("Token JWT inválido", e);
        }
    }

    public UUID getEscolaIdFromToken(String token) {
        String escolaId = getClaimsFromToken(token).get("escolaId", String.class);
        return escolaId != null ? UUID.fromString(escolaId) : null;
    }

    public String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }

    public boolean isValid(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }
}