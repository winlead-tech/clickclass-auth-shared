package com.clickclass.auth.shared.exception;

public class TokenBlacklistedException extends RuntimeException {

    private final String jti;
    private final String tokenId;

    public TokenBlacklistedException(String jti) {
        super("Token com JTI " + jti + " está na blacklist");
        this.jti = jti;
        this.tokenId = jti;
    }

    public String getJti() {
        return jti;
    }

    public String getTokenId() {
        return tokenId;
    }
}