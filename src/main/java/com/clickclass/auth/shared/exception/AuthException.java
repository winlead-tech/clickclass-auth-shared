package com.clickclass.auth.shared.exception;

public class AuthException extends RuntimeException {
    private final int statusCode;
    private final String errorCode;

    public AuthException(String errorCode, String message, int statusCode) {
        super(message);
        this.errorCode = errorCode;
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}