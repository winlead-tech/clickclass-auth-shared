package com.clickclass.auth.shared.service;

public interface BlacklistService {
    boolean isTokenBlacklisted(String jti);
}