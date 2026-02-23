package com.clickclass.auth.shared.service.impl;

import com.clickclass.auth.shared.service.BlacklistService;
import org.springframework.data.redis.core.RedisTemplate;

public class RedisBlacklistService implements BlacklistService {

    private final RedisTemplate<String, Object> redisTemplate;
    private static final String KEY_PREFIX = "auth:blacklist:access:jti:";

    public RedisBlacklistService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    private String keyForJti(String jti) {
        return KEY_PREFIX + jti;
    }

    @Override
    public boolean isTokenBlacklisted(String jti) {
        if (jti == null) return false;
        return Boolean.TRUE.equals(redisTemplate.hasKey(keyForJti(jti)));
    }
}