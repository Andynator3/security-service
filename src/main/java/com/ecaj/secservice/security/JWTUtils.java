package com.ecaj.secservice.security;

public class JWTUtils {
    public static final String SECRET = "mySecret1230";
    public static final String AUTH_HEADER = "Authorization";
    public static final String PREFIX = "Bearer ";
    public static final long EXPIRED_ACCESS_TOKEN = 120000;
    public static final long EXPIRED_REFRESH_TOKEN = 900000;
}
