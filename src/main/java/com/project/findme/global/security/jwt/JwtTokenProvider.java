package com.project.findme.global.security.jwt;

import com.project.findme.global.security.authentication.AuthDetailService;
import com.project.findme.global.security.jwt.config.JwtKeyProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;

@Log4j2
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final JwtKeyProperties jwtKeyProperties;
    private final AuthDetailService authDetailService;

    private final long ACCESS_TOKEN_EXPIRED_TIME = 2 * 60 * 60 * 1000; // 2시간

    @AllArgsConstructor
    enum TokenType {
        ACCESS_TOKEN("accessToken"),
        REFRESH_TOKEN("refreshToken");

        private final String value;
    }

    private Key getSignInKey(String secretKey) {
        byte[] keyByte = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyByte);
    }

    public Claims extractAllClaims(String token) throws ExpiredJwtException, IllegalStateException, UnsupportedOperationException {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey(jwtKeyProperties.getKey()))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getUserId(String token) {
        return extractAllClaims(token).getSubject();
    }

    public boolean isExpired(String token) {
        try {
            extractAllClaims(token).getExpiration();
            return false;
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    private String doGenerateToken(String id, TokenType tokenType, Long expireTime) {
        Claims claims = Jwts.claims().setSubject(id);
        claims.put("tokenType", tokenType.value);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expireTime))
                .signWith(getSignInKey(jwtKeyProperties.getKey()))
                .compact();
    }

    public LocalDateTime getExpiredTime() {
        return LocalDateTime.now().plusSeconds(ACCESS_TOKEN_EXPIRED_TIME / 1000);
    }

    public String generateAccessToken(String id) {
        return doGenerateToken(id, TokenType.ACCESS_TOKEN, ACCESS_TOKEN_EXPIRED_TIME);
    }

    public String generateRefreshToken(String id) {
        // 1주
        long REFRESH_TOKEN_EXPIRED_TIME = 7 * 24 * 60 * 60 * 1000;
        return doGenerateToken(id, TokenType.REFRESH_TOKEN, REFRESH_TOKEN_EXPIRED_TIME);
    }

    public Authentication authentication(String token) {
        UserDetails userDetails = authDetailService.loadUserByUsername(getUserId(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

}
