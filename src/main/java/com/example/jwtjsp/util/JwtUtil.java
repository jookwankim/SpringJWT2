package com.example.jwtjsp.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-token.expiration-ms}")
    private long accessTokenExpirationMs;

    @Value("${jwt.refresh-token.expiration-ms}")
    private long refreshTokenExpirationMs;

    @Value("${jwt.access-token.cookie-name}")
    private String accessTokenCookieName;

    @Value("${jwt.refresh-token.cookie-name}")
    private String refreshTokenCookieName;


    private Key key;
    private static final String AUTHORITIES_KEY = "auth";

    @PostConstruct
    public void init() {
        byte[] keyBytes = secretKey.getBytes();
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    
    public String getAccessTokenCookieName() {
		return accessTokenCookieName;
	}


	public void setAccessTokenCookieName(String accessTokenCookieName) {
		this.accessTokenCookieName = accessTokenCookieName;
	}


	public String getRefreshTokenCookieName() {
		return refreshTokenCookieName;
	}


	public void setRefreshTokenCookieName(String refreshTokenCookieName) {
		this.refreshTokenCookieName = refreshTokenCookieName;
	}


	// Access Token 생성
    public String createAccessToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenExpirationMs);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // Refresh Token 생성
    public String createRefreshToken(Authentication authentication) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshTokenExpirationMs);

        return Jwts.builder()
                .setSubject(authentication.getName()) // Refresh token might not need authorities
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // Cookie에서 Access Token 가져오기
    public String getAccessTokenFromCookie(HttpServletRequest request) {
        return getTokenFromCookie(request, accessTokenCookieName);
    }

    // Cookie에서 Refresh Token 가져오기
    public String getRefreshTokenFromCookie(HttpServletRequest request) {
         return getTokenFromCookie(request, refreshTokenCookieName);
    }

    private String getTokenFromCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }


    // Token 유효성 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    // Token에서 Authentication 객체 얻기
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

     // Token에서 사용자 이름 얻기
    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }


    // HttpOnly 쿠키 생성 유틸리티
    public Cookie createCookie(String name, String value, long maxAgeSeconds, String path) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        // cookie.setSecure(true); // HTTPS 환경에서만 true로 설정
        cookie.setMaxAge((int) maxAgeSeconds);
        cookie.setPath(path); // 쿠키를 사용할 경로 설정
        return cookie;
    }

     // Access Token용 쿠키 생성
    public Cookie createAccessTokenCookie(String token) {
        long maxAgeSeconds = accessTokenExpirationMs / 1000;
        return createCookie(accessTokenCookieName, token, maxAgeSeconds, "/"); // 전체 경로에서 사용
    }

    // Refresh Token용 쿠키 생성
    public Cookie createRefreshTokenCookie(String token) {
         long maxAgeSeconds = refreshTokenExpirationMs / 1000;
        // Refresh Token은 갱신 API 경로에서만 사용되도록 제한
        return createCookie(refreshTokenCookieName, token, maxAgeSeconds, "/api/token/refresh");
    }

    // 쿠키 삭제 유틸리티
    public Cookie createLogoutCookie(String name, String path) {
         Cookie cookie = new Cookie(name, null); // 값을 null로 설정
         cookie.setMaxAge(0); // 유효기간 0
         cookie.setHttpOnly(true);
         // cookie.setSecure(true); // HTTPS
         cookie.setPath(path);
         return cookie;
    }
}