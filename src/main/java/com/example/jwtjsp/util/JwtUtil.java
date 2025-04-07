package com.example.jwtjsp.util;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.example.jwtjsp.security.CustomUserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;

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
        
        // --- Principal에서 Email 정보 추출 ---
        String email = null;
        Object principal = authentication.getPrincipal(); // Principal 객체 가져오기
        
        // Principal 객체가 CustomUserDetails 타입인지 확인
        if (principal instanceof CustomUserDetails) {
            // CustomUserDetails로 안전하게 형변환 후 email 정보 가져오기
            email = ((CustomUserDetails) principal).getEmail();
        } else if (principal instanceof UserDetails) {
            // 만약 CustomUserDetails가 아닌 표준 UserDetails 타입이라면 경고 로그 출력
            // (이 경우 email 정보를 가져올 수 없음)
            log.warn("Principal is UserDetails but not CustomUserDetails, cannot extract email for JWT. Username: {}", ((UserDetails) principal).getUsername());
        } else {
            // UserDetails 타입도 아닌 경우 (예: 인증 전에는 문자열일 수 있음)
            log.warn("Principal is not an instance of UserDetails. Type: {}", principal.getClass().getName());
        }
        // --- Email 정보 추출 완료 ---

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenExpirationMs);

     // JWT 빌더 생성
        JwtBuilder builder = Jwts.builder()
                .setSubject(authentication.getName()) // Username (sub 클레임)
                .claim(AUTHORITIES_KEY, authorities); // Roles (auth 클레임)

        // --- email 클레임 추가 ---
        // email 정보가 정상적으로 추출되었을 경우에만 클레임 추가
        if (email != null && !email.isEmpty()) {
            builder.claim("email", email); // "email" 이라는 이름으로 클레임 추가
            log.debug("Adding email claim to JWT for user: {}", authentication.getName());
        }
        // --- email 클레임 추가 완료 ---

        // 토큰 생성 및 반환
        return builder
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
    
    /**
     * Access Token 문자열에서 'email' 클레임을 추출합니다.
     * @param token Access Token 문자열
     * @return 추출된 email 문자열, 없거나 오류 발생 시 null 반환
     */
    public String getEmailFromToken(String token) {
        if (token == null || token.isEmpty()) {
            log.warn("getEmailFromToken called with null or empty token.");
            return null;
        }
        try {
            // 토큰 파싱하여 클레임(본문) 얻기
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key) // 서명 검증용 키 설정
                    .build()
                    .parseClaimsJws(token) // 토큰 파싱 및 검증
                    .getBody();

            // "email" 이름의 클레임 값을 String 타입으로 반환
            // 해당 클레임이 없으면 null 반환
            return claims.get("email", String.class);

        } catch (ExpiredJwtException e) {
            // 토큰이 만료되었더라도 클레임 정보는 읽어올 수 있습니다.
            log.warn("Attempting to get email from expired token: {}", e.getMessage());
            try {
                 // 만료된 토큰의 클레임에서 email 정보 추출 시도
                return e.getClaims().get("email", String.class);
            } catch (Exception claimException) {
                 log.error("Could not get email claim from expired token's claims", claimException);
                 return null;
            }
        } catch (JwtException | IllegalArgumentException e) {
            // 기타 JWT 관련 예외 또는 잘못된 인자 예외 처리
            log.error("Error parsing JWT to get email: {}", e.getMessage());
            return null;
        } catch (Exception e) {
             // 예상치 못한 다른 예외 처리
             log.error("Unexpected error while getting email from token", e);
             return null;
        }
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