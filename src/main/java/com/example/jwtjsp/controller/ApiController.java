package com.example.jwtjsp.controller;

import com.example.jwtjsp.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@RestController
@RequiredArgsConstructor
public class ApiController {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService; // For recreating Authentication

    @GetMapping("/hello")
    public String hello(Authentication authentication) {
        // JwtAuthenticationFilter가 성공적으로 인증 컨텍스트를 설정하면
        // Authentication 객체를 주입받아 사용자 정보를 활용할 수 있습니다.
        String username = (authentication != null) ? authentication.getName() : "Unknown";
        return "Hello, " + username + "! You have accessed a protected resource.";
    }

    @PostMapping("/api/token/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        // 1. Cookie에서 Refresh Token 가져오기
        String refreshToken = jwtUtil.getRefreshTokenFromCookie(request);
        log.debug("Received refresh token request.");

        if (refreshToken != null && jwtUtil.validateToken(refreshToken)) {
            try {
                // 2. Refresh Token이 유효하면, 사용자 정보로 새로운 Access Token 발급
                String username = jwtUtil.getUsernameFromToken(refreshToken);
                // 중요: 실제 사용자 정보를 기반으로 Authentication 객체를 다시 만들어야 함
                // UserDetailsService를 사용하여 UserDetails 로드
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                // Authentication 객체 생성 (비밀번호 없이)
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                String newAccessToken = jwtUtil.createAccessToken(authentication);

                // 3. 새로운 Access Token 쿠키 설정
                Cookie newAccessTokenCookie = jwtUtil.createAccessTokenCookie(newAccessToken);
                response.addCookie(newAccessTokenCookie);

                // (선택적) Refresh Token Rotation: 새로운 Refresh Token 발급 및 쿠키 설정
                // String newRefreshToken = jwtUtil.createRefreshToken(authentication);
                // Cookie newRefreshTokenCookie = jwtUtil.createRefreshTokenCookie(newRefreshToken);
                // response.addCookie(newRefreshTokenCookie);

                log.info("Access token refreshed successfully for user: {}", username);
                // 성공 시 클라이언트에 특별한 데이터 없이 200 OK만 보내도 됨
                // (새 토큰은 쿠키로 전달됨)
                return ResponseEntity.ok().build();

            } catch (Exception e) {
                log.error("Error refreshing token: {}", e.getMessage(), e);
                 // Refresh 토큰은 유효했으나 사용자 정보 로드 등에 실패한 경우
                 return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error processing refresh token");
            }
        } else {
            log.warn("Invalid or missing refresh token cookie.");
            // 4. Refresh Token이 유효하지 않으면 401 Unauthorized 응답
            // 클라이언트(JS)는 이 응답을 받고 로그인 페이지로 리다이렉트해야 함
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired refresh token");
        }
    }
}