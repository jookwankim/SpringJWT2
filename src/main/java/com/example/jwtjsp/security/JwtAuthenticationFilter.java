package com.example.jwtjsp.security;

import com.example.jwtjsp.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Cookie에서 Access Token 가져오기
        String accessToken = jwtUtil.getAccessTokenFromCookie(request);

        // 2. Access Token 유효성 검증
        if (StringUtils.hasText(accessToken) && jwtUtil.validateToken(accessToken)) {
            // 토큰이 유효하면 인증 정보 설정
            Authentication authentication = jwtUtil.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("Authenticated user: {}, setting security context", authentication.getName());
        } else {
             log.debug("No valid JWT access token found in cookie for URI: {}", request.getRequestURI());
             // 만료되었거나 유효하지 않은 토큰이면 컨텍스트를 클리어할 필요는 없음 (기본적으로 null)
             // SecurityContextHolder.clearContext(); // 명시적으로 클리어해도 무방
        }

        // 다음 필터로 진행
        filterChain.doFilter(request, response);
    }
}