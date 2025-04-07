package com.example.jwtjsp.security; // 본인의 프로젝트 패키지 경로에 맞게 수정하세요

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component; // @Component로 빈 등록 또는 SecurityConfig에서 @Bean으로 등록

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 인증되지 않은 사용자가 보호된 리소스에 접근 시 호출되는 핸들러입니다.
 * /login 페이지로 리다이렉트 시킵니다.
 */
@Slf4j
@Component // Spring이 이 클래스를 빈으로 관리하도록 설정 (또는 SecurityConfig에서 @Bean으로 직접 정의)
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        log.warn(">>> [EntryPoint] 인증되지 않은 접근 감지 - URI: {}. 로그인 페이지로 리다이렉트합니다.", request.getRequestURI());

        // 디버깅을 위해 어떤 예외 때문에 호출되었는지 로그를 남길 수 있습니다.
        // log.debug(">>> [EntryPoint] 발생한 예외: ", authException);

        // /login 페이지로 리다이렉트
        // request.getContextPath()를 사용하여 컨텍스트 경로가 있을 경우에도 올바르게 동작하도록 합니다.
        response.sendRedirect(request.getContextPath() + "/login");
    }
}