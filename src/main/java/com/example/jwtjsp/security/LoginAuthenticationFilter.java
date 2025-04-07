package com.example.jwtjsp.security;

import com.example.jwtjsp.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper = new ObjectMapper(); // For potential JSON request body parsing if needed

    public LoginAuthenticationFilter(JwtUtil jwtUtil) {
        // 로그인 요청을 처리할 URL과 HTTP 메소드를 지정합니다.
        super(new AntPathRequestMatcher("/loginProc", "POST"));
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        log.info("Attempting authentication for /loginProc");

        // JSP 폼에서는 일반적으로 form-data로 전송됩니다.
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        if (username == null) {
            username = "";
        }
        if (password == null) {
            password = "";
        }
        username = username.trim();

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        // AuthenticationManager에게 인증 위임
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    // 인증 성공 시 호출됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authResult) throws IOException, ServletException {
        log.info("Authentication successful for user: {}", authResult.getName());

        // Access Token 생성
        String accessToken = jwtUtil.createAccessToken(authResult);
        // Refresh Token 생성
        String refreshToken = jwtUtil.createRefreshToken(authResult);

        // Access Token을 HttpOnly 쿠키에 저장
        Cookie accessTokenCookie = jwtUtil.createAccessTokenCookie(accessToken);
        response.addCookie(accessTokenCookie);

        // Refresh Token을 HttpOnly 쿠키에 저장 (경로 제한)
        Cookie refreshTokenCookie = jwtUtil.createRefreshTokenCookie(refreshToken);
        response.addCookie(refreshTokenCookie);

        log.info("Access and Refresh tokens created and added to cookies.");

        // 인증 성공 후 메인 페이지로 리다이렉트
        //getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
         // 기본 SuccessHandler는 없으므로 직접 리다이렉트 (또는 SuccessHandler 설정)
         // response.sendRedirect("/main"); // <-- 여기!
         // SecurityConfig에서 .defaultSuccessUrl("/main", true) 를 사용하거나 custom SuccessHandler를 설정하는 것이 더 일반적입니다.
         // 여기서는 간단하게 직접 리다이렉트합니다.
         // 주의: 이미 응답이 커밋되었을 수 있으므로, SuccessHandler 사용 권장.
         // 여기서는 AbstractAuthenticationProcessingFilter의 기본 동작을 활용하기 위해 successHandler를 호출합니다.
         // 명시적 success handler가 없다면 기본 동작(설정된 default target url 등)을 따르거나 아무것도 안 할 수 있음
         // 가장 확실한 방법은 SuccessHandler를 주입받거나 직접 리다이렉션 하는 것
         //response.sendRedirect("/main"); // 인증 성공 후 리다이렉션

    }

    // 인증 실패 시 호출됨
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        log.warn("Authentication failed: {}", failed.getMessage());
        // 실패 시 로그인 페이지로 리다이렉트 (에러 파라미터 추가)
        //getFailureHandler().onAuthenticationFailure(request, response, failed);
         // 기본 FailureHandler가 없다면 직접 처리
         // response.sendRedirect("/login?error"); // <-- 여기!
         // SecurityConfig에서 .failureUrl("/login?error")를 설정하는 것이 더 일반적입니다.
         // 여기서는 직접 리다이렉트합니다.
         //response.sendRedirect("/login?error"); // 인증 실패 시 리다이렉션
        super.unsuccessfulAuthentication(request, response, failed); // This will invoke the configured failure handler.
    }


    // --- Helper methods from UsernamePasswordAuthenticationFilter ---
    protected String obtainPassword(HttpServletRequest request) {
		String password = request.getParameter("password"); // form field name
		return (password != null) ? password : "";
	}

	protected String obtainUsername(HttpServletRequest request) {
		String username = request.getParameter("username"); // form field name
		return (username != null) ? username : "";
	}

    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
	}

    //--- Login DTO (If needed for JSON request body) ---
    @Getter @Setter
    private static class LoginRequest {
        private String username;
        private String password;
    }
}