package com.example.jwtjsp.security; // 본인의 프로젝트 패키지 경로에 맞게 수정하세요

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 인증 성공 후 리다이렉션 과정을 로깅하기 위한 커스텀 Success Handler 입니다.
 * SimpleUrlAuthenticationSuccessHandler를 상속받아 기본적인 리다이렉션 기능을 사용하면서
 * 추가적인 로그를 기록합니다.
 */
@Slf4j
public class LoggingAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    // SavedRequest를 사용하기 위한 RequestCache (선택 사항: Spring Security가 보호된 리소스 접근 시 저장한 요청이 있는지 확인)
    private RequestCache requestCache = new HttpSessionRequestCache();

    /**
     * 생성자. 리다이렉트할 기본 URL을 설정합니다.
     * @param defaultTargetUrl 인증 성공 시 기본적으로 리다이렉트할 URL
     */
    public LoggingAuthenticationSuccessHandler(String defaultTargetUrl) {
        super(defaultTargetUrl); // 부모 클래스에 기본 타겟 URL 설정
        // setAlwaysUseDefaultTargetUrl(true); // 필요시 이 옵션을 활성화하여 항상 defaultTargetUrl을 사용하도록 강제
        log.info("LoggingAuthenticationSuccessHandler initialized. Default Target URL: {}", defaultTargetUrl);
    }

    /**
     * 인증 성공 시 호출되는 메소드입니다. 리다이렉션 전에 로그를 기록합니다.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        // 로그인한 사용자 정보 로깅
        String username = (authentication != null && authentication.isAuthenticated()) ? authentication.getName() : "N/A";
        log.info(">>> [AuthSuccess] 핸들러 시작. 사용자: {}", username);

        // 응답이 이미 커밋되었는지 확인 (리다이렉트 불가 상태)
        if (response.isCommitted()) {
            log.error(">>> [AuthSuccess] 에러: 리다이렉트 전에 응답이 이미 커밋되었습니다!");
            // 이미 커밋되었으면 여기서 더 진행할 수 없음
            return;
        }

        // Spring Security가 저장한 요청(SavedRequest)이 있는지 확인 (예: 로그인 전에 접근하려던 페이지)
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        String targetUrl;

        if (savedRequest != null) {
            targetUrl = savedRequest.getRedirectUrl();
            log.info(">>> [AuthSuccess] 저장된 요청 발견. 리다이렉트 URL: {}", targetUrl);
            // SavedRequest 사용 후 세션에서 제거
            requestCache.removeRequest(request, response);
        } else {
            // 저장된 요청이 없으면 기본 URL 또는 설정된 로직에 따라 URL 결정
            // determineTargetUrl 메소드는 SimpleUrlAuthenticationSuccessHandler의 로직을 따름
            targetUrl = determineTargetUrl(request, response, authentication);
            log.info(">>> [AuthSuccess] 저장된 요청 없음. 결정된 리다이렉트 URL: {}", targetUrl);
        }


        // 실제 리다이렉션 수행 전 로그
        log.info(">>> [AuthSuccess] 리다이렉트 시도 -> {}", targetUrl);

        // 부모 클래스의 onAuthenticationSuccess를 호출하여 실제 리다이렉션 로직 수행
        // clearAuthenticationAttributes(request); // 기본적으로 super.onAuthenticationSuccess 내에서 호출됨
        getRedirectStrategy().sendRedirect(request, response, targetUrl); // 명시적으로 리다이렉션 호출 (super.onAuthenticationSuccess 대신 사용 가능)

        // super.onAuthenticationSuccess(request, response, authentication); // 이 메소드는 내부적으로 clearAuthenticationAttributes 와 getRedirectStrategy().sendRedirect() 를 호출함. 둘 중 하나 사용.

        log.info(">>> [AuthSuccess] 리다이렉트 실행 완료 (RedirectStrategy 호출 후)");
        // 참고: sendRedirect 이후에는 추가적인 응답 작성이 불가합니다.
    }

    // RequestCache 설정자 (필요한 경우 외부에서 주입 가능)
    public void setRequestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
    }
}