package com.example.jwtjsp.config;

import java.util.List;

// 필요한 import 문들
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.jwtjsp.security.CustomUserDetails;
import com.example.jwtjsp.security.JwtAuthenticationFilter;
import com.example.jwtjsp.security.LoggingAuthenticationSuccessHandler; // 로깅 핸들러 import
import com.example.jwtjsp.security.LoginAuthenticationFilter;
import com.example.jwtjsp.util.JwtUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // 필수 컴포넌트 주입
    private final JwtUtil jwtUtil;
    private final AuthenticationConfiguration authenticationConfiguration;
    // CustomAuthenticationEntryPoint가 @Component로 등록되어 있다고 가정하고 주입
    private final AuthenticationEntryPoint customAuthenticationEntryPoint;

    // ApplicationContext 주입 (핸들러 직접 조회를 위해)
    @Autowired
    private ApplicationContext context;

    // --- 기본 빈 설정 ---

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = new CustomUserDetails(
                "user",
                passwordEncoder().encode("password"),
                "user@example.com",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        UserDetails admin = new CustomUserDetails(
                "admin",
                passwordEncoder().encode("admin"),
                "admin@example.com",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER"))
        );

        // 만약 데이터베이스를 사용한다면, DB에서 사용자 정보를 조회할 때 email 정보도 함께 가져와서
        // CustomUserDetails 객체를 생성하여 반환하도록 구현해야 합니다.
        
        // 확인용 로그 추가 (선택 사항이지만 추천)
        log.info(">>> Creating UserDetailsService Bean. User object type: {}, Admin object type: {}",
                 user.getClass().getName(), admin.getClass().getName());

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // --- 핸들러 빈 설정 ---

    @Bean
    public AuthenticationSuccessHandler customAuthenticationSuccessHandler() {
        // LoggingAuthenticationSuccessHandler 사용, 기본 리다이렉트 URL은 "/main"
        return new LoggingAuthenticationSuccessHandler("/main");
    }

    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler() {
         SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
         // 실패 시 /login?error 로 리다이렉트
         failureHandler.setDefaultFailureUrl("/login?error");
         return failureHandler;
    }

    // --- 커스텀 필터 빈 설정 ---

    // !!! 진단용 수정: 핸들러를 ApplicationContext에서 직접 조회하여 설정 !!!
    @Bean
    public LoginAuthenticationFilter loginAuthenticationFilter() throws Exception {
        LoginAuthenticationFilter filter = new LoginAuthenticationFilter(jwtUtil);
        filter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        filter.setFilterProcessesUrl("/loginProc");

        // Context에서 직접 핸들러 빈 가져오기 (빈 이름이 customAuthenticationSuccessHandler, customAuthenticationFailureHandler 라고 가정)
        AuthenticationSuccessHandler successHandler = context.getBean("customAuthenticationSuccessHandler", AuthenticationSuccessHandler.class);
        AuthenticationFailureHandler failureHandler = context.getBean("customAuthenticationFailureHandler", AuthenticationFailureHandler.class);

        log.info(">>> [DEBUG] Explicitly fetching and setting handlers on LoginAuthenticationFilter bean."); // 확인용 로그 추가
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);

        return filter;
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtUtil);
    }


    // --- 메인 SecurityFilterChain 설정 ---
    // !!! 진단용 수정: loginFilter 파라미터 제거하고 빈 메소드 직접 호출 !!!
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CSRF 비활성화 (Stateless)
            .csrf(csrf -> csrf.disable())
            // 세션 관리: STATELESS 설정
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // 요청별 접근 권한 설정
            .authorizeHttpRequests(authz -> authz
                .antMatchers("/login", "/loginProc", "/css/**", "/js/**", "/favicon.ico").permitAll() // 공개 경로
                .antMatchers("/api/token/refresh").permitAll() // 토큰 갱신 경로
                .antMatchers("/hello").hasRole("USER") // USER 권한 필요 경로
                .antMatchers("/admin").hasRole("ADMIN") // ADMIN 권한 필요 경로 (예시)
                .anyRequest().authenticated() // 나머지 모든 요청은 인증 필요
            )
            // 기본 FormLogin, HttpBasic 비활성화
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            // 로그아웃 설정
            .logout(logout -> logout
                .logoutUrl("/logout")
                .addLogoutHandler((request, response, authentication) -> { // 쿠키 삭제 핸들러
                    // logout 핸들러 내부의 get~CookieName() 메소드 호출은 JwtUtil 클래스 확인 필요
                    response.addCookie(jwtUtil.createLogoutCookie(jwtUtil.getAccessTokenCookieName(), "/"));
                    response.addCookie(jwtUtil.createLogoutCookie(jwtUtil.getRefreshTokenCookieName(), "/api/token/refresh"));
                })
                .logoutSuccessUrl("/login?logout") // 로그아웃 성공 시 이동할 URL
                .permitAll()
            )
            // 예외 처리 설정: 인증되지 않은 사용자 접근 시 처리
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(customAuthenticationEntryPoint) // 주입받은 Custom EntryPoint 사용
            );

        // !!! 중요: 필터 추가 방식 변경 !!!
        // 기존: http.addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class);
        // 변경: loginAuthenticationFilter() 빈 메소드를 직접 호출하여 필터 인스턴스를 가져와 설정
        http.addFilterAt(loginAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        // JwtAuthenticationFilter는 기존 방식 유지 (또는 동일하게 변경해도 무방)
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}