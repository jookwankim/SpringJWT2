package com.example.jwtjsp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
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

import com.example.jwtjsp.security.JwtAuthenticationFilter;
import com.example.jwtjsp.security.LoggingAuthenticationSuccessHandler;
import com.example.jwtjsp.security.LoginAuthenticationFilter;
import com.example.jwtjsp.util.JwtUtil;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final AuthenticationConfiguration authenticationConfiguration;
    
 // AuthenticationEntryPoint 주입 (위 클래스에 @Component를 사용했거나 아래 @Bean으로 정의)
    private final AuthenticationEntryPoint customAuthenticationEntryPoint;

    // 간단한 인메모리 사용자 설정 (실제로는 DB 연동)
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN", "USER")
                .build();
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
    
 // Define Success Handler Bean
    @Bean
    public AuthenticationSuccessHandler customAuthenticationSuccessHandler() {
        // LoggingAuthenticationSuccessHandler를 사용하고 기본 리다이렉트 URL을 "/main"으로 설정
        return new LoggingAuthenticationSuccessHandler("/main");
    }

    // Define Failure Handler Bean
    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler() {
         SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
         failureHandler.setDefaultFailureUrl("/login?error"); // Redirect target on failure
         return failureHandler;
    }

    // 로그인 처리를 위한 커스텀 필터 빈 등록
     @Bean
    public LoginAuthenticationFilter loginAuthenticationFilter() throws Exception {
        LoginAuthenticationFilter filter = new LoginAuthenticationFilter(jwtUtil);
        filter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        filter.setFilterProcessesUrl("/loginProc"); // 로그인 처리 URL 설정
        
     // Set the handlers
        filter.setAuthenticationSuccessHandler(customAuthenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(customAuthenticationFailureHandler());

        return filter;
    }

    // JWT 인증 필터 빈 등록
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtUtil);
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // CSRF 비활성화 (Stateless 이므로)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 사용 안함
                .authorizeHttpRequests(authz -> authz
                        .antMatchers("/login", "/loginProc", "/css/**", "/js/**", "/favicon.ico").permitAll() // 로그인 및 정적 리소스 허용
                        .antMatchers("/api/token/refresh").permitAll() // 토큰 갱신 엔드포인트는 접근 허용 (필터에서 처리) - 주의: Refresh Token 자체로 인증
                        .antMatchers("/hello").hasRole("USER") // /hello는 USER 롤 필요
                        .antMatchers("/admin").hasRole("ADMIN") // /admin은 ADMIN 롤 필요 (예시)
                        .anyRequest().authenticated() // 나머지 요청은 인증 필요
                )
                // 기본 FormLogin, HttpBasic 비활성화
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                // 로그아웃 처리
                .logout(logout -> logout
                        .logoutUrl("/logout") // 로그아웃 처리 URL
                        .addLogoutHandler((request, response, authentication) -> {
                            // 로그아웃 시 쿠키 삭제 핸들러
                             response.addCookie(jwtUtil.createLogoutCookie(jwtUtil.getAccessTokenCookieName(), "/"));
                             response.addCookie(jwtUtil.createLogoutCookie(jwtUtil.getRefreshTokenCookieName(), "/api/token/refresh"));
                        })
                        .logoutSuccessUrl("/login?logout") // 로그아웃 성공 시 리다이렉트 URL
                        .permitAll()
                )
                // ★★★ 예외 처리 설정 추가 ★★★
                .exceptionHandling(exceptions -> exceptions
                    // 인증되지 않은 사용자가 접근 시 사용할 EntryPoint 지정
                    .authenticationEntryPoint(customAuthenticationEntryPoint)
                    // 참고: 인가는 되었으나 권한이 부족한 경우(403 Forbidden) 처리 핸들러는 .accessDeniedHandler(...) 로 설정 가능
                    // .accessDeniedHandler(yourAccessDeniedHandler)
                );
        


        // 커스텀 필터 추가: (order is important)
        // 1. LoginAuthenticationFilter: UsernamePasswordAuthenticationFilter 자리에 추가하여 로그인 처리 및 토큰 발급
        // 2. JwtAuthenticationFilter: UsernamePasswordAuthenticationFilter 앞에 추가하여 요청 시 토큰 검증 및 인증 설정
         http.addFilterAt(loginAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
         http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }
}