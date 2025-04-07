package com.example.jwtjsp.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {

    @GetMapping("/login")
    public String loginPage() {
        // 사용자가 이미 인증되었다면 메인 페이지로 리다이렉트
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getPrincipal())) {
            return "redirect:/main";
        }
        return "login"; // /WEB-INF/views/login.jsp
    }

    @GetMapping(value = {"/", "/main"})
    public String mainPage(Model model, Authentication authentication) {
         if (authentication != null && authentication.isAuthenticated()) {
             model.addAttribute("username", authentication.getName());
         }
         // Access token expiry time (in ms) needed for client-side refresh logic
         // This value comes from application.properties via JwtUtil or direct @Value injection
         // For simplicity, let's assume JwtUtil has a getter or we inject the value here
         // Example: Injecting directly
         // @Value("${jwt.access-token.expiration-ms}") private long accessTokenExpirationMs;
         // model.addAttribute("accessTokenExpiryMs", accessTokenExpirationMs);
         // Or get it from jwtUtil if you add a getter there
         // model.addAttribute("accessTokenExpiryMs", jwtUtil.getAccessTokenExpirationMs());

        // Let's hardcode for now, replace with dynamic value injection
        long accessTokenExpirationMs = 3600000L; // 1 hour in ms
        model.addAttribute("accessTokenExpiryMs", accessTokenExpirationMs);

        return "main"; // /WEB-INF/views/main.jsp
    }
}