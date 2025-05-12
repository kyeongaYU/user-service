package com.budgetmate.user.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.budgetmate.user.dto.LoginRequest;
import com.budgetmate.user.dto.SignupRequest;
import com.budgetmate.user.entity.User;
import com.budgetmate.user.service.UserService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    // 회원가입
    @PostMapping("/signup")
    public ResponseEntity<User> signup(@RequestBody SignupRequest request) {
        User newUser = userService.signup(request);
        return ResponseEntity.ok(newUser);
    }

    // 로그인 → JWT 반환
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        String token = userService.login(request);
        return ResponseEntity.ok().body(
                java.util.Map.of("token", token)
        );
    }

    // 내 정보 조회
    @GetMapping("/me")
    public ResponseEntity<?> getMyInfo(@AuthenticationPrincipal org.springframework.security.core.userdetails.User userDetails) {
        return ResponseEntity.ok(
            Map.of(
                "username", userDetails.getUsername(),
                "authorities", userDetails.getAuthorities()
            )
        );
    }

}
