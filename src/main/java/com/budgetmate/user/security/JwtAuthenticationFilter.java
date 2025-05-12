package com.budgetmate.user.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        // 1. 요청 헤더에서 토큰 추출
        String token = jwtTokenProvider.resolveToken(request);
        logger.debug("[JwtAuthenticationFilter] 추출한 토큰: {}", token);

        // 2. 토큰이 존재하고 유효한 경우에만 인증 객체 설정
        if (token != null && jwtTokenProvider.validateToken(token)) {
            Authentication auth = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
            logger.debug("[JwtAuthenticationFilter] 인증 완료: {}", auth.getName());
        } else {
            logger.debug("[JwtAuthenticationFilter] 토큰 없음 또는 유효하지 않음");
        }

        // 3. 다음 필터로 진행
        filterChain.doFilter(request, response);
    }
}
