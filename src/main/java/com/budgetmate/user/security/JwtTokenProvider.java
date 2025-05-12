package com.budgetmate.user.security;

import com.budgetmate.user.service.UserDetailsServiceImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

	private final UserDetailsServiceImpl userDetailsService;

	@Value("${jwt.secret}")
	private String secretKey;

	private final long tokenValidTime = 1000L * 60 * 60; // 1시간

	private SecretKey key;

	private final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

	@PostConstruct
	protected void init() {
		// Base64 인코딩 후 SecretKey 생성
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getBytes(StandardCharsets.UTF_8));
		key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(encodedKey));
	}

	//  토큰 생성
	public String createToken(String email, List<String> roles) {
		Date now = new Date();
		Date expiry = new Date(now.getTime() + tokenValidTime);

		return Jwts.builder().subject(email) // ✅ subject 설정
				.claim("roles", roles) // ✅ roles claim 설정
				.issuedAt(now).expiration(expiry).signWith(key).compact();
	}

	//  토큰에서 인증 정보 추출
	public Authentication getAuthentication(String token) {
		String email = getEmail(token);
		UserDetails userDetails = userDetailsService.loadUserByUsername(email);
		return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
	}

	// ✉️ 토큰에서 사용자 이메일 추출
	public String getEmail(String token) {
		return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().getSubject();
	}

	// ✅ 토큰 유효성 검사
	public boolean validateToken(String token) {
		try {
			Jws<Claims> claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
			return !claims.getPayload().getExpiration().before(new Date());
		} catch (JwtException | IllegalArgumentException e) {
			logger.warn("❌ 유효하지 않은 토큰: {}", e.getMessage());
			return false;
		}
	}

	// 🔍 HTTP 요청에서 토큰 추출
	public String resolveToken(HttpServletRequest request) {
		return request.getHeader("X-AUTH-TOKEN");
	}
}
