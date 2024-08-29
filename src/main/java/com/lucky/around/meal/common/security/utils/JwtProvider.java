package com.lucky.around.meal.common.security.utils;

import java.util.Date;

import javax.crypto.SecretKey;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.lucky.around.meal.common.security.details.PrincipalDetailsService;
import com.lucky.around.meal.common.security.record.JwtRecord;
import com.lucky.around.meal.exception.exceptionType.SecurityExceptionType;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

// jwt 관리 클래스
@Slf4j
@Component
public class JwtProvider {
  private final PrincipalDetailsService principalDetailsService;
  // jwt 파싱 암호키
  private final SecretKey key;

  // 액세스 토큰이 저장될 헤더 필드 이름
  @Value("${jwt.access-token-header}")
  public String accessTokenHeader;

  // 액세스 토큰 앞에 지정될 프리픽스
  @Value("${jwt.prefix}")
  public String prefix;

  // 액세스 토큰 만료 기한
  @Value("${jwt.access-token-TTL}")
  private int accessTokenTTL;

  // 리프레시 토큰 만료 기한
  @Value("${jwt.refresh-token-TTL}")
  private int refreshTokenTTL;

  // jwt 파싱 암호키를 바이트화하여 저장
  public JwtProvider(
      @Value("${jwt.secret}") String secretKey, PrincipalDetailsService principalDetailsService) {
    this.principalDetailsService = principalDetailsService;
    byte[] keyBytes = Decoders.BASE64.decode(secretKey);
    this.key = Keys.hmacShaKeyFor(keyBytes);
  }

  // 로그인 성공 시 액세스 토큰, 리프레시 토큰 발급
  public JwtRecord getLoginToken(Authentication authResult) {
    String authorities =
        authResult.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("권한이 없는 사용자"));
    String memberId = authResult.getName();
    return generateJwt(authorities, memberId);
  }

  // 액세스 토큰, 리프레시 토큰이 담긴 JwtRecord 생성 메소드
  public JwtRecord generateJwt(String authorities, String memberId) {
    long now = (new Date()).getTime();

    // 액세스 토큰 생성
    String accessToken =
        Jwts.builder()
            .subject(memberId)
            .claim("authorities", authorities)
            .expiration(new Date(now + accessTokenTTL))
            .signWith(key)
            .compact();
    // 리프레시 토큰 생성
    String refreshToken =
        Jwts.builder()
            .subject(memberId)
            .expiration(new Date(now + refreshTokenTTL))
            .signWith(key)
            .compact();

    return new JwtRecord(accessToken, refreshToken);
  }

  // 액세스 토큰 검증 및 정보 리턴
  public Claims validateToken(HttpServletRequest request) {
    // 헤더에서 토큰 가져오기
    String bearerToken = request.getHeader(accessTokenHeader);
    // 헤더에 토큰 값이 없거나 지정된 프리픽스로 시작하는 문자열이 아니면 검증 실패
    if (!StringUtils.hasText(bearerToken) || !bearerToken.startsWith("Bearer ")) {
      throw new AuthenticationServiceException(
          SecurityExceptionType.INVALID_JWT_TOKEN.getMessage());
    }
    try {
      // 액세스 토큰 해석하여 정보 가져오기
      Claims userinfo =
          Jwts.parser().verifyWith(key).build().parseSignedClaims(bearerToken).getPayload();
      return userinfo;
    } catch (SecurityException | MalformedJwtException e) {
      throw new AuthenticationServiceException(
          SecurityExceptionType.INVALID_JWT_SIGNATURE.getMessage(), e);
    } catch (ExpiredJwtException e) {
      throw new AuthenticationServiceException(
          SecurityExceptionType.EXPIRED_JWT_TOKEN.getMessage(), e);
    } catch (UnsupportedJwtException e) {
      throw new AuthenticationServiceException(
          SecurityExceptionType.UNSUPPORTED_JWT_TOKEN.getMessage(), e);
    } catch (IllegalArgumentException e) {
      throw new AuthenticationServiceException(
          SecurityExceptionType.EMPTY_JWT_CLAIMS.getMessage(), e);
    }
  }

  // 인증 객체 리턴
  public Authentication getAuthentication(Claims userInfo) {
    // 액세스 토큰에 담긴 memberId로 PrincipalDetails 객체 가져오기
    UserDetails userDetails = principalDetailsService.loadUserByUsername(userInfo.getSubject());
    // 가져온 객체를 이용해 인증객체 만들기
    return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
  }
}
