package com.lucky.around.meal.common.security.filters;

import java.io.IOException;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lucky.around.meal.common.security.handler.CustomAuthenticationFailureHandler;
import com.lucky.around.meal.common.security.record.JwtRecord;
import com.lucky.around.meal.common.security.redis.RefreshToken;
import com.lucky.around.meal.common.security.redis.RefreshTokenRepository;
import com.lucky.around.meal.common.security.utils.CookieProvider;
import com.lucky.around.meal.common.security.utils.JwtProvider;
import com.lucky.around.meal.controller.record.LoginRecord;
import com.lucky.around.meal.exception.exceptionType.SecurityExceptionType;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

// 로그인 인증 처리 필터
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  // jwt 관리 클래스
  private final JwtProvider jwtProvider;
  // 쿠키 관리 클래스
  private final CookieProvider cookieProvider;
  // redis 리포지토리
  private final RefreshTokenRepository refreshTokenRepository;
  // 예외 처리 핸들러
  private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

  // refreshToken 프리픽스
  @Value("${spring.data.redis.prefix}")
  String refreshTokenPrefix;

  // 클래스 생성 완료 후 초기화
  @PostConstruct
  public void init() {
    setFilterProcessesUrl("/api/members/login");
  }

  // 로그인 인증 처리 클래스
  @Override
  public Authentication attemptAuthentication(
      HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    try {
      // 회원가입 폼으로 들어온 정보를 LoginRecord로 변환
      LoginRecord login = new ObjectMapper().readValue(request.getInputStream(), LoginRecord.class);

      // getAuthenticationManager 클래스를 이용해 인증처리(이때 PrincipalDetailsService 사용됨)
      return getAuthenticationManager()
          .authenticate(
              // 회원가입 폼으로 들어온 정보가 특정 클래스로 래핑된다. null은 권한정보
              new UsernamePasswordAuthenticationToken(login.memberId(), login.password(), null));

    } catch (JsonParseException | JsonMappingException e) {
      // CustomAuthenticationFailureHandler 에서 예외가 처리되도록 하기 위해 모든 예외를 AuthenticationServiceException
      // 감쌈
      throw new AuthenticationServiceException(
          SecurityExceptionType.INVALID_JSON_REQUEST.getMessage(), e);
    } catch (IOException e) {
      throw new AuthenticationServiceException(
          SecurityExceptionType.IO_ERROR_PROCESSING_REQUEST.getMessage(), e);
    } catch (AuthenticationException e) {
      throw new AuthenticationServiceException(
          SecurityExceptionType.INVALID_CREDENTIALS.getMessage(), e);
    } catch (Exception e) {
      throw new AuthenticationServiceException(SecurityExceptionType.SERVER_ERROR.getMessage(), e);
    }
  }

  // 로그인 인증 성공시 실행되는 메소드
  @Override
  protected void successfulAuthentication(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain chain,
      Authentication authResult)
      throws IOException, ServletException {
    // 인증 객체를 이용해 jwt 생성
    JwtRecord jwtRecord = jwtProvider.getLoginToken(authResult);
    // accessToken은 헤더에 저장
    response.setHeader(jwtProvider.accessTokenHeader, jwtProvider.prefix + jwtRecord.accessToken());
    // refreshToken은 쿠키에 저장
    response.addCookie(cookieProvider.createRefreshTokenCookie(jwtRecord.refreshToken()));
    // redis에 refreshToken 저장
    refreshTokenRepository.save(
        new RefreshToken(refreshTokenPrefix + jwtRecord.refreshToken(), authResult.getName()));
  }

  // 로그인 인증 실패시 실행되는 메소드
  // attemptAuthentication 에서 발생한 예외들이 이곳으로 전달된다.
  @Override
  protected void unsuccessfulAuthentication(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
      throws IOException, ServletException {
    customAuthenticationFailureHandler.onAuthenticationFailure(request, response, failed);
  }
}
