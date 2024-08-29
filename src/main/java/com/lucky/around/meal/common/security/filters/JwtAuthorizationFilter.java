package com.lucky.around.meal.common.security.filters;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import com.lucky.around.meal.common.security.utils.JwtProvider;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

  private final JwtProvider jwtProvider;
  private final AuthenticationEntryPoint authenticationEntryPoint;

  @Value("${spring.excluded.path-list}")
  private List<String> excludedPaths;

  // 특정 경로 필터 처리 제외
  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    String path = request.getRequestURI();
    return excludedPaths.contains(path);
  }

  // jwt 검증 및 인증객체 등록
  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    try {
      Claims userInfo = jwtProvider.validateToken(request);
      SecurityContextHolder.getContext().setAuthentication(jwtProvider.getAuthentication(userInfo));
      filterChain.doFilter(request, response);
    } catch (AuthenticationServiceException e) {
      // 예외를 CustomAuthenticationEntryPoint로 전달
      authenticationEntryPoint.commence(request, response, e);
    }
  }
}
