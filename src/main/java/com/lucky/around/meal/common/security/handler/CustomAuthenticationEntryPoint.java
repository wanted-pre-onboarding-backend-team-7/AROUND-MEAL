package com.lucky.around.meal.common.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import lombok.extern.slf4j.Slf4j;

// 로그인 후 이용가능한 요청 했을 때 사용되는 핸들러
@Slf4j
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
  // handlerExceptionResolver 의존성 주입
  // handlerExceptionResolver 를 이용하면 CustomExceptionHandler를 사용해 전역 예외 처리가 가능하다.
  private final HandlerExceptionResolver resolver;

  // handlerExceptionResolver 종류 중에서도 handlerExceptionResolver 를 주입받기 위한 생성자 설정
  public CustomAuthenticationEntryPoint(
      @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
    this.resolver = resolver;
  }

  // 예외처리
  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException) {
    resolver.resolveException(
        request, response, null, (Exception) request.getAttribute("exception"));
  }
}
