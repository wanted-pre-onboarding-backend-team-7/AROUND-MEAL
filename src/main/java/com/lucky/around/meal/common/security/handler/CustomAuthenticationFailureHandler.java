package com.lucky.around.meal.common.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import lombok.extern.slf4j.Slf4j;

// 로그인 인증시 발생하는 예외 처리 핸들러
@Slf4j
@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

  // handlerExceptionResolver 의존성 주입
  // handlerExceptionResolver 를 이용하면 CustomExceptionHandler를 사용해 전역 예외 처리가 가능하다.
  private final HandlerExceptionResolver resolver;

  // handlerExceptionResolver 종류 중에서도 handlerExceptionResolver 를 주입받기 위한 생성자 설정
  public CustomAuthenticationFailureHandler(
      @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
    this.resolver = resolver;
  }

  // 예외처리
  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
      throws ServletException {
    resolver.resolveException(request, response, null, exception);
  }
}
