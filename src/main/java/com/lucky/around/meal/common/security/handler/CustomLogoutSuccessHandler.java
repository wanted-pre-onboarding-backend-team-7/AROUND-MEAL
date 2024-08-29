package com.lucky.around.meal.common.security.handler;

import java.util.Optional;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import com.lucky.around.meal.common.security.redis.RefreshToken;
import com.lucky.around.meal.common.security.redis.RefreshTokenRepository;
import com.lucky.around.meal.common.security.utils.CookieProvider;
import com.lucky.around.meal.exception.CustomException;
import com.lucky.around.meal.exception.exceptionType.SecurityExceptionType;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

  private final CookieProvider cookieProvider;
  private final RefreshTokenRepository refreshTokenRepository;
  private final @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver;

  public CustomLogoutSuccessHandler(
      CookieProvider cookieProvider,
      RefreshTokenRepository refreshTokenRepository,
      @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
    this.cookieProvider = cookieProvider;
    this.refreshTokenRepository = refreshTokenRepository;
    this.resolver = resolver;
  }

  // refreshToken 프리픽스
  @Value("${spring.data.redis.prefix}")
  String refreshTokenPrefix;

  @Override
  public void onLogoutSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws ServletException {
    try {
      Cookie findCookie = cookieProvider.deleteRefreshTokenCookie(request);
      response.addCookie(findCookie);
      deleteRefreshTokenInRedis(findCookie);
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      resolver.resolveException(request, response, null, e);
    }
  }

  public void deleteRefreshTokenInRedis(Cookie findCookie) {
    Optional<RefreshToken> refreshToken =
        refreshTokenRepository.findById(refreshTokenPrefix + findCookie.getValue());
    if (refreshToken.isPresent()) {
      refreshTokenRepository.delete(refreshToken.get());
    } else {
      throw new CustomException(SecurityExceptionType.REFRESHTOKEN_NOT_FOUND);
    }
  }
}
