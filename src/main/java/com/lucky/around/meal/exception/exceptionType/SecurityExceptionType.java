package com.lucky.around.meal.exception.exceptionType;

import org.springframework.http.HttpStatus;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public enum SecurityExceptionType implements ExceptionType {

  // 401 Unautorized
  // JwtAuthenticationFilter(로그인 시 사용되는 인증필터) 오류
  INVALID_JSON_REQUEST(HttpStatus.UNAUTHORIZED, "JSON 요청 본문을 처리하는 도중 오류가 발생했습니다. 요청 형식을 확인해 주세요."),
  IO_ERROR_PROCESSING_REQUEST(
      HttpStatus.UNAUTHORIZED, "서버에서 요청을 처리하는 도중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요."),
  INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "인증 정보가 잘못되었거나 유효하지 않습니다. 아이디와 비밀번호를 확인해 주세요."),
  SERVER_ERROR(HttpStatus.UNAUTHORIZED, "서버에서 문제가 발생했습니다. 잠시 후 다시 시도해 주세요."),
  USER_NOT_FOUND(HttpStatus.UNAUTHORIZED, "해당하는 아이디의 회원이 없습니다."),

  // 401 Unautorized
  // JwtAuthorizationFilter(jwt 토큰 검증 때 사용되는 인증필터) 오류
  INVALID_JWT_TOKEN(HttpStatus.UNAUTHORIZED, "토큰이 존재하지 않거나 잘못된 형식입니다."),
  INVALID_JWT_SIGNATURE(HttpStatus.UNAUTHORIZED, "유효하지 않은 JWT 서명 입니다."),
  EXPIRED_JWT_TOKEN(HttpStatus.UNAUTHORIZED, "만료된 JWT token 입니다."),
  UNSUPPORTED_JWT_TOKEN(HttpStatus.UNAUTHORIZED, "지원되지 않는 JWT 토큰 입니다."),
  EMPTY_JWT_CLAIMS(HttpStatus.UNAUTHORIZED, "JWT 클레임이 비어 있습니다."),

  // 404 Not Found
  // CustomLogoutSuccessHandler(로그아웃 성공 핸들러) 오류
  COOKIE_NOT_FOUND(HttpStatus.NOT_FOUND, "지정된 쿠키를 찾을 수 없습니다."),
  REFRESHTOKEN_NOT_FOUND(HttpStatus.NOT_FOUND, "저장된 refreshToken을 찾을 수 없습니다."),

  // 403 Forbidden
  UNAUTHRIZED_REQUEST(HttpStatus.FORBIDDEN, "요청권한이 없습니다.");

  private final HttpStatus status;
  private final String message;

  @Override
  public HttpStatus status() {
    return null;
  }

  @Override
  public String message() {
    return "";
  }
}
