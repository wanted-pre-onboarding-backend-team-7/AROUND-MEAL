package com.lucky.around.meal.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import com.lucky.around.meal.common.security.details.PrincipalDetails;
import com.lucky.around.meal.controller.dto.MemberDto;
import com.lucky.around.meal.controller.record.RegisterRecord;
import com.lucky.around.meal.service.MemberService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/members")
public class MemberController {

  private final MemberService memberService;

  // 회원가입
  @PostMapping
  public ResponseEntity<String> signUp(@RequestBody RegisterRecord registerRecord) {
    // 계정명 중복 검증
    memberService.isExistInDB(registerRecord);
    // 회원가입
    memberService.signUp(registerRecord);
    return ResponseEntity.ok("회원가입이 성공적으로 완료되었습니다.");
  }

  // 사용자 정보 반환
  @GetMapping
  public ResponseEntity<MemberDto> getMemberInfo(
      @AuthenticationPrincipal PrincipalDetails principalDetails) {
    MemberDto memberDto = memberService.getMemberInfo(principalDetails);
    return ResponseEntity.ok(memberDto);
  }

  // 리프레시 토큰으로 엑세스 토큰, 리프레시 토큰 재발급
  @PostMapping("/refresh_token")
  public ResponseEntity<String> reissueRefreshToken(
      HttpServletRequest request, HttpServletResponse response) {
    memberService.reissueRefreshToken(request, response);
    return ResponseEntity.ok("토큰 재발급이 성공적으로 완료되었습니다.");
  }

  // 맛집 추천 알람 여부
  @PatchMapping
  public ResponseEntity<Void> updateRecommendationAlerts(@RequestParam("enabled") boolean enabled) {
    memberService.updateRecommendationAlertsEnabled(enabled);
    return ResponseEntity.ok().build();
  }
}
