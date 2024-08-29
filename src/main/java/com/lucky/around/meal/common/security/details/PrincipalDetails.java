package com.lucky.around.meal.common.security.details;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.lucky.around.meal.entity.Member;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

// 인증객체에 들어가는 Member 객체의 래핑클래스
@Getter
@RequiredArgsConstructor
public class PrincipalDetails implements UserDetails {

  private final Member member;

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of(new SimpleGrantedAuthority(member.getRole().getRole()));
  }

  @Override
  public String getPassword() {
    return this.member.getPassword();
  }

  @Override
  public String getUsername() {
    return this.member.getMemberId();
  }

  public String getEmail() {
    return this.member.getEmail();
  }
}
