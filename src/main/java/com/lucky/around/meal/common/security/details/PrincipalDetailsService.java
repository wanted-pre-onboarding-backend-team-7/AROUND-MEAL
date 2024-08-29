package com.lucky.around.meal.common.security.details;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.lucky.around.meal.entity.Member;
import com.lucky.around.meal.exception.exceptionType.SecurityExceptionType;
import com.lucky.around.meal.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

// 로그인 인증 처리시 인증객체를 저장하기 위해 사용되는 서비스
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

  private final MemberRepository memberRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    Member member =
        memberRepository
            .findById(username)
            .orElseThrow(
                () ->
                    new UsernameNotFoundException(
                        SecurityExceptionType.USER_NOT_FOUND.getMessage()));
    return new PrincipalDetails(member);
  }
}
