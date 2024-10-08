package com.lucky.around.meal.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.lucky.around.meal.entity.Member;

public interface MemberRepository extends JpaRepository<Member, Long> {

  // 평가 생성 시 유효성 검사
  Optional<Member> findById(Long memberId);

  // 로그인 시 memberName으로 사용자 반환
  Optional<Member> findByMemberName(String memberName);

  // memberName 중복 검증시 사용
  boolean existsByMemberName(String memberName);

  @Query("SELECT m FROM Member m WHERE m.launchRecommendAgree = true")
  List<Member> findAllWithLunchRecommendAgree();
}
