package com.lucky.around.meal.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.lucky.around.meal.entity.Member;

public interface MemberRepository extends JpaRepository<Member, String> {}
