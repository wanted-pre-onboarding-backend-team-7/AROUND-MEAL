package com.lucky.around.meal.entity;

import jakarta.persistence.*;

import com.lucky.around.meal.entity.enums.MemberRole;

import lombok.*;

@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@ToString
@Entity
@Table(name = "member")
public class Member {

  @Id private String memberId;

  @Column(nullable = false)
  private String password;

  @Column(nullable = false)
  private String email;

  @Enumerated(EnumType.STRING)
  private MemberRole role;

  @Column(nullable = false)
  private long lat;

  @Column(nullable = false)
  private long lon;
}
