package com.lucky.around.meal.common.security.redis;

import java.io.Serializable;

import jakarta.persistence.Id;

import org.springframework.data.redis.core.RedisHash;

import lombok.*;

@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Getter
@EqualsAndHashCode
@ToString
@RedisHash(value = "RefreshToken", timeToLive = 259200)
public class RefreshToken implements Serializable {
  @Id String refreshToken;

  String memberId;
}
