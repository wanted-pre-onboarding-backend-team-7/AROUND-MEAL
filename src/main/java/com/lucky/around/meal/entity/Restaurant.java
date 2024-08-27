package com.lucky.around.meal.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.validation.constraints.NotNull;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class Restaurant {
  @Id private String id;
  @NotNull private String restaurantName;
  @ManyToOne private Region region;
  private String oldRest;
  private String newRest;
  @NotNull private String category;
  private String restaurantTel;
  private double lon;
  private double lat;
  private double ratingAverage;

  @Builder
  private Restaurant(
      String id,
      String restaurantName,
      Region region,
      String oldRest,
      String newRest,
      String category,
      String restaurantTel,
      double lon,
      double lat,
      double ratingAverage) {
    this.id = id;
    this.restaurantName = restaurantName;
    this.region = region;
    this.oldRest = oldRest;
    this.newRest = newRest;
    this.category = category;
    this.restaurantTel = restaurantTel;
    this.lon = lon;
    this.lat = lat;
    this.ratingAverage = ratingAverage;
  }
}
